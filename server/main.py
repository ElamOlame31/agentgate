import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request, Depends, Query
from fastapi.responses import HTMLResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

# ── API Key Auth ─────────────────────────────────────────────────────────────

def _get_api_key() -> str | None:
    return os.getenv("AGENTGATE_API_KEY", "").strip() or None

async def require_api_key(request: Request):
    api_key = _get_api_key()
    if api_key is None:
        return  # auth disabled — no key configured
    provided = request.headers.get("X-API-Key", "")
    if provided != api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key. Set X-API-Key header.")


from core.models import (
    AgentRegistration, AuthorizationRequest, AuthorizationResponse, Decision,
    ContentScanRequest, ContentScanResponse,
)
from core import audit, trust_engine
from core.explainer import generate_explanation
from core.policy_engine import (
    create_policy, get_all_policies, delete_policy,
    check_policies, Policy, init_policy_table
)
from core.alerts import fire_alert, fire_approval_request, alerts_configured, alert_status
from core.report import generate_pdf, generate_csv
from core import approvals
from core.delegation import validate_delegation, chain_summary, MAX_DELEGATION_DEPTH

# Persistent agent registry (loaded from SQLite on startup)
_agents: dict[str, AgentRegistration] = {}


class ConnectionManager:
    def __init__(self):
        self._connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._connections.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self._connections:
            self._connections.remove(ws)

    async def broadcast(self, data: dict):
        dead = []
        for ws in self._connections:
            try:
                await ws.send_text(json.dumps(data))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._connections.remove(ws)


manager = ConnectionManager()


async def _ws_broadcast(data: dict):
    await manager.broadcast(data)


@asynccontextmanager
async def lifespan(app: FastAPI):
    audit.init_db()
    audit.cleanup_old_history(max_age_seconds=3600.0)
    init_policy_table()
    _agents.update(audit.load_all_agents())
    approvals.set_broadcast_callback(_ws_broadcast)
    if _get_api_key():
        print("[AgentGate] Auth ON  — API key required on all endpoints")
    else:
        print("[AgentGate] Auth OFF — set AGENTGATE_API_KEY in .env to enable")
    if alerts_configured():
        print(f"[AgentGate] Alerts ON -> {alert_status()}")
    else:
        print("[AgentGate] Alerts OFF — set AGENTGATE_ALERT_TOPIC in .env to enable")
    yield


app = FastAPI(title="AgentGate PDP", version="0.2.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Agent Registration ──────────────────────────────────────────────────────

@app.post("/agents/register", response_model=dict, dependencies=[Depends(require_api_key)])
async def register_agent(reg: AgentRegistration):
    if not reg.token:
        reg.token = str(uuid.uuid4())
    _agents[reg.agent_id] = reg
    audit.save_agent(reg)
    await manager.broadcast({"type": "agents", "data": _agent_list()})
    return {"agent_id": reg.agent_id, "token": reg.token, "status": "registered"}


@app.get("/agents", response_model=list, dependencies=[Depends(require_api_key)])
async def list_agents():
    return _agent_list()


class DelegationRequest(BaseModel):
    parent_agent_id: str
    parent_token: str
    child_agent_id: str
    child_name: str
    child_declared_purpose: str
    child_resources: list[str]
    child_actions: list[str]
    child_declared_purpose_detail: str = ""


@app.post("/agents/delegate", response_model=dict, dependencies=[Depends(require_api_key)])
async def delegate_agent(req: DelegationRequest):
    if req.parent_agent_id not in _agents:
        raise HTTPException(status_code=404, detail="Parent agent not found")

    parent = _agents[req.parent_agent_id]

    if parent.token and req.parent_token != parent.token:
        raise HTTPException(status_code=401, detail="Invalid parent agent token")

    if parent.delegation_depth >= MAX_DELEGATION_DEPTH:
        raise HTTPException(
            status_code=400,
            detail=f"Max delegation depth ({MAX_DELEGATION_DEPTH}) reached — chain too deep"
        )

    valid, error = validate_delegation(
        parent.authorized_resources, parent.authorized_actions,
        req.child_resources, req.child_actions,
    )
    if not valid:
        raise HTTPException(status_code=400, detail=f"Scope violation: {error}")

    child = AgentRegistration(
        agent_id=req.child_agent_id,
        name=req.child_name,
        declared_purpose=req.child_declared_purpose,
        authorized_resources=req.child_resources,
        authorized_actions=req.child_actions,
        delegated_by=req.parent_agent_id,
        delegation_depth=parent.delegation_depth + 1,
        scope_at_delegation=parent.authorized_resources + parent.authorized_actions,
        token=str(uuid.uuid4()),
    )
    _agents[child.agent_id] = child
    audit.save_agent(child)
    await manager.broadcast({"type": "agents", "data": _agent_list()})
    print(
        f"[AgentGate] Delegated: {req.parent_agent_id} -> {req.child_agent_id} "
        f"(depth {child.delegation_depth})",
        flush=True
    )
    return {
        "agent_id": child.agent_id,
        "token": child.token,
        "delegation_depth": child.delegation_depth,
        "delegated_by": child.delegated_by,
        "status": "delegated",
    }


@app.delete("/agents/{agent_id}", dependencies=[Depends(require_api_key)])
async def deregister_agent(agent_id: str):
    if agent_id not in _agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    del _agents[agent_id]
    audit.delete_agent(agent_id)
    return {"status": "deregistered"}


def _agent_list():
    return [
        {
            "agent_id": a.agent_id,
            "name": a.name,
            "declared_purpose": a.declared_purpose,
            "delegation_depth": a.delegation_depth,
            "delegated_by": a.delegated_by,
            "chain": chain_summary(a.agent_id, _agents),
        }
        for a in _agents.values()
    ]


# ── Authorization (PDP) ─────────────────────────────────────────────────────

@app.post("/authorize", response_model=AuthorizationResponse, dependencies=[Depends(require_api_key)])
async def authorize(request: AuthorizationRequest):
    if not request.request_id:
        request.request_id = str(uuid.uuid4())

    # Unknown agent → deny immediately
    if request.agent_id not in _agents:
        response = _build_unknown_agent_response(request)
        audit.log_decision(response)
        await manager.broadcast({"type": "decision", "data": response.model_dump()})
        return response

    agent = _agents[request.agent_id]

    # ── Policy check FIRST (hard rules override trust score) ──────────────
    policy_match = check_policies(request.agent_id, request.action, request.resource)
    if policy_match.matched:
        response = _build_policy_blocked_response(request, agent, policy_match)
        audit.log_decision(response)
        await manager.broadcast({"type": "decision", "data": response.model_dump()})
        fire_alert(
            response.decision.value, request.agent_id,
            request.action, request.resource,
            response.explanation, response.attack_flags,
            response.trust_breakdown.final_score,
        )
        return response

    # ── Trust scoring ──────────────────────────────────────────────────────
    breakdown, flags = trust_engine.compute_trust(agent, request, _agents)
    decision = trust_engine.make_decision(breakdown, flags)
    explanation = generate_explanation(
        agent.name, request.action, request.resource,
        breakdown, decision, flags
    )

    # ── Human-in-the-loop: pause ESCALATE for manual review ───────────────
    if decision == Decision.ESCALATE and agent.requires_human_approval:
        pending = approvals.create_pending(
            request_id=request.request_id,
            agent_id=request.agent_id,
            action=request.action,
            resource=request.resource,
            explanation=explanation,
            trust_score=breakdown.final_score,
        )
        await manager.broadcast({"type": "pending", "data": pending.to_dict()})
        fire_approval_request(
            request.request_id, request.agent_id,
            request.action, request.resource,
            explanation, breakdown.final_score,
        )
        response = AuthorizationResponse(
            request_id=request.request_id,
            agent_id=request.agent_id,
            action=request.action,
            resource=request.resource,
            decision=Decision.PENDING,
            trust_breakdown=breakdown,
            explanation=f"[PENDING HUMAN APPROVAL] {explanation}",
            attack_flags=flags,
        )
        audit.log_decision(response)
        return response

    response = AuthorizationResponse(
        request_id=request.request_id,
        agent_id=request.agent_id,
        action=request.action,
        resource=request.resource,
        decision=decision,
        trust_breakdown=breakdown,
        explanation=explanation,
        attack_flags=flags,
    )

    audit.log_decision(response)
    await manager.broadcast({"type": "decision", "data": response.model_dump()})
    fire_alert(
        decision.value, request.agent_id,
        request.action, request.resource,
        explanation, flags,
        breakdown.final_score,
    )
    return response


# ── Content Scan (Injection Detection) ─────────────────────────────────────

@app.post("/scan", response_model=ContentScanResponse, dependencies=[Depends(require_api_key)])
async def scan_content_endpoint(body: ContentScanRequest):
    from core.injection_detector import should_scan, scan_content
    from core.trust_engine import classify_resource_sensitivity

    agent = _agents.get(body.agent_id)
    if agent is None:
        return ContentScanResponse(
            level="clean", confidence=0.0,
            evidence="Agent not registered — scan skipped",
            scanned=False,
        )

    # Use agent metadata for Layer 1 check (assume HIGH sensitivity for external content)
    eligible = should_scan(
        processes_external_content=agent.processes_external_content,
        authorized_actions=agent.authorized_actions,
        resource_sensitivity="HIGH",
    )

    if not eligible:
        return ContentScanResponse(
            level="clean", confidence=0.0,
            evidence="Agent not eligible for content scanning (processes_external_content=False)",
            scanned=False,
        )

    result = scan_content(body.content, agent.declared_purpose)

    # Broadcast to dashboard
    await manager.broadcast({
        "type": "injection",
        "data": {
            "agent_id": body.agent_id,
            "level": result.level,
            "confidence": result.confidence,
            "evidence": result.evidence,
            "timestamp": __import__("time").time(),
        }
    })

    # Fire alert on injection detection
    if result.level in ("injection", "suspicious"):
        fire_alert(
            "INJECTION_" + result.level.upper(),
            body.agent_id, "content_scan", "external_content",
            result.evidence, [f"INJECTION_{result.level.upper()}"],
            round(result.confidence * 100, 1),
        )

    return ContentScanResponse(
        level=result.level,
        confidence=result.confidence,
        evidence=result.evidence,
        scanned=True,
    )


def _build_unknown_agent_response(request: AuthorizationRequest) -> AuthorizationResponse:
    from core.models import TrustBreakdown, ResourceSensitivity
    breakdown = TrustBreakdown(
        identity_score=0, delegation_score=0,
        purpose_alignment_score=0, behavioral_score=0,
        resource_sensitivity=ResourceSensitivity.CRITICAL,
        final_score=0, threshold_required=90,
    )
    return AuthorizationResponse(
        request_id=request.request_id or str(uuid.uuid4()),
        agent_id=request.agent_id,
        action=request.action,
        resource=request.resource,
        decision=Decision.DENY,
        trust_breakdown=breakdown,
        explanation="Denied: agent is not registered in AgentGate — identity cannot be verified.",
        attack_flags=["UNREGISTERED_AGENT"],
    )


def _build_policy_blocked_response(
    request: AuthorizationRequest,
    agent: AgentRegistration,
    policy_match
) -> AuthorizationResponse:
    from core.models import TrustBreakdown, ResourceSensitivity
    from core.trust_engine import classify_resource_sensitivity
    sensitivity = classify_resource_sensitivity(request.resource)
    breakdown = TrustBreakdown(
        identity_score=100, delegation_score=100,
        purpose_alignment_score=100, behavioral_score=100,
        resource_sensitivity=sensitivity,
        final_score=100, threshold_required=0,
    )
    decision = Decision.DENY if policy_match.policy.effect == "DENY" else Decision.ESCALATE
    return AuthorizationResponse(
        request_id=request.request_id,
        agent_id=request.agent_id,
        action=request.action,
        resource=request.resource,
        decision=decision,
        trust_breakdown=breakdown,
        explanation=f"Policy block: {policy_match.reason}",
        attack_flags=[f"POLICY_VIOLATION:{policy_match.policy.id}"],
    )


# ── Policy Engine ───────────────────────────────────────────────────────────

class PolicyRequest(BaseModel):
    rule: str


@app.post("/policies", response_model=Policy, dependencies=[Depends(require_api_key)])
async def add_policy(body: PolicyRequest):
    policy = create_policy(body.rule)
    await manager.broadcast({"type": "policies", "data": [p.model_dump() for p in get_all_policies()]})
    return policy


@app.get("/policies", response_model=list[Policy])
async def list_policies():
    return get_all_policies()


@app.delete("/policies/{policy_id}", dependencies=[Depends(require_api_key)])
async def remove_policy(policy_id: str):
    if not delete_policy(policy_id):
        raise HTTPException(status_code=404, detail="Policy not found")
    await manager.broadcast({"type": "policies", "data": [p.model_dump() for p in get_all_policies()]})
    return {"status": "deleted"}


# ── Human Approval Endpoints ────────────────────────────────────────────────

@app.get("/decisions/pending", dependencies=[Depends(require_api_key)])
async def list_pending():
    return approvals.get_all_pending()


@app.get("/decisions/{decision_id}")
async def get_decision(decision_id: str):
    a = approvals.get_pending(decision_id)
    if a is None:
        raise HTTPException(status_code=404, detail="Decision not found")
    return a.to_dict()


@app.post("/decisions/{decision_id}/approve")
async def approve_decision(decision_id: str):
    if not approvals.approve(decision_id):
        raise HTTPException(status_code=404, detail="Decision not found or already resolved")
    print(f"[AgentGate] Human APPROVED {decision_id}", flush=True)
    return {"status": "approved", "decision_id": decision_id}


@app.post("/decisions/{decision_id}/deny")
async def deny_decision(decision_id: str):
    if not approvals.deny(decision_id):
        raise HTTPException(status_code=404, detail="Decision not found or already resolved")
    print(f"[AgentGate] Human DENIED {decision_id}", flush=True)
    return {"status": "denied", "decision_id": decision_id}


# ── Audit & Stats ───────────────────────────────────────────────────────────

@app.get("/audit/recent", dependencies=[Depends(require_api_key)])
async def recent_audit(limit: int = 50):
    return audit.get_recent_decisions(limit)


@app.get("/audit/agent/{agent_id}", dependencies=[Depends(require_api_key)])
async def agent_audit(agent_id: str, limit: int = 100):
    return audit.get_agent_decisions(agent_id, limit)


@app.get("/audit/stats")
async def stats():
    return audit.get_stats()


@app.get("/audit/export", dependencies=[Depends(require_api_key)])
async def export_audit(
    format: str = Query("pdf", regex="^(pdf|csv)$"),
    from_ts: float = Query(None, description="Start Unix timestamp (default: 30 days ago)"),
    to_ts:   float = Query(None, description="End Unix timestamp (default: now)"),
):
    import time as _time
    now   = _time.time()
    to_ts   = to_ts   or now
    from_ts = from_ts or (now - 30 * 86400)

    rows  = audit.get_decisions_in_range(from_ts, to_ts)
    stats = audit.get_stats()

    if format == "csv":
        csv_data = generate_csv(rows)
        filename = f"agentgate_audit_{int(from_ts)}_{int(to_ts)}.csv"
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    pdf_bytes = generate_pdf(rows, stats, from_ts, to_ts)
    filename  = f"agentgate_audit_{int(from_ts)}_{int(to_ts)}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/audit/baselines", dependencies=[Depends(require_api_key)])
async def all_baselines():
    return audit.get_all_baselines()


@app.get("/audit/baselines/{agent_id}", dependencies=[Depends(require_api_key)])
async def agent_baseline(agent_id: str):
    b = audit.get_agent_baseline(agent_id)
    if b is None:
        raise HTTPException(status_code=404, detail="No baseline data for this agent yet")
    return b


# ── WebSocket ───────────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        await ws.send_text(json.dumps({"type": "stats", "data": audit.get_stats()}))
        await ws.send_text(json.dumps({"type": "policies", "data": [p.model_dump() for p in get_all_policies()]}))
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)


# ── Dashboard ───────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    dashboard_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "dashboard", "index.html"
    )
    with open(dashboard_path, "r", encoding="utf-8") as f:
        return f.read()


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("AGENTGATE_PORT", 8000))
    uvicorn.run("server.main:app", host="0.0.0.0", port=port, reload=True)
