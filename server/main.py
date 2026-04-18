import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

from core.models import AgentRegistration, AuthorizationRequest, AuthorizationResponse, Decision
from core import audit, trust_engine
from core.explainer import generate_explanation
from core.policy_engine import (
    create_policy, get_all_policies, delete_policy,
    check_policies, Policy, init_policy_table
)
from core.alerts import fire_alert, alerts_configured, alert_status

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


@asynccontextmanager
async def lifespan(app: FastAPI):
    audit.init_db()
    init_policy_table()
    _agents.update(audit.load_all_agents())
    if alerts_configured():
        print(f"[AgentGate] Alerts ON → {alert_status()}")
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

@app.post("/agents/register", response_model=dict)
async def register_agent(reg: AgentRegistration):
    if not reg.token:
        reg.token = str(uuid.uuid4())
    _agents[reg.agent_id] = reg
    audit.save_agent(reg)
    await manager.broadcast({"type": "agents", "data": _agent_list()})
    return {"agent_id": reg.agent_id, "token": reg.token, "status": "registered"}


@app.get("/agents", response_model=list)
async def list_agents():
    return _agent_list()


@app.delete("/agents/{agent_id}")
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
        }
        for a in _agents.values()
    ]


# ── Authorization (PDP) ─────────────────────────────────────────────────────

@app.post("/authorize", response_model=AuthorizationResponse)
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
    breakdown, flags = trust_engine.compute_trust(agent, request)
    decision = trust_engine.make_decision(breakdown, flags)
    explanation = generate_explanation(
        agent.name, request.action, request.resource,
        breakdown, decision, flags
    )

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


@app.post("/policies", response_model=Policy)
async def add_policy(body: PolicyRequest):
    policy = create_policy(body.rule)
    await manager.broadcast({"type": "policies", "data": [p.model_dump() for p in get_all_policies()]})
    return policy


@app.get("/policies", response_model=list[Policy])
async def list_policies():
    return get_all_policies()


@app.delete("/policies/{policy_id}")
async def remove_policy(policy_id: str):
    if not delete_policy(policy_id):
        raise HTTPException(status_code=404, detail="Policy not found")
    await manager.broadcast({"type": "policies", "data": [p.model_dump() for p in get_all_policies()]})
    return {"status": "deleted"}


# ── Audit & Stats ───────────────────────────────────────────────────────────

@app.get("/audit/recent")
async def recent_audit(limit: int = 50):
    return audit.get_recent_decisions(limit)


@app.get("/audit/stats")
async def stats():
    return audit.get_stats()


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
