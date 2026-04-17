import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import uuid
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv()

from core.models import AgentRegistration, AuthorizationRequest, AuthorizationResponse, Decision
from core import audit, trust_engine
from core.explainer import generate_explanation

# In-memory agent registry
_agents: dict[str, AgentRegistration] = {}

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self._connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._connections.append(ws)

    def disconnect(self, ws: WebSocket):
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
    yield


app = FastAPI(title="AgentGate PDP", version="0.1.0", lifespan=lifespan)

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
    return {"agent_id": reg.agent_id, "token": reg.token, "status": "registered"}


@app.get("/agents", response_model=list)
async def list_agents():
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


@app.delete("/agents/{agent_id}")
async def deregister_agent(agent_id: str):
    if agent_id not in _agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    del _agents[agent_id]
    return {"status": "deregistered"}


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
    return response


def _build_unknown_agent_response(request: AuthorizationRequest) -> AuthorizationResponse:
    from core.models import TrustBreakdown, ResourceSensitivity
    breakdown = TrustBreakdown(
        identity_score=0,
        delegation_score=0,
        purpose_alignment_score=0,
        behavioral_score=0,
        resource_sensitivity=ResourceSensitivity.CRITICAL,
        final_score=0,
        threshold_required=90,
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


# ── Audit & Stats ───────────────────────────────────────────────────────────

@app.get("/audit/recent")
async def recent_audit(limit: int = 50):
    return audit.get_recent_decisions(limit)


@app.get("/audit/stats")
async def stats():
    return audit.get_stats()


# ── WebSocket (real-time dashboard feed) ────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        # Send current stats on connect
        await ws.send_text(json.dumps({"type": "stats", "data": audit.get_stats()}))
        while True:
            await ws.receive_text()  # keep-alive
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
