"""
AgentGate MCP Authorization Proxy

Drop-in HTTP proxy that sits between any LLM agent and any MCP server.
Every tools/call and resources/read is intercepted, submitted to AgentGate
for authorization, then forwarded (PERMIT) or blocked (DENY/ESCALATE) before
the upstream MCP server ever sees the request.

Architecture:
  Agent → MCP Proxy (this) → AgentGate /authorize → Upstream MCP Server

Configuration (env vars):
  AGENTGATE_URL          AgentGate PDP base URL       (default: http://localhost:8000)
  AGENTGATE_API_KEY      API key for AgentGate         (default: empty — dev mode)
  MCP_UPSTREAM_URL       Upstream MCP server URL       (required)
  MCP_PROXY_PORT         Port this proxy listens on    (default: 8001)

Per-request identity (set by the LLM agent via request headers, stripped before forwarding):
  X-AgentGate-Agent-Id   Registered AgentGate agent ID
  X-AgentGate-Token      JWT token issued at registration
  X-AgentGate-Purpose    Optional justification for this request

JSON-RPC methods intercepted:
  tools/call       → action=<tool_name>, resource=/tools/<tool_name>
  resources/read   → action=read,        resource=<uri>

All other MCP methods are forwarded transparently.
"""

import json
import os
import sys

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

AGENTGATE_URL = os.getenv("AGENTGATE_URL", "http://localhost:8000").rstrip("/")
AGENTGATE_API_KEY = os.getenv("AGENTGATE_API_KEY", "")
MCP_UPSTREAM_URL = os.getenv("MCP_UPSTREAM_URL", "").rstrip("/")

app = FastAPI(title="AgentGate MCP Proxy", version="1.0.0")

# Methods that require AgentGate authorization before forwarding
_INTERCEPTED = {"tools/call", "resources/read"}


def _jsonrpc_error(id_, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


def _extract_auth_target(method: str, params: dict) -> tuple[str, str]:
    """
    Map an MCP method + params to (action, resource) for AgentGate.

    tools/call   → action=<tool_name>, resource=/tools/<tool_name>
    resources/read → action=read,     resource=<uri from params>
    """
    if method == "tools/call":
        tool_name = (params or {}).get("name", "unknown_tool")
        return tool_name, f"/tools/{tool_name}"
    if method == "resources/read":
        uri = (params or {}).get("uri", "/resources/unknown")
        return "read", uri
    return method, "/"


async def _authorize(
    agent_id: str,
    token: str,
    action: str,
    resource: str,
    justification: str = "",
) -> tuple[str, str]:
    """
    Call AgentGate /authorize. Returns (decision, explanation).
    decision is one of: PERMIT, DENY, ESCALATE, PENDING
    """
    headers = {"Content-Type": "application/json"}
    if AGENTGATE_API_KEY:
        headers["X-API-Key"] = AGENTGATE_API_KEY

    payload = {
        "agent_id": agent_id,
        "action": action,
        "resource": resource,
        "token": token,
        "justification": justification,
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(f"{AGENTGATE_URL}/authorize", json=payload, headers=headers)
    data = resp.json()
    return data.get("decision", "DENY"), data.get("explanation", "")


async def _forward(request_body: dict, strip_headers: dict) -> dict:
    """Forward JSON-RPC payload to upstream MCP server, return the JSON-RPC response."""
    if not MCP_UPSTREAM_URL:
        return _jsonrpc_error(
            request_body.get("id"), -32000,
            "MCP_UPSTREAM_URL not configured — set it in the environment"
        )
    # Forward all original headers except the AgentGate identity headers
    forward_headers = {"Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(MCP_UPSTREAM_URL, json=request_body, headers=forward_headers)
    try:
        return resp.json()
    except Exception:
        return _jsonrpc_error(request_body.get("id"), -32000, "Upstream returned non-JSON response")


@app.post("/")
async def mcp_proxy(request: Request):
    # Extract AgentGate identity headers (stripped before forwarding)
    agent_id = request.headers.get("X-AgentGate-Agent-Id", "")
    token = request.headers.get("X-AgentGate-Token", "")
    justification = request.headers.get("X-AgentGate-Purpose", "")

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(_jsonrpc_error(None, -32700, "Parse error — invalid JSON"))

    method = body.get("method", "")
    req_id = body.get("id")

    # Pass through non-intercepted methods immediately
    if method not in _INTERCEPTED:
        result = await _forward(body, {})
        return JSONResponse(result)

    # Require identity for intercepted methods
    if not agent_id or not token:
        return JSONResponse(
            _jsonrpc_error(
                req_id, -32001,
                "AgentGate identity required: set X-AgentGate-Agent-Id and X-AgentGate-Token headers"
            )
        )

    params = body.get("params") or {}
    action, resource = _extract_auth_target(method, params)

    try:
        decision, explanation = await _authorize(agent_id, token, action, resource, justification)
    except Exception as exc:
        # AgentGate unreachable — fail closed (deny by default)
        return JSONResponse(
            _jsonrpc_error(
                req_id, -32000,
                f"AgentGate authorization service unreachable — request blocked: {exc}"
            )
        )

    if decision == "PERMIT":
        result = await _forward(body, {})
        return JSONResponse(result)

    # DENY / ESCALATE / PENDING → block with JSON-RPC error
    code_map = {"DENY": -32002, "ESCALATE": -32003, "PENDING": -32004}
    msg = f"AgentGate {decision}: {explanation}"
    return JSONResponse(_jsonrpc_error(req_id, code_map.get(decision, -32002), msg))


@app.get("/healthz")
async def healthz():
    return {
        "status": "ok",
        "agentgate_url": AGENTGATE_URL,
        "upstream_configured": bool(MCP_UPSTREAM_URL),
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("MCP_PROXY_PORT", 8001))
    uvicorn.run("server.mcp_proxy:app", host="0.0.0.0", port=port, reload=False)
