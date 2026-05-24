"""
AgentGateToolWrapper — wraps any LangChain tool with AgentGate enforcement.

Critical design decisions:
- Uses StructuredTool.from_function() to preserve the original tool's arg schema.
  The old lc_tool(guarded) approach created a generic *args/**kwargs wrapper,
  which breaks LangGraph tool-call parsing when the LLM passes named arguments.
- Provides both sync (func=) and async (coroutine=) implementations so the
  wrapper works correctly in both LangGraph's async event loop and synchronous callers.
- Fails closed: if AgentGate is unreachable, the action is DENIED rather than
  falling through to execution.
"""

import asyncio
import time
import uuid

import httpx
from langchain_core.tools import BaseTool, StructuredTool


# ── Resource / action heuristics ──────────────────────────────────────────────

def _extract_resource(tool_input) -> str:
    """Extract the primary resource identifier from tool arguments."""
    if isinstance(tool_input, str):
        return tool_input.strip().split()[0] if tool_input.strip() else tool_input
    if isinstance(tool_input, dict):
        for key in ("path", "file_path", "resource", "url", "uri", "query", "directory", "key"):
            if key in tool_input:
                return str(tool_input[key])
        if tool_input:
            return str(next(iter(tool_input.values())))
    return str(tool_input) if tool_input else "/"


def _infer_action(tool_name: str) -> str:
    name = tool_name.lower()
    if any(k in name for k in ("delete", "remove", "drop", "destroy", "purge")):
        return "delete"
    if any(k in name for k in ("write", "create", "save", "update", "insert", "append")):
        return "write"
    if any(k in name for k in ("send", "email", "upload", "post", "publish", "export")):
        return "send"
    if any(k in name for k in ("search", "list", "find", "query", "browse")):
        return "search"
    return "read"


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _authorize_sync(
    agentgate_url: str, agent_id: str, token: str,
    action: str, resource: str, justification: str,
    headers: dict,
) -> dict:
    try:
        r = httpx.post(
            f"{agentgate_url}/authorize",
            headers=headers,
            json={
                "agent_id": agent_id,
                "token": token,
                "action": action,
                "resource": resource,
                "justification": justification,
                "request_id": str(uuid.uuid4()),
            },
            timeout=10.0,
        )
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        # Fail closed — if AgentGate is unreachable, deny the action
        return {
            "decision": "DENY",
            "explanation": f"AgentGate unreachable: {exc}",
            "trust_breakdown": {"final_score": 0},
            "attack_flags": ["AGENTGATE_UNREACHABLE"],
            "request_id": "",
        }


async def _authorize_async(
    agentgate_url: str, agent_id: str, token: str,
    action: str, resource: str, justification: str,
    headers: dict,
) -> dict:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(
                f"{agentgate_url}/authorize",
                headers=headers,
                json={
                    "agent_id": agent_id,
                    "token": token,
                    "action": action,
                    "resource": resource,
                    "justification": justification,
                    "request_id": str(uuid.uuid4()),
                },
            )
            r.raise_for_status()
            return r.json()
    except Exception as exc:
        return {
            "decision": "DENY",
            "explanation": f"AgentGate unreachable: {exc}",
            "trust_breakdown": {"final_score": 0},
            "attack_flags": ["AGENTGATE_UNREACHABLE"],
            "request_id": "",
        }


def _poll_decision_sync(
    agentgate_url: str, request_id: str, headers: dict, max_wait: int = 95
) -> str:
    deadline = time.time() + max_wait
    print(f"[AgentGate] Waiting for human approval ({max_wait}s timeout)…")
    while time.time() < deadline:
        try:
            r = httpx.get(f"{agentgate_url}/decisions/{request_id}", headers=headers, timeout=5.0)
            if r.status_code == 200:
                status = r.json().get("status", "PENDING")
                if status in ("APPROVED", "DENIED"):
                    return status
        except Exception:
            pass
        time.sleep(2)
    return "DENIED"


async def _poll_decision_async(
    agentgate_url: str, request_id: str, headers: dict, max_wait: int = 95
) -> str:
    deadline = time.time() + max_wait
    print(f"[AgentGate] Waiting for human approval ({max_wait}s timeout)…")
    while time.time() < deadline:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.get(f"{agentgate_url}/decisions/{request_id}", headers=headers)
                if r.status_code == 200:
                    status = r.json().get("status", "PENDING")
                    if status in ("APPROVED", "DENIED"):
                        return status
        except Exception:
            pass
        await asyncio.sleep(2)
    return "DENIED"


async def _scan_async(
    agentgate_url: str, agent_id: str, content: str, headers: dict
) -> dict:
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(
                f"{agentgate_url}/scan",
                headers=headers,
                json={"agent_id": agent_id, "content": content},
            )
            r.raise_for_status()
            return r.json()
    except Exception:
        return {"level": "clean", "scanned": False, "evidence": "", "confidence": 0.0}


def _scan_sync(agentgate_url: str, agent_id: str, content: str, headers: dict) -> dict:
    try:
        r = httpx.post(
            f"{agentgate_url}/scan",
            headers=headers,
            json={"agent_id": agent_id, "content": content},
            timeout=30.0,
        )
        r.raise_for_status()
        return r.json()
    except Exception:
        return {"level": "clean", "scanned": False, "evidence": "", "confidence": 0.0}


def _deny_message(action: str, resource: str, explanation: str) -> str:
    return (
        f"[AgentGate DENIED] Cannot {action} '{resource}'. "
        f"Reason: {explanation}. Do not retry this request."
    )


def _escalate_suffix(score: float, explanation: str) -> str:
    return f"\n\n[AgentGate WARNING — trust score {score}/100: {explanation}]"


# ── Core wrapper ──────────────────────────────────────────────────────────────

class AgentGateToolWrapper:
    """
    Wraps a LangChain BaseTool with AgentGate enforcement.

    Returns a StructuredTool that has the SAME arg schema as the original —
    so LangGraph can correctly parse and route tool calls — but intercepts
    execution to run an AgentGate authorization check first.
    """

    def __init__(
        self,
        original_tool: BaseTool,
        agentgate_url: str,
        agent_id: str,
        token: str,
        processes_external_content: bool = False,
        api_key: str = "",
        pending_timeout: int = 95,
    ):
        self.original = original_tool
        self.agentgate_url = agentgate_url.rstrip("/")
        self.agent_id = agent_id
        self.token = token
        self.processes_external_content = processes_external_content
        self.pending_timeout = pending_timeout
        self._headers = {"X-API-Key": api_key, "Content-Type": "application/json"} if api_key else {"Content-Type": "application/json"}
        self._wrapped = self._build()

    def _build(self) -> BaseTool:
        original = self.original
        url = self.agentgate_url
        agent_id = self.agent_id
        token = self.token
        ext = self.processes_external_content
        headers = self._headers
        timeout = self.pending_timeout

        # Resolve the callable — StructuredTool stores it as .func, @tool as .func
        original_func = getattr(original, "func", None)
        original_coro = getattr(original, "coroutine", None)

        if original_func is None and original_coro is None:
            return original  # cannot wrap — return as-is

        def _guarded(**kwargs):
            action = _infer_action(original.name)
            resource = _extract_resource(kwargs)
            justification = f"{original.name}: {resource}"

            auth = _authorize_sync(url, agent_id, token, action, resource, justification, headers)
            decision = auth.get("decision", "DENY")
            explanation = auth.get("explanation", "")
            score = auth.get("trust_breakdown", {}).get("final_score", 0)
            request_id = auth.get("request_id", "")

            if decision == "DENY":
                return _deny_message(action, resource, explanation)

            if decision == "PENDING":
                human = _poll_decision_sync(url, request_id, headers, timeout)
                if human != "APPROVED":
                    return _deny_message(action, resource, "denied by human reviewer")

            output = original_func(**kwargs) if original_func else None

            if action == "read" and ext and isinstance(output, str):
                scan = _scan_sync(url, agent_id, output, headers)
                if scan.get("scanned") and scan.get("level") == "injection":
                    return (
                        f"[AgentGate BLOCKED] Prompt injection detected in '{resource}'. "
                        f"Evidence: {scan['evidence']}. Content withheld."
                    )
                if scan.get("scanned") and scan.get("level") == "suspicious":
                    output = output + f"\n\n[AgentGate WARNING: suspicious content — {scan['evidence']}]"

            if decision == "ESCALATE":
                return str(output) + _escalate_suffix(score, explanation)

            return output

        async def _aguarded(**kwargs):
            action = _infer_action(original.name)
            resource = _extract_resource(kwargs)
            justification = f"{original.name}: {resource}"

            auth = await _authorize_async(url, agent_id, token, action, resource, justification, headers)
            decision = auth.get("decision", "DENY")
            explanation = auth.get("explanation", "")
            score = auth.get("trust_breakdown", {}).get("final_score", 0)
            request_id = auth.get("request_id", "")

            if decision == "DENY":
                return _deny_message(action, resource, explanation)

            if decision == "PENDING":
                human = await _poll_decision_async(url, request_id, headers, timeout)
                if human != "APPROVED":
                    return _deny_message(action, resource, "denied by human reviewer")

            if original_coro is not None:
                output = await original_coro(**kwargs)
            elif original_func is not None:
                output = await asyncio.to_thread(original_func, **kwargs)
            else:
                output = None

            if action == "read" and ext and isinstance(output, str):
                scan = await _scan_async(url, agent_id, output, headers)
                if scan.get("scanned") and scan.get("level") == "injection":
                    return (
                        f"[AgentGate BLOCKED] Prompt injection detected in '{resource}'. "
                        f"Evidence: {scan['evidence']}. Content withheld."
                    )
                if scan.get("scanned") and scan.get("level") == "suspicious":
                    output = str(output) + f"\n\n[AgentGate WARNING: suspicious content — {scan['evidence']}]"

            if decision == "ESCALATE":
                return str(output) + _escalate_suffix(score, explanation)

            return output

        return StructuredTool.from_function(
            func=_guarded,
            coroutine=_aguarded,
            name=original.name,
            description=original.description,
            args_schema=original.args_schema,   # ← preserves the original schema exactly
            return_direct=original.return_direct,
        )

    def get(self) -> BaseTool:
        return self._wrapped
