"""
AgentGateToolWrapper — wraps any LangChain tool with enforcement.

Uses a functional approach: creates a new @tool function with the same
schema as the original, but intercepts the call before execution.
This is the approach that works reliably with LangGraph's create_react_agent.
"""

import time
import uuid
import httpx
from langchain_core.tools import tool as lc_tool, BaseTool


def _extract_resource(tool_input) -> str:
    if isinstance(tool_input, str):
        return tool_input.strip().split()[0] if tool_input.strip() else tool_input
    if isinstance(tool_input, dict):
        for key in ("path", "file_path", "resource", "url", "query", "directory"):
            if key in tool_input:
                return str(tool_input[key])
        if tool_input:
            return str(next(iter(tool_input.values())))
    return str(tool_input)


def _infer_action(tool_name: str) -> str:
    name = tool_name.lower()
    if any(k in name for k in ["delete", "remove", "drop"]):
        return "delete"
    if any(k in name for k in ["write", "create", "save", "update", "insert"]):
        return "write"
    if any(k in name for k in ["search", "list", "find", "query"]):
        return "search"
    return "read"


def _authorize(agentgate_url: str, agent_id: str, token: str,
               action: str, resource: str, justification: str,
               headers: dict = {}) -> dict:
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
        timeout=30.0,
    )
    r.raise_for_status()
    return r.json()


def _poll_decision(agentgate_url: str, request_id: str,
                   headers: dict = {}, max_wait: int = 95) -> str:
    """Poll /decisions/{id} until resolved or timeout. Returns 'APPROVED' or 'DENIED'."""
    deadline = time.time() + max_wait
    remaining = max_wait
    print(f"[AgentGate] Waiting for human approval on {request_id}… ({max_wait}s timeout)")
    while time.time() < deadline:
        try:
            r = httpx.get(
                f"{agentgate_url}/decisions/{request_id}",
                headers=headers,
                timeout=5.0,
            )
            if r.status_code == 200:
                data = r.json()
                status = data.get("status", "PENDING")
                if status in ("APPROVED", "DENIED"):
                    return status
                expires_at = data.get("expires_at", 0)
                remaining = max(0, int(expires_at - time.time()))
                print(f"[AgentGate] Still pending… {remaining}s remaining", end="\r")
        except Exception:
            pass
        time.sleep(2)
    return "DENIED"


def _scan_content(agentgate_url: str, agent_id: str, content: str,
                  headers: dict = {}) -> dict:
    r = httpx.post(
        f"{agentgate_url}/scan",
        headers=headers,
        json={"agent_id": agent_id, "content": content},
        timeout=30.0,
    )
    r.raise_for_status()
    return r.json()


class AgentGateToolWrapper:
    """
    Wraps a LangChain tool: returns a new tool with the same schema
    but with AgentGate enforcement added before execution.
    """

    def __init__(self, original_tool: BaseTool, agentgate_url: str,
                 agent_id: str, token: str, processes_external_content: bool = False,
                 api_key: str = ""):
        self.original_tool = original_tool
        self.agentgate_url = agentgate_url
        self.agent_id = agent_id
        self.token = token
        self.processes_external_content = processes_external_content
        self._headers = {"X-API-Key": api_key} if api_key else {}
        self.wrapped = self._build()

    def _build(self) -> BaseTool:
        original = self.original_tool
        agentgate_url = self.agentgate_url
        agent_id = self.agent_id
        token = self.token
        processes_external_content = self.processes_external_content
        headers = self._headers

        original_func = original.func if hasattr(original, "func") else None

        if original_func is None:
            return original

        import functools

        @functools.wraps(original_func)
        def guarded(*args, **kwargs):
            resource = _extract_resource(kwargs if kwargs else (args[0] if args else ""))
            action = _infer_action(original.name)
            justification = f"LangChain agent calling {original.name}"

            result = _authorize(agentgate_url, agent_id, token, action, resource, justification, headers)
            decision = result["decision"]
            score = result["trust_breakdown"]["final_score"]
            explanation = result["explanation"]

            if decision == "DENY":
                return (
                    f"ACCESS DENIED by AgentGate security layer. "
                    f"Action: {action} on '{resource}'. "
                    f"Reason: {explanation}. "
                    f"Do not retry this request."
                )

            if decision == "PENDING":
                request_id = result.get("request_id", "")
                print(f"\n[AgentGate] HUMAN APPROVAL REQUIRED for {action} on '{resource}'")
                print(f"[AgentGate] Check your phone or dashboard to approve/deny.")
                human_decision = _poll_decision(agentgate_url, request_id, headers)
                print(f"\n[AgentGate] Human decision: {human_decision}")
                if human_decision != "APPROVED":
                    return (
                        f"ACCESS DENIED by human reviewer via AgentGate.\n"
                        f"Action: {action} on '{resource}'.\n"
                        f"A human operator reviewed and denied this request.\n"
                        f"Do not retry this request."
                    )

            # Execute the real tool
            output = original_func(*args, **kwargs)

            # Injection scan: only for read actions on agents that handle external content
            if action == "read" and processes_external_content and isinstance(output, str):
                scan = _scan_content(agentgate_url, agent_id, output, headers)
                if scan.get("scanned") and scan.get("level") == "injection":
                    return (
                        f"CONTENT BLOCKED by AgentGate injection detector.\n"
                        f"Resource: '{resource}'\n"
                        f"Detection: {scan['evidence']}\n"
                        f"Confidence: {scan['confidence']:.0%}\n"
                        f"The document contains prompt injection instructions. "
                        f"Content has been withheld to protect agent integrity."
                    )
                elif scan.get("scanned") and scan.get("level") == "suspicious":
                    output = (
                        f"{output}\n\n"
                        f"[AgentGate WARNING: suspicious content detected — {scan['evidence']}]"
                    )

            if decision == "ESCALATE":
                return (
                    f"{output}\n\n"
                    f"[AgentGate FLAGGED: score {score}/100. {explanation}]"
                )

            return output

        guarded.__name__ = original.name
        guarded.__doc__ = original.description
        wrapped_tool = lc_tool(guarded)
        return wrapped_tool

    def get(self) -> BaseTool:
        return self.wrapped
