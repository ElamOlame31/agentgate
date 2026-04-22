"""
AgentGate integration for Microsoft AutoGen (autogen-agentchat >= 0.4).

Usage:

    from autogen_agentchat.agents import AssistantAgent
    from integrations.autogen_agentgate import AgentGateToolkit

    toolkit = AgentGateToolkit(
        agentgate_url="http://localhost:8000",
        api_key="your-key",
        agent_id="autogen_agent",
        name="ResearchBot",
        declared_purpose="Research and summarize documents",
        authorized_resources=["/documents/*"],
        authorized_actions=["read", "search"],
    )

    safe_tools = toolkit.wrap([read_document, search_web, send_email])

    agent = AssistantAgent(
        name="ResearchBot",
        model_client=model_client,
        tools=safe_tools,
    )

Every tool call goes through AgentGate before executing.
DENY  → tool returns an access-denied message (agent gracefully handles it)
ESCALATE → tool runs but response is flagged
PENDING → blocks until human approves/denies (auto_resolve_pending=True by default)
"""

import uuid
import time
import functools
import httpx
from typing import Callable, Any

try:
    from autogen_core.tools import FunctionTool
    AUTOGEN_AVAILABLE = True
except ImportError:
    AUTOGEN_AVAILABLE = False
    FunctionTool = None


def _infer_action(func_name: str) -> str:
    name = func_name.lower()
    if any(k in name for k in ["delete", "remove", "drop", "erase"]):
        return "delete"
    if any(k in name for k in ["write", "create", "save", "update", "insert", "post", "send"]):
        return "write"
    if any(k in name for k in ["search", "list", "find", "query", "browse"]):
        return "search"
    return "read"


def _extract_resource(func_name: str, args: tuple, kwargs: dict) -> str:
    for key in ("path", "file_path", "resource", "url", "query", "topic", "directory"):
        if key in kwargs:
            return str(kwargs[key])
    if args:
        return str(args[0])
    return f"/{func_name}"


def _authorize(url: str, agent_id: str, token: str, action: str,
               resource: str, justification: str, headers: dict) -> dict:
    r = httpx.post(
        f"{url}/authorize",
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


def _poll_decision(url: str, request_id: str, headers: dict, timeout: int = 95) -> str:
    deadline = time.time() + timeout
    print(f"[AgentGate] Waiting for human approval ({timeout}s timeout)...")
    while time.time() < deadline:
        try:
            r = httpx.get(f"{url}/decisions/{request_id}", headers=headers, timeout=5.0)
            if r.status_code == 200:
                data = r.json()
                status = data.get("status", "PENDING")
                if status in ("APPROVED", "DENIED"):
                    print(f"[AgentGate] Human decision: {status}")
                    return status
                remaining = max(0, int(data.get("expires_at", 0) - time.time()))
                print(f"[AgentGate] Still pending... {remaining}s remaining", end="\r")
        except Exception:
            pass
        time.sleep(2)
    print("[AgentGate] Timeout — auto-denied")
    return "DENIED"


def _wrap_function(
    func: Callable,
    url: str,
    agent_id: str,
    token: str,
    headers: dict,
    action_override: str | None = None,
    processes_external_content: bool = False,
    pending_timeout: int = 95,
) -> Callable:
    """Return a new function with AgentGate enforcement injected before execution."""

    @functools.wraps(func)
    def guarded(*args, **kwargs) -> Any:
        action = action_override or _infer_action(func.__name__)
        resource = _extract_resource(func.__name__, args, kwargs)
        justification = f"AutoGen agent calling {func.__name__}"

        result = _authorize(url, agent_id, token, action, resource, justification, headers)
        decision = result["decision"]
        score = result["trust_breakdown"]["final_score"]
        explanation = result.get("explanation", "")

        if decision == "DENY":
            return (
                f"[AgentGate] ACCESS DENIED: {action} on '{resource}'. "
                f"Reason: {explanation}. Do not retry."
            )

        if decision == "PENDING":
            request_id = result.get("request_id", "")
            print(f"\n[AgentGate] HUMAN APPROVAL REQUIRED: {action} on '{resource}'")
            human_decision = _poll_decision(url, request_id, headers, pending_timeout)
            if human_decision != "APPROVED":
                return (
                    f"[AgentGate] ACCESS DENIED by human reviewer: "
                    f"{action} on '{resource}'. Do not retry."
                )

        # Execute the real function
        output = func(*args, **kwargs)

        # Injection scan for agents that process external content
        if action == "read" and processes_external_content and isinstance(output, str):
            try:
                scan_r = httpx.post(
                    f"{url}/scan",
                    headers=headers,
                    json={"agent_id": agent_id, "content": output},
                    timeout=30.0,
                )
                if scan_r.status_code == 200:
                    scan = scan_r.json()
                    if scan.get("level") == "injection":
                        return (
                            f"[AgentGate] CONTENT BLOCKED: prompt injection detected in '{resource}'. "
                            f"Evidence: {scan.get('evidence', '')}. "
                            f"Content withheld to protect agent integrity."
                        )
                    elif scan.get("level") == "suspicious":
                        output = f"{output}\n\n[AgentGate WARNING: suspicious content — {scan.get('evidence', '')}]"
            except Exception:
                pass

        if decision == "ESCALATE":
            return f"{output}\n\n[AgentGate FLAGGED: score {score}/100. {explanation}]"

        return output

    return guarded


class AgentGateToolkit:
    """
    Wraps Python functions as AgentGate-enforced AutoGen FunctionTools.

    Every tool call is authorized before execution. DENY returns a safe
    error message the agent can handle gracefully. PENDING blocks until
    a human approves or the timeout fires.
    """

    def __init__(
        self,
        agentgate_url: str,
        agent_id: str,
        name: str,
        declared_purpose: str,
        authorized_resources: list[str],
        authorized_actions: list[str],
        api_key: str = "",
        processes_external_content: bool = False,
        requires_human_approval: bool = False,
        pending_timeout: int = 95,
    ):
        if not AUTOGEN_AVAILABLE:
            raise ImportError(
                "autogen-agentchat is required. Install it with: "
                "pip install autogen-agentchat"
            )

        self.url = agentgate_url.rstrip("/")
        self.agent_id = agent_id
        self._headers = {"X-API-Key": api_key} if api_key else {}
        self.processes_external_content = processes_external_content
        self.pending_timeout = pending_timeout

        # Register the agent
        r = httpx.post(
            f"{self.url}/agents/register",
            headers=self._headers,
            json={
                "agent_id": agent_id,
                "name": name,
                "declared_purpose": declared_purpose,
                "authorized_resources": authorized_resources,
                "authorized_actions": authorized_actions,
                "processes_external_content": processes_external_content,
                "requires_human_approval": requires_human_approval,
            },
            timeout=30.0,
        )
        r.raise_for_status()
        self._token = r.json()["token"]
        print(f"[AgentGate] Registered AutoGen agent: {agent_id} (token={self._token[:8]}...)")

    def wrap(self, functions: list[Callable]) -> list:
        """
        Wrap a list of Python functions with AgentGate enforcement.
        Returns a list of FunctionTool objects ready for AssistantAgent(tools=...).
        """
        tools = []
        for func in functions:
            guarded = _wrap_function(
                func=func,
                url=self.url,
                agent_id=self.agent_id,
                token=self._token,
                headers=self._headers,
                processes_external_content=self.processes_external_content,
                pending_timeout=self.pending_timeout,
            )
            tool = FunctionTool(
                func=guarded,
                description=func.__doc__ or f"Execute {func.__name__} with AgentGate enforcement",
                name=func.__name__,
            )
            tools.append(tool)
            print(f"[AgentGate] Wrapped tool: {func.__name__}")
        return tools


def agentgate_tool(
    gate_or_url,
    action: str | None = None,
    resource_arg: str = "path",
    api_key: str = "",
):
    """
    Decorator for standalone use — no toolkit needed.

    @agentgate_tool(gate, action="read", resource_arg="path")
    def read_document(path: str) -> str:
        return open(path).read()
    """
    from agentgate import AgentGate

    if isinstance(gate_or_url, AgentGate):
        gate = gate_or_url
        url = gate.url
        agent_id = gate.agent_id or ""
        token = gate.token or ""
        headers = gate._headers
    else:
        url = gate_or_url
        agent_id = ""
        token = ""
        headers = {"X-API-Key": api_key} if api_key else {}

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            act = action or _infer_action(func.__name__)
            resource = kwargs.get(resource_arg) or _extract_resource(func.__name__, args, kwargs)
            result = _authorize(url, agent_id, token, act, str(resource), f"Calling {func.__name__}", headers)
            if result["decision"] == "DENY":
                raise PermissionError(f"AgentGate DENIED {act} on {resource}: {result.get('explanation','')}")
            return func(*args, **kwargs)
        return wrapper
    return decorator
