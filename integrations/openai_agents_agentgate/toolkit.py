"""
AgentGate integration for OpenAI Agents SDK (openai-agents >= 0.0.3).

Usage:

    from agents import Agent, Runner
    from integrations.openai_agents_agentgate import AgentGateToolkit

    toolkit = AgentGateToolkit(
        agentgate_url="http://localhost:8000",
        api_key="your-key",
        agent_id="openai_research_bot",
        name="ResearchBot",
        declared_purpose="Research and summarize public financial documents",
        authorized_resources=["/documents/*", "/reports/*"],
        authorized_actions=["read", "search"],
    )

    safe_tools = toolkit.wrap([read_document, search_web])

    agent = Agent(name="ResearchBot", tools=safe_tools)
    result = Runner.run_sync(agent, "Summarize Q3 reports")

Every tool call is intercepted by AgentGate before execution.
DENY     -> raises PermissionError (agent handles gracefully)
ESCALATE -> tool runs but response is annotated with flag
PENDING  -> blocks until human approves/denies (auto-deny after 95s)
"""

import uuid
import time
import functools
import inspect
import httpx
from typing import Callable, Any

try:
    from agents import function_tool
    OPENAI_AGENTS_AVAILABLE = True
except ImportError:
    OPENAI_AGENTS_AVAILABLE = False
    function_tool = None


def _infer_action(func_name: str) -> str:
    name = func_name.lower()
    if any(k in name for k in ["delete", "remove", "drop", "erase", "purge"]):
        return "delete"
    if any(k in name for k in ["write", "create", "save", "update", "insert", "post", "send", "upload"]):
        return "write"
    if any(k in name for k in ["search", "list", "find", "query", "browse", "fetch"]):
        return "search"
    return "read"


def _extract_resource(func_name: str, args: tuple, kwargs: dict) -> str:
    for key in ("path", "file_path", "resource", "url", "query", "topic", "directory", "filename"):
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
            "agent_id":     agent_id,
            "token":        token,
            "action":       action,
            "resource":     resource,
            "justification": justification,
            "request_id":   str(uuid.uuid4()),
        },
        timeout=30.0,
    )
    r.raise_for_status()
    return r.json()


def _poll_pending(url: str, request_id: str, headers: dict, timeout: int = 95) -> str:
    deadline = time.time() + timeout
    print(f"[AgentGate] Waiting for human approval ({timeout}s timeout)...")
    while time.time() < deadline:
        try:
            r = httpx.get(f"{url}/decisions/{request_id}", headers=headers, timeout=5.0)
            if r.status_code == 200:
                status = r.json().get("status", "PENDING")
                if status in ("APPROVED", "DENIED"):
                    print(f"[AgentGate] Human decision: {status}")
                    return status
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
    @functools.wraps(func)
    def guarded(*args, **kwargs) -> Any:
        action   = action_override or _infer_action(func.__name__)
        resource = _extract_resource(func.__name__, args, kwargs)

        result     = _authorize(url, agent_id, token, action, resource,
                                f"OpenAI agent calling {func.__name__}", headers)
        decision   = result["decision"]
        score      = result["trust_breakdown"]["final_score"]
        explanation = result.get("explanation", "")

        if decision == "DENY":
            raise PermissionError(
                f"[AgentGate] ACCESS DENIED: {action} on '{resource}'. "
                f"Reason: {explanation}."
            )

        if decision == "PENDING":
            request_id    = result.get("request_id", "")
            human_decision = _poll_pending(url, request_id, headers, pending_timeout)
            if human_decision != "APPROVED":
                raise PermissionError(
                    f"[AgentGate] ACCESS DENIED by human reviewer: "
                    f"{action} on '{resource}'."
                )

        output = func(*args, **kwargs)

        # Prompt injection scan for agents that read external content
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
                        raise PermissionError(
                            f"[AgentGate] CONTENT BLOCKED: prompt injection detected in "
                            f"'{resource}'. Evidence: {scan.get('evidence', '')}."
                        )
                    if scan.get("level") == "suspicious":
                        output = (
                            f"{output}\n\n"
                            f"[AgentGate WARNING: suspicious content detected — "
                            f"{scan.get('evidence', '')}]"
                        )
            except PermissionError:
                raise
            except Exception:
                pass

        if decision == "ESCALATE":
            return f"{output}\n\n[AgentGate FLAGGED: score {score:.0f}/100 — {explanation}]"

        return output

    return guarded


class AgentGateToolkit:
    """
    Registers an OpenAI agent with AgentGate and wraps tools with enforcement.

    Compatible with openai-agents SDK — returns function_tool-decorated callables
    ready for Agent(tools=[...]).
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
        delegation_depth: int = 0,
        processes_external_content: bool = False,
        requires_human_approval: bool = False,
        pending_timeout: int = 95,
    ):
        if not OPENAI_AGENTS_AVAILABLE:
            raise ImportError(
                "openai-agents is required. Install it with: pip install openai-agents"
            )

        self.url     = agentgate_url.rstrip("/")
        self.agent_id = agent_id
        self._headers = {"X-API-Key": api_key} if api_key else {}
        self.processes_external_content = processes_external_content
        self.pending_timeout = pending_timeout

        r = httpx.post(
            f"{self.url}/agents/register",
            headers=self._headers,
            json={
                "agent_id":               agent_id,
                "name":                   name,
                "declared_purpose":       declared_purpose,
                "authorized_resources":   authorized_resources,
                "authorized_actions":     authorized_actions,
                "delegation_depth":       delegation_depth,
                "processes_external_content": processes_external_content,
                "requires_human_approval":    requires_human_approval,
            },
            timeout=30.0,
        )
        r.raise_for_status()
        self._token = r.json()["token"]
        print(f"[AgentGate] Registered OpenAI agent: {agent_id}")

    def wrap(self, functions: list[Callable]) -> list:
        """
        Wrap Python functions with AgentGate enforcement and convert them to
        OpenAI Agents SDK function_tool objects.
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
            # function_tool decorator from openai-agents SDK
            wrapped = function_tool(guarded)
            tools.append(wrapped)
            print(f"[AgentGate] Wrapped tool: {func.__name__}")
        return tools


def agentgate_tool(
    gate_or_url,
    action: str | None = None,
    resource_arg: str = "path",
    api_key: str = "",
):
    """
    Standalone decorator — no toolkit needed.

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
            act      = action or _infer_action(func.__name__)
            resource = kwargs.get(resource_arg) or _extract_resource(func.__name__, args, kwargs)
            result   = _authorize(url, agent_id, token, act, str(resource),
                                  f"Calling {func.__name__}", headers)
            if result["decision"] == "DENY":
                raise PermissionError(
                    f"AgentGate DENIED {act} on {resource}: {result.get('explanation', '')}"
                )
            return func(*args, **kwargs)
        if function_tool:
            return function_tool(wrapper)
        return wrapper
    return decorator
