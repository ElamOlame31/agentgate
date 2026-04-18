"""
AgentGateToolWrapper — wraps any LangChain tool with enforcement.

Uses a functional approach: creates a new @tool function with the same
schema as the original, but intercepts the call before execution.
This is the approach that works reliably with LangGraph's create_react_agent.
"""

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
               action: str, resource: str, justification: str) -> dict:
    r = httpx.post(
        f"{agentgate_url}/authorize",
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


class AgentGateToolWrapper:
    """
    Wraps a LangChain tool: returns a new tool with the same schema
    but with AgentGate enforcement added before execution.
    """

    def __init__(self, original_tool: BaseTool, agentgate_url: str,
                 agent_id: str, token: str):
        self.original_tool = original_tool
        self.agentgate_url = agentgate_url
        self.agent_id = agent_id
        self.token = token
        self.wrapped = self._build()

    def _build(self) -> BaseTool:
        original = self.original_tool
        agentgate_url = self.agentgate_url
        agent_id = self.agent_id
        token = self.token

        # Build a new tool function with the same schema
        # by copying the original tool's args_schema
        original_func = original.func if hasattr(original, "func") else None

        if original_func is None:
            # Can't wrap without the original function — return as-is
            return original

        import functools

        @functools.wraps(original_func)
        def guarded(*args, **kwargs):
            # Determine resource and action
            resource = _extract_resource(kwargs if kwargs else (args[0] if args else ""))
            action = _infer_action(original.name)
            justification = f"LangChain agent calling {original.name}"

            result = _authorize(agentgate_url, agent_id, token, action, resource, justification)
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

            # Execute the real tool
            output = original_func(*args, **kwargs)

            if decision == "ESCALATE":
                return (
                    f"{output}\n\n"
                    f"[AgentGate FLAGGED: score {score}/100. {explanation}]"
                )

            return output

        # Create new tool preserving original name and description
        guarded.__name__ = original.name
        guarded.__doc__ = original.description
        wrapped_tool = lc_tool(guarded)
        return wrapped_tool

    def get(self) -> BaseTool:
        return self.wrapped
