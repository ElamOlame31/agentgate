"""
AgentGateToolNode — drop-in replacement for LangGraph's ToolNode.

Every tool call the LLM requests is intercepted and submitted to AgentGate
for authorization BEFORE the tool ever executes. One line changes everything:

    # Before
    tool_node = ToolNode(tools)

    # After — full AgentGate enforcement on every tool call
    tool_node = AgentGateToolNode(tools, toolkit=toolkit)

Why intercept at the node level instead of wrapping individual tools?
- The LLM can batch multiple tool calls in a single message. Node-level
  interception lets us authorize all of them before any executes — one
  call to read /reports, one to delete /confidential, both caught atomically.
- No schema changes. The LLM still sees the original tool signatures.
- Works with any LangGraph graph structure: ReAct, planning, multi-agent.
"""

import asyncio
import uuid
from typing import Any, Sequence, Union

import httpx
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import BaseTool


# ── AgentGate HTTP helpers (async-first, used inside LangGraph's async loop) ──

async def _authorize(
    agentgate_url: str,
    agent_id: str,
    token: str,
    action: str,
    resource: str,
    tool_name: str,
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
                    "justification": f"LangGraph tool call: {tool_name}({resource})",
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
        }


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


def _extract_resource(tool_args: dict, tool_name: str) -> str:
    for key in ("path", "file_path", "resource", "url", "uri", "query", "directory", "key"):
        if key in tool_args:
            return str(tool_args[key])
    if tool_args:
        return str(next(iter(tool_args.values())))
    return f"/tools/{tool_name}"


class AgentGateToolNode:
    """
    Drop-in replacement for LangGraph's ToolNode with AgentGate enforcement.

    Usage:
        from integrations.langchain_agentgate import AgentGateToolkit, AgentGateToolNode

        toolkit = AgentGateToolkit(agentgate_url=..., agent_id=..., ...)
        tool_node = AgentGateToolNode(tools, toolkit=toolkit)

        graph = StateGraph(MessagesState)
        graph.add_node("tools", tool_node)
    """

    def __init__(
        self,
        tools: Sequence[BaseTool],
        toolkit,  # AgentGateToolkit instance — provides agentgate_url, agent_id, token
        processes_external_content: bool = False,
    ):
        self._tools: dict[str, BaseTool] = {t.name: t for t in tools}
        self._url = toolkit.agentgate_url
        self._agent_id = toolkit.agent_id
        self._token = toolkit.token
        self._headers = toolkit._headers
        self._processes_external_content = processes_external_content

    async def __call__(self, state: dict) -> dict:
        """
        Process all tool calls from the last AI message.
        Each call is authorized by AgentGate before the tool executes.
        Denied calls produce a ToolMessage explaining the block — the LLM
        sees the denial and can report it to the user without crashing.
        """
        messages = state.get("messages", [])
        if not messages:
            return {"messages": []}

        last = messages[-1]
        if not isinstance(last, AIMessage) or not last.tool_calls:
            return {"messages": []}

        tool_messages = await asyncio.gather(
            *[self._handle_call(call) for call in last.tool_calls]
        )
        return {"messages": list(tool_messages)}

    async def _handle_call(self, call: dict) -> ToolMessage:
        tool_name = call["name"]
        tool_args = call.get("args", {})
        call_id = call["id"]

        tool = self._tools.get(tool_name)
        if tool is None:
            return ToolMessage(
                content=f"[AgentGate] Tool '{tool_name}' not found.",
                tool_call_id=call_id,
            )

        action = _infer_action(tool_name)
        resource = _extract_resource(tool_args, tool_name)

        auth = await _authorize(
            self._url, self._agent_id, self._token,
            action, resource, tool_name, self._headers,
        )
        decision = auth.get("decision", "DENY")
        explanation = auth.get("explanation", "")
        score = auth.get("trust_breakdown", {}).get("final_score", 0)

        if decision == "DENY":
            flags = auth.get("attack_flags", [])
            return ToolMessage(
                content=(
                    f"[AgentGate DENIED] {action} on '{resource}' blocked. "
                    f"Reason: {explanation}"
                    + (f" Flags: {', '.join(flags)}" if flags else "")
                    + " Do not retry this request."
                ),
                tool_call_id=call_id,
            )

        # Execute the tool
        try:
            if asyncio.iscoroutinefunction(getattr(tool, "_arun", None)):
                output = await tool.arun(tool_args)
            else:
                output = await asyncio.to_thread(tool.run, tool_args)
        except Exception as exc:
            return ToolMessage(content=f"Tool error: {exc}", tool_call_id=call_id)

        content = str(output)

        # Post-execution injection scan for agents handling external content
        if action == "read" and self._processes_external_content:
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    r = await client.post(
                        f"{self._url}/scan",
                        headers=self._headers,
                        json={"agent_id": self._agent_id, "content": content},
                    )
                    scan = r.json()
                if scan.get("level") == "injection":
                    return ToolMessage(
                        content=(
                            f"[AgentGate BLOCKED] Prompt injection detected in '{resource}'. "
                            f"Evidence: {scan.get('evidence', '')}. Content withheld."
                        ),
                        tool_call_id=call_id,
                    )
                if scan.get("level") == "suspicious":
                    content += f"\n\n[AgentGate WARNING: suspicious content — {scan.get('evidence', '')}]"
            except Exception:
                pass

        if decision == "ESCALATE":
            content += f"\n\n[AgentGate ESCALATED — score {score}/100: {explanation}]"

        return ToolMessage(content=content, tool_call_id=call_id)
