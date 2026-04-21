"""
AgentGateToolkit — registers an agent and wraps a list of tools in one call.
"""

import httpx
from langchain_core.tools import BaseTool
from integrations.langchain_agentgate.wrapper import AgentGateToolWrapper


class AgentGateToolkit:
    """
    One-stop setup for AgentGate + LangChain.

    1. Registers the agent with AgentGate
    2. Wraps any list of LangChain tools with enforcement
    3. Returns drop-in replacements ready for create_react_agent()
    """

    def __init__(
        self,
        agentgate_url: str,
        agent_id: str,
        name: str,
        declared_purpose: str,
        authorized_resources: list[str],
        authorized_actions: list[str],
        delegation_depth: int = 0,
        processes_external_content: bool = False,
        requires_human_approval: bool = False,
        api_key: str = "",
    ):
        self.agentgate_url = agentgate_url.rstrip("/")
        self.agent_id = agent_id
        self.processes_external_content = processes_external_content
        self._headers = {"X-API-Key": api_key} if api_key else {}
        self.token = self._register(
            agent_id, name, declared_purpose,
            authorized_resources, authorized_actions,
            delegation_depth, processes_external_content,
            requires_human_approval,
        )

    def _register(self, agent_id, name, purpose, resources, actions, depth,
                  ext_content, requires_human_approval) -> str:
        r = httpx.post(
            f"{self.agentgate_url}/agents/register",
            headers=self._headers,
            json={
                "agent_id": agent_id,
                "name": name,
                "declared_purpose": purpose,
                "authorized_resources": resources,
                "authorized_actions": actions,
                "delegation_depth": depth,
                "processes_external_content": ext_content,
                "requires_human_approval": requires_human_approval,
            },
            timeout=15.0,
        )
        r.raise_for_status()
        return r.json()["token"]

    def wrap(self, tools: list[BaseTool]) -> list[BaseTool]:
        """Wrap a list of LangChain tools with AgentGate enforcement."""
        from integrations.langchain_agentgate.wrapper import AgentGateToolWrapper
        wrapped = []
        for t in tools:
            w = AgentGateToolWrapper(
                original_tool=t,
                agentgate_url=self.agentgate_url,
                agent_id=self.agent_id,
                token=self.token,
                processes_external_content=self.processes_external_content,
                api_key=next(iter(self._headers.values()), "") if self._headers else "",
            )
            wrapped.append(w.get())
        return wrapped
