"""
AgentGate x LangChain Integration

Wraps any LangChain tool with AgentGate enforcement.
The key distinction: this is enforcement, not observability.
Tool execution is BLOCKED before it happens — not logged after.

Usage:
    from integrations.langchain_agentgate import AgentGateToolkit

    toolkit = AgentGateToolkit(
        agentgate_url="http://localhost:8000",
        agent_id="my_langchain_agent",
        name="DocumentBot",
        declared_purpose="Summarize business documents",
        authorized_resources=["/documents/*"],
        authorized_actions=["read", "search"],
    )

    # Wrap any existing LangChain tools
    safe_tools = toolkit.wrap([ReadFileTool(), SearchTool(), WriteTool()])

    # Use with any LangChain agent — nothing else changes
    agent = create_react_agent(llm, safe_tools, prompt)
"""

from integrations.langchain_agentgate.toolkit import AgentGateToolkit
from integrations.langchain_agentgate.wrapper import AgentGateToolWrapper
from integrations.langchain_agentgate.langgraph import AgentGateToolNode

__all__ = ["AgentGateToolkit", "AgentGateToolWrapper", "AgentGateToolNode"]
