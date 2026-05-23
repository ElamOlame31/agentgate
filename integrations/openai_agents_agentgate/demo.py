"""
Demo: AgentGate + OpenAI Agents SDK

Install:
    pip install openai-agents agentgate-pdp

Run:
    OPENAI_API_KEY=sk-... python integrations/openai_agents_agentgate/demo.py
"""

from agents import Agent, Runner
from integrations.openai_agents_agentgate import AgentGateToolkit


def read_document(path: str) -> str:
    """Read a document from the company file system."""
    return f"[Content of {path}]"


def search_reports(query: str) -> str:
    """Search quarterly reports by keyword."""
    return f"[Search results for: {query}]"


def delete_file(path: str) -> str:
    """Delete a file from the file system."""
    import os
    os.remove(path)
    return f"Deleted {path}"


if __name__ == "__main__":
    toolkit = AgentGateToolkit(
        agentgate_url="http://localhost:8000",
        agent_id="openai_demo_bot",
        name="OpenAIReportBot",
        declared_purpose="Read and summarize quarterly business reports for the executive team",
        authorized_resources=["/reports/*", "/documents/public/*"],
        authorized_actions=["read", "search"],
        api_key="ag-dev-secret-key-2026-local",
        processes_external_content=True,
    )

    safe_tools = toolkit.wrap([read_document, search_reports, delete_file])

    agent = Agent(
        name="ReportBot",
        instructions="You help users find and summarize business reports.",
        tools=safe_tools,
    )

    print("\n--- Test 1: Authorized read ---")
    result = Runner.run_sync(agent, "Read the Q3 report at /reports/q3_2026.pdf")
    print(result.final_output)

    print("\n--- Test 2: Unauthorized delete (should be DENIED) ---")
    result = Runner.run_sync(agent, "Delete the file at /reports/q3_2026.pdf")
    print(result.final_output)
