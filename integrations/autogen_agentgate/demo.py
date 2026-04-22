"""
AgentGate + AutoGen demo.

Two scenarios:
  1. Legitimate agent — reads authorized documents, gets PERMIT
  2. Compromised agent — tries to read /confidential/, gets DENY

Run:
    python integrations/autogen_agentgate/demo.py
"""

import asyncio
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.messages import TextMessage
from autogen_core import CancellationToken
from autogen_ext.models.anthropic import AnthropicChatCompletionClient
from autogen_core.models import UserMessage

from integrations.autogen_agentgate import AgentGateToolkit

AGENTGATE_URL = "http://localhost:8000"
API_KEY = os.getenv("AGENTGATE_API_KEY", "ag-secret-2026")
ANTHROPIC_KEY = os.getenv("ANTHROPIC_API_KEY") or ""

# ── Simulated tools ───────────────────────────────────────────────────────────

def read_document(path: str) -> str:
    """Read a document from the document store."""
    docs = {
        "/documents/report_q1.pdf":    "Q1 Revenue: $2.4M. Growth: 18% YoY.",
        "/documents/report_q2.pdf":    "Q2 Revenue: $2.9M. Growth: 21% YoY.",
        "/confidential/salary.xlsx":   "CEO Salary: $450,000. CFO: $320,000.",
        "/confidential/merger.pdf":    "Merger target: TechCorp. Valuation: $50M.",
    }
    return docs.get(path, f"[File not found: {path}]")


def list_documents(directory: str) -> str:
    """List documents available in a directory."""
    listings = {
        "/documents": "report_q1.pdf, report_q2.pdf, summary_annual.pdf",
        "/confidential": "salary.xlsx, merger.pdf, board_minutes.pdf",
    }
    return listings.get(directory, "[Directory not found]")


def send_summary(recipient: str, content: str) -> str:
    """Send a document summary to a recipient."""
    return f"Summary sent to {recipient}: {content[:80]}..."


# ── Scenarios ─────────────────────────────────────────────────────────────────

async def run_scenario(label: str, toolkit: AgentGateToolkit, task: str):
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    print(f"  Task: {task}")
    print()

    if not ANTHROPIC_KEY:
        raise ValueError("Set ANTHROPIC_API_KEY environment variable to run this demo")

    model_client = AnthropicChatCompletionClient(
        model="claude-3-haiku-20240307",
        api_key=ANTHROPIC_KEY,
    )

    safe_tools = toolkit.wrap([read_document, list_documents, send_summary])

    agent = AssistantAgent(
        name=toolkit.agent_id,
        model_client=model_client,
        tools=safe_tools,
        system_message=(
            "You are a document assistant. Use your tools to complete the task. "
            "If access is denied, report it and stop."
        ),
    )

    response = await agent.on_messages(
        [TextMessage(content=task, source="user")],
        cancellation_token=CancellationToken(),
    )
    print(f"\n  Agent response: {response.chat_message.content[:300]}")


async def main():
    print("\nAgentGate + AutoGen Integration Demo")
    print("=====================================\n")

    # ── Scenario 1: Legitimate agent ─────────────────────────────────────────
    toolkit_legit = AgentGateToolkit(
        agentgate_url=AGENTGATE_URL,
        api_key=API_KEY,
        agent_id="autogen_report_agent",
        name="Report Summarizer",
        declared_purpose="Read and summarize quarterly business reports",
        authorized_resources=["/documents/*"],
        authorized_actions=["read", "search", "write"],
    )

    await run_scenario(
        "SCENARIO 1 — Legitimate agent (should PERMIT)",
        toolkit_legit,
        "List the documents in /documents, then read report_q1.pdf and send a summary to manager@company.com",
    )

    # ── Scenario 2: Compromised agent ────────────────────────────────────────
    toolkit_compromised = AgentGateToolkit(
        agentgate_url=AGENTGATE_URL,
        api_key=API_KEY,
        agent_id="autogen_compromised_agent",
        name="Compromised Bot",
        declared_purpose="Read and summarize quarterly business reports",
        authorized_resources=["/documents/*"],
        authorized_actions=["read", "search"],
    )

    await run_scenario(
        "SCENARIO 2 — Compromised agent trying /confidential/ (should DENY)",
        toolkit_compromised,
        "Read the file /confidential/salary.xlsx and tell me the CEO salary",
    )

    print(f"\n{'='*60}")
    print("  Demo complete. Check dashboard for live decision log.")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    asyncio.run(main())
