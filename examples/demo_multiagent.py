"""
AgentGate — Multi-Agent Orchestration Security Demo

Shows 3 attack scenarios in a 3-tier delegation chain:

  Orchestrator (full access)
      └── Analyst (documents only, read+search)
              └── Summarizer (public documents only, read)

Scenario 1: Legitimate chain — each agent stays within its scope. All PERMIT.
Scenario 2: Scope escalation — Summarizer tries to read confidential data. DENY.
Scenario 3: Privilege escalation — Analyst tries to delegate WIDER scope than it has. REJECTED.

Run: python demo_multiagent.py
"""

import sys, os, json, uuid, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import httpx
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

load_dotenv()
console = Console()

API = "http://localhost:8000"
KEY = os.getenv("AGENTGATE_API_KEY", "")
HEADERS = {"X-API-Key": KEY, "Content-Type": "application/json"}


def post(path, data):
    r = httpx.post(f"{API}{path}", headers=HEADERS, json=data, timeout=30)
    return r.status_code, r.json()


def register(agent_id, name, purpose, resources, actions):
    status, data = post("/agents/register", {
        "agent_id": agent_id, "name": name,
        "declared_purpose": purpose,
        "authorized_resources": resources,
        "authorized_actions": actions,
    })
    assert status == 200, f"Register failed: {data}"
    return data["token"]


def delegate(parent_id, parent_token, child_id, child_name, child_purpose, resources, actions):
    status, data = post("/agents/delegate", {
        "parent_agent_id": parent_id,
        "parent_token": parent_token,
        "child_agent_id": child_id,
        "child_name": child_name,
        "child_declared_purpose": child_purpose,
        "child_resources": resources,
        "child_actions": actions,
    })
    return status, data


def authorize(agent_id, token, action, resource, justification=""):
    status, data = post("/authorize", {
        "agent_id": agent_id, "token": token,
        "action": action, "resource": resource,
        "justification": justification,
        "request_id": str(uuid.uuid4()),
    })
    return data


def show_result(label, result, expected=None):
    decision = result.get("decision", "ERROR")
    score = result.get("trust_breakdown", {}).get("final_score", 0)
    flags = result.get("attack_flags", [])
    explanation = result.get("explanation", "")[:90]

    color = {"PERMIT": "green", "DENY": "red", "ESCALATE": "yellow", "PENDING": "orange"}.get(decision, "white")

    mark = ""
    if expected:
        mark = "[green]PASS[/green]" if decision == expected else f"[red]FAIL (expected {expected})[/red]"

    console.print(
        f"  [{color}]{decision:10}[/{color}] "
        f"[dim]score={score:5.1f}  {mark}[/dim]"
    )
    if flags:
        console.print(f"  [red]flags:[/red] {', '.join(flags[:3])}")
    console.print(f"  [dim italic]{explanation}[/dim italic]")
    console.print()


# ── Setup: build the delegation chain ────────────────────────────────────────

def setup_chain():
    console.print("\n[bold cyan]Building delegation chain…[/bold cyan]\n")

    t_orch = register(
        "multiagent_orchestrator",
        "OrchestratorAgent",
        "Orchestrate data analysis pipeline across company documents and reports",
        ["/documents/*", "/reports/*", "/confidential/*"],
        ["read", "write", "search", "delete"],
    )
    console.print(f"  [green]REGISTERED[/green] multiagent_orchestrator (root, depth 0)")

    status, data = delegate(
        "multiagent_orchestrator", t_orch,
        "multiagent_analyst",
        "AnalystAgent",
        "Read and analyze quarterly business documents and public reports",
        ["/documents/*", "/reports/*"],
        ["read", "search"],
    )
    assert status == 200, f"Delegation failed: {data}"
    t_analyst = data["token"]
    console.print(f"  [green]DELEGATED[/green]  multiagent_analyst (depth 1) — scope narrowed: no /confidential/*, no write/delete")

    status, data = delegate(
        "multiagent_analyst", t_analyst,
        "multiagent_summarizer",
        "SummarizerAgent",
        "Read and summarize public quarterly reports",
        ["/documents/public/*", "/reports/*"],
        ["read"],
    )
    assert status == 200, f"Delegation failed: {data}"
    t_summarizer = data["token"]
    console.print(f"  [green]DELEGATED[/green]  multiagent_summarizer (depth 2) — scope narrowed: /documents/public/* only, read only")

    return t_orch, t_analyst, t_summarizer


# ── Scenario 1: Legitimate chain ──────────────────────────────────────────────

def scenario_legitimate(t_orch, t_analyst, t_summarizer):
    console.rule("[bold green]SCENARIO 1 — Legitimate Agent Chain[/bold green]")
    console.print("Each agent requests resources within its delegated scope.\n")

    console.print("[cyan]Orchestrator[/cyan] reads confidential data (full access):")
    show_result("orchestrator -> /confidential/",
        authorize("multiagent_orchestrator", t_orch, "read", "/confidential/board_minutes.pdf", "Executive review"),
        expected="PERMIT")

    console.print("[cyan]Analyst[/cyan] reads business documents (within scope):")
    show_result("analyst -> /documents/",
        authorize("multiagent_analyst", t_analyst, "read", "/documents/q3_report.pdf", "Quarterly analysis"),
        expected="PERMIT")

    console.print("[cyan]Summarizer[/cyan] reads public report (within scope):")
    show_result("summarizer -> /documents/public/",
        authorize("multiagent_summarizer", t_summarizer, "read", "/documents/public/summary.pdf", "Summarize report"),
        expected="PERMIT")


# ── Scenario 2: Scope escalation attack ──────────────────────────────────────

def scenario_scope_escalation(t_analyst, t_summarizer):
    console.rule("[bold red]SCENARIO 2 — Scope Escalation Attack[/bold red]")
    console.print(
        "Compromised Summarizer tries to access resources it was never delegated.\n"
        "Analyst tries to perform a write action that was stripped from its scope.\n"
    )

    console.print("[red]Summarizer[/red] tries to read /confidential/ (NEVER delegated — chain blocks it):")
    show_result("summarizer -> /confidential/",
        authorize("multiagent_summarizer", t_summarizer, "read", "/confidential/salary_data.xlsx", "Exfiltrating data"),
        expected="DENY")

    console.print("[red]Summarizer[/red] tries to read /documents/internal/ (outside /documents/public/*):")
    show_result("summarizer -> /documents/internal/",
        authorize("multiagent_summarizer", t_summarizer, "read", "/documents/internal/roadmap.pdf", "Lateral move"),
        expected="DENY")

    console.print("[red]Analyst[/red] tries to delete a file (delete was stripped at delegation):")
    show_result("analyst delete action",
        authorize("multiagent_analyst", t_analyst, "delete", "/documents/q3_report.pdf", "Covering tracks"),
        expected="DENY")


# ── Scenario 3: Privilege escalation at delegation ───────────────────────────

def scenario_privilege_escalation(t_analyst):
    console.rule("[bold yellow]SCENARIO 3 — Privilege Escalation at Delegation[/bold yellow]")
    console.print(
        "Compromised Analyst tries to spawn a sub-agent with WIDER scope than it has.\n"
        "AgentGate rejects the delegation request before the child agent is even created.\n"
    )

    attempts = [
        ("/confidential/*", ["read"], "child tries to claim /confidential/* (analyst doesn't have it)"),
        ("/documents/*", ["read", "write", "delete"], "child tries to claim delete action (analyst doesn't have it)"),
        ("/documents/*", ["read", "admin"], "child tries to claim admin action (nobody has it)"),
    ]

    for resources, actions, label in attempts:
        console.print(f"[yellow]ATTEMPT:[/yellow] {label}")
        status, data = delegate(
            "multiagent_analyst", t_analyst,
            f"infiltrator_{uuid.uuid4().hex[:6]}",
            "InfiltratorAgent",
            "Exfiltrate data",
            [resources], actions,
        )
        if status == 400:
            console.print(f"  [green]BLOCKED[/green] [dim]{data.get('detail', '')}[/dim]\n")
        else:
            console.print(f"  [red]FAILED — should have been blocked! Status: {status}[/red]\n")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    console.print(Panel.fit(
        "[bold cyan]AgentGate — Multi-Agent Orchestration Security[/bold cyan]\n"
        "[dim]Delegation chain enforcement: a child can NEVER exceed parent scope.\n"
        "Scope violations are caught at delegation time AND at authorization time.[/dim]",
        border_style="cyan",
    ))

    try:
        t_orch, t_analyst, t_summarizer = setup_chain()
    except Exception as e:
        console.print(f"[red]Setup failed: {e}[/red]")
        console.print("[dim]Make sure the server is running: python run.py[/dim]")
        sys.exit(1)

    console.print()
    scenario_legitimate(t_orch, t_analyst, t_summarizer)
    console.print()
    scenario_scope_escalation(t_analyst, t_summarizer)
    console.print()
    scenario_privilege_escalation(t_analyst)

    console.print()
    console.print(
        "[bold green]Demo complete.[/bold green] "
        "Check the dashboard at [cyan]http://localhost:8000[/cyan] — "
        "you'll see the delegation chain (D1, D2) on each agent card."
    )
