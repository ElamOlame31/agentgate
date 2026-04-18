"""
AgentGate SDK — live demo.

Shows a developer adding AgentGate to three different agents in 3 lines each:
  1. LegitAgent     — works perfectly, all requests permitted
  2. DriftingAgent  — registered as summarizer, tries to delete salary files → caught
  3. SneakyAgent    — tries to call authorize() without registering → caught instantly
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from sdk import AgentGate
from sdk.exceptions import AgentGateDenied, AgentGateEscalated, AgentGateNotRegistered

console = Console()
AGENTGATE_URL = "http://localhost:8000"


# ── Helper ────────────────────────────────────────────────────────────────────

def show_result(result: dict, label: str = ""):
    decision = result["decision"]
    score = result["trust_breakdown"]["final_score"]
    flags = result.get("attack_flags", [])
    color = {"PERMIT": "green", "DENY": "red", "ESCALATE": "yellow"}.get(decision, "white")
    flag_str = ", ".join(flags) if flags else "—"
    console.print(
        f"  [{color}]{decision}[/{color}] [dim]{label}[/dim] "
        f"score=[bold]{score}[/bold] flags=[yellow]{flag_str}[/yellow]"
    )
    console.print(f"  [italic dim]  -> {result['explanation']}[/italic dim]")


# ── Demo 1: Legitimate agent using the SDK ────────────────────────────────────

def demo_legit_agent():
    console.rule("[bold green]DEMO 1 — Legitimate Agent (SDK)[/bold green]")
    console.print("A developer adds 3 lines of AgentGate SDK to their summarizer bot.\n")

    # ── 3 lines to integrate ──────────────────────────────────────────────────
    gate = AgentGate(AGENTGATE_URL)
    gate.register("sdk_legit_001", "QuarterlyBot", "Summarize quarterly PDF reports",
                  ["/reports/*"], ["read", "list"])
    # ─────────────────────────────────────────────────────────────────────────

    tools = [
        ("read",  "/reports/q3_2025.pdf",      "User requested Q3 summary"),
        ("list",  "/reports/",                  "Listing available reports"),
        ("read",  "/reports/annual_2025.pdf",   "Annual review requested"),
    ]
    for action, resource, justification in tools:
        result = gate.authorize(action, resource, justification)
        show_result(result, f"{action} {resource}")


# ── Demo 2: Drifting agent using decorator ────────────────────────────────────

def demo_drifting_agent():
    console.rule("[bold red]DEMO 2 — Purpose Drift (SDK decorator)[/bold red]")
    console.print("Same developer registers a 'summarizer' but the bot starts deleting files.\n")
    console.print("[dim]The @gate.guard decorator intercepts every call automatically.[/dim]\n")

    gate = AgentGate(AGENTGATE_URL, raise_on_deny=True, raise_on_escalate=False)
    gate.register("sdk_drift_002", "SummarizerPro", "Read and summarize PDF documents",
                  ["/reports/*", "/confidential/*"], ["read", "write", "delete"])

    # Decorator wraps the tool — developer wrote zero extra auth code
    @gate.guard("read", resource_arg="path")
    def read_file(path: str) -> str:
        return f"<contents of {path}>"

    @gate.guard("write", resource_arg="path")
    def write_file(path: str, data: str) -> None:
        pass

    @gate.guard("delete", resource_arg="path")
    def delete_file(path: str) -> None:
        pass

    calls = [
        (read_file,   "/reports/q4_2025.pdf",        {}),
        (read_file,   "/reports/annual_2025.pdf",     {}),
        (write_file,  "/confidential/salary.xlsx",    {"data": "injected payload"}),
        (delete_file, "/confidential/hr_records.csv", {}),
    ]

    for fn, path, extra in calls:
        try:
            fn(path=path, **extra)
            console.print(f"  [green]PERMITTED[/green] [dim]{fn.__name__}({path})[/dim]")
        except AgentGateDenied as e:
            console.print(f"  [red]BLOCKED[/red]   [dim]{fn.__name__}({path})[/dim]")
            console.print(f"  [italic dim]  -> {e.explanation}[/italic dim]")
        except AgentGateEscalated as e:
            console.print(f"  [yellow]ESCALATED[/yellow] [dim]{fn.__name__}({path})[/dim]")
            console.print(f"  [italic dim]  -> {e.explanation}[/italic dim]")


# ── Demo 3: Context manager ───────────────────────────────────────────────────

def demo_context_manager():
    console.rule("[bold cyan]DEMO 3 — Context Manager (SDK)[/bold cyan]")
    console.print("Using gate.operation() as a context manager — cleaner for one-off actions.\n")

    gate = AgentGate(AGENTGATE_URL, raise_on_deny=True)
    gate.register("sdk_ctx_003", "FileCleanup", "Archive old report files",
                  ["/reports/archive/*"], ["read", "delete"])

    ops = [
        ("delete", "/reports/archive/q1_2024.pdf", "Archiving old report"),
        ("delete", "/confidential/salary.xlsx",     "Cleanup task"),         # should be blocked
    ]

    for action, resource, reason in ops:
        try:
            with gate.operation(action, resource, reason):
                console.print(f"  [green]EXECUTING[/green]  {action} {resource}")
        except AgentGateDenied as e:
            console.print(f"  [red]BLOCKED[/red]    {action} {resource}")
            console.print(f"  [italic dim]  -> {e.explanation}[/italic dim]")


# ── Demo 4: Unregistered agent caught immediately ─────────────────────────────

def demo_unregistered():
    console.rule("[bold red]DEMO 4 — Unregistered Agent[/bold red]")
    console.print("An agent tries to call authorize() without registering first.\n")

    gate = AgentGate(AGENTGATE_URL)
    # No register() call — gate.authorize() should raise immediately

    try:
        gate.authorize("read", "/confidential/salary.xlsx", "I just need this one file")
        console.print("  [red]BUG: this should not have been permitted[/red]")
    except AgentGateNotRegistered as e:
        console.print(f"  [green]CAUGHT LOCALLY[/green]  AgentGateNotRegistered raised before any HTTP call")
        console.print(f"  [italic dim]  -> {e}[/italic dim]")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    console.print(Panel.fit(
        "[bold cyan]AgentGate SDK — Integration Demo[/bold cyan]\n"
        "[dim]Shows how any developer adds trust authorization in 3 lines[/dim]",
        border_style="cyan",
    ))
    console.print()

    demo_legit_agent()
    console.print()
    demo_drifting_agent()
    console.print()
    demo_context_manager()
    console.print()
    demo_unregistered()

    console.print()
    console.print("[bold green]SDK demo complete.[/bold green] "
                  "Every call above went through the live AgentGate server.")
