"""
DEMO: What happens WITHOUT AgentGate.
A naive resource server that uses only OAuth-style token checks.
All four attacks succeed silently.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

# Fake "secure" resource server — only checks token existence
REGISTERED_TOKENS = {
    "agent_read_001": "tok_abc123",
    "agent_manager_002": "tok_def456",
    "agent_sub_003": "tok_ghi789",
}

def naive_authorize(agent_id: str, token: str, action: str, resource: str) -> dict:
    """Current best practice: check token, that's it."""
    if agent_id in REGISTERED_TOKENS and REGISTERED_TOKENS[agent_id] == token:
        return {"decision": "PERMIT", "reason": "Valid token"}
    return {"decision": "DENY", "reason": "Invalid token"}


def print_result(decision: str, agent: str, action: str, resource: str, note: str = ""):
    color = "green" if decision == "PERMIT" else "red"
    console.print(
        f"  [{color}]{decision}[/{color}]  "
        f"[dim]{agent}[/dim]  {action.upper()} [cyan]{resource}[/cyan]"
        + (f"  [yellow]← {note}[/yellow]" if note else "")
    )


def main():
    console.print("\n")
    console.rule("[bold red]WITHOUT AGENTGATE — Naive Token-Only Auth[/bold red]")
    console.print("[dim]Every authenticated agent can do anything. Watch.[/dim]\n")

    time.sleep(0.5)

    # Attack 1: Privilege escalation
    console.print("[bold]Attack 1 — Privilege Escalation:[/bold]")
    r = naive_authorize("agent_sub_003", "tok_ghi789", "delete", "/confidential/salary.xlsx")
    print_result(r["decision"], "agent_sub_003", "delete", "/confidential/salary.xlsx", "SUB-AGENT deleting confidential salary data!")
    r = naive_authorize("agent_sub_003", "tok_ghi789", "admin", "/system/users")
    print_result(r["decision"], "agent_sub_003", "admin", "/system/users", "SUB-AGENT gaining admin on user directory!")
    time.sleep(0.5)

    # Attack 2: Purpose drift
    console.print("\n[bold]Attack 2 — Purpose Drift (read agent making destructive calls):[/bold]")
    for action, resource in [
        ("read", "/reports/q4.pdf"),
        ("write", "/confidential/salary.xlsx"),
        ("delete", "/confidential/hr_records.csv"),
        ("read", "/confidential/passwords.txt"),
    ]:
        r = naive_authorize("agent_read_001", "tok_abc123", action, resource)
        note = "DRIFT: destroying data with read-only agent!" if action in ("write","delete") else ""
        note = "CRITICAL: reading passwords!" if "password" in resource else note
        print_result(r["decision"], "agent_read_001", action, resource, note)
    time.sleep(0.5)

    # Attack 3: Velocity
    console.print("\n[bold]Attack 3 — Data Exfiltration (30 rapid requests):[/bold]")
    all_permitted = True
    for i in range(30):
        r = naive_authorize("agent_read_001", "tok_abc123", "read", f"/confidential/file_{i:03d}.xlsx")
        if r["decision"] != "PERMIT":
            all_permitted = False
    if all_permitted:
        console.print("  [red]ALL 30 PERMITTED[/red] — Entire confidential directory exfiltrated. Zero flags.")
    time.sleep(0.5)

    # Attack 4: Audit gap
    console.print("\n[bold]Attack 4 — Audit Gap:[/bold]")
    console.print("  [dim]Logs show:[/dim]")
    console.print("  [dim]  2025-01-15 02:14:33 | DELETE /confidential/salary.xlsx | status=200[/dim]")
    console.print("  [dim]  2025-01-15 02:14:34 | DELETE /confidential/hr_records.csv | status=200[/dim]")
    console.print("  [yellow]  Who did this? User? Agent? Which agent? Why? Unknown.[/yellow]")
    console.print("  [yellow]  No agent identity, no delegation chain, no purpose, no trust context.[/yellow]")

    console.print("\n")
    console.rule("[bold red]RESULT: ALL ATTACKS SUCCEEDED — ZERO DETECTION[/bold red]")
    console.print(
        "\n[dim]This is the state of the art today. Every enterprise deploying AI agents\n"
        "is running exactly this. Now run [bold]demo/protected_demo.py[/bold] to see AgentGate.[/dim]\n"
    )


if __name__ == "__main__":
    main()
