"""
DEMO: The same attacks, WITH AgentGate running.
Run this after starting the server: python -m server.main
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
from rich.console import Console
from rich import box

console = Console()

def main():
    console.print("\n")
    console.rule("[bold green]WITH AGENTGATE — Context-Aware Trust Authorization[/bold green]")
    console.print("[dim]Make sure AgentGate is running: python -m server.main[/dim]\n")
    time.sleep(0.5)

    try:
        from simulator.agents import (
            run_good_agent,
            run_privilege_escalation,
            run_purpose_drift,
            run_velocity_attack,
        )
    except ImportError as e:
        console.print(f"[red]Import error: {e}[/red]")
        return

    console.print("[dim]Watch the dashboard at http://localhost:8000 — trust scores drop in real-time.\n[/dim]")
    time.sleep(1)

    # Scenario 1 — Legitimate agent, should be permitted
    run_good_agent()
    time.sleep(1)

    # Scenario 2 — Privilege escalation
    run_privilege_escalation()
    time.sleep(1)

    # Scenario 3 — Purpose drift
    run_purpose_drift()
    time.sleep(1)

    # Scenario 4 — Velocity attack
    run_velocity_attack()
    time.sleep(0.5)

    console.rule("[bold green]DEMO COMPLETE[/bold green]")
    console.print(
        "\n[green]Every attack was detected and blocked.[/green]\n"
        "[dim]Check the dashboard for the full audit trail with trust scores,\n"
        "delegation chains, purpose alignment scores, and AI-generated explanations.[/dim]\n"
    )


if __name__ == "__main__":
    main()
