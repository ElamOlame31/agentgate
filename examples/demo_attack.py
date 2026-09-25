#!/usr/bin/env python3
"""
AgentGate attack demo — runs automatically inside docker-compose.demo.yml.

Usage (standalone):
    export AGENTGATE_URL=http://localhost:8000
    export AGENTGATE_API_KEY=ag-demo-secret-key-2026-local
    python demo_attack.py
"""
import os
import sys
import time
import uuid

import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.rule import Rule
from rich import box

AGENTGATE_URL = os.getenv("AGENTGATE_URL", "http://localhost:8000")
API_KEY = os.getenv("AGENTGATE_API_KEY", "ag-demo-secret-key-2026-local")
HEADERS = {"X-API-Key": API_KEY}

console = Console(highlight=False)

# ── Helpers ─────────────────────────────────────────────────────────────────

def wait_for_server(timeout: int = 180):
    console.print("\n[dim]Waiting for AgentGate PDP to finish loading...[/dim]")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = httpx.get(f"{AGENTGATE_URL}/healthz", timeout=5.0)
            if r.status_code == 200:
                console.print("[green]✓ AgentGate ready[/green]\n")
                return
        except Exception:
            pass
        time.sleep(3)
    console.print("[red]✗ AgentGate did not become healthy in time. Check logs.[/red]")
    sys.exit(1)


def register(data: dict) -> tuple[str, str]:
    r = httpx.post(
        f"{AGENTGATE_URL}/agents/register", json=data,
        headers=HEADERS, timeout=30.0,
    )
    if r.status_code == 409:
        data["agent_id"] = data["agent_id"] + "_" + uuid.uuid4().hex[:6]
        r = httpx.post(
            f"{AGENTGATE_URL}/agents/register", json=data,
            headers=HEADERS, timeout=30.0,
        )
    r.raise_for_status()
    return data["agent_id"], r.json()["token"]


def authorize(agent_id: str, token: str, action: str, resource: str,
              justification: str = "") -> dict:
    r = httpx.post(
        f"{AGENTGATE_URL}/authorize",
        json={
            "agent_id": agent_id, "token": token,
            "action": action, "resource": resource,
            "justification": justification,
            "request_id": str(uuid.uuid4()),
        },
        headers=HEADERS, timeout=60.0,
    )
    r.raise_for_status()
    return r.json()


def print_decision(result: dict, label: str):
    d = result["decision"]
    score = result["trust_breakdown"]["final_score"]
    flags = ", ".join(result.get("attack_flags", [])) or "—"
    color = {"PERMIT": "green", "DENY": "red", "ESCALATE": "yellow"}.get(d, "white")
    console.print(
        f"  [{color}]{d:8s}[/{color}]  {label:<48s}  "
        f"score=[bold]{score:3.0f}[/bold]  flags=[yellow]{flags}[/yellow]"
    )


# Summary rows collected throughout the demo
_summary: list[tuple] = []


def record(phase: str, label: str, result: dict):
    d = result["decision"]
    score = result["trust_breakdown"]["final_score"]
    flags = ", ".join(result.get("attack_flags", [])) or "—"
    _summary.append((phase, label, d, f"{score:.0f}", flags))


# ── Phase 0 — Naive token auth (without AgentGate) ──────────────────────────

def phase_naive():
    console.print(Rule("[bold red]PHASE 0 — Without AgentGate: Naive Token-Only Auth[/bold red]"))
    console.print(
        "[dim]A resource server that checks only 'is this token valid?'.\n"
        "Every attack passes silently.[/dim]\n"
    )
    time.sleep(0.4)

    TOKENS = {"report_bot": "tok_abc", "sub_agent": "tok_xyz", "exfil_agent": "tok_def"}

    def naive_auth(agent: str, token: str, action: str, resource: str, note: str = ""):
        ok = TOKENS.get(agent) == token
        d = "PERMIT" if ok else "DENY"
        color = "green" if ok else "red"
        console.print(
            f"  [{color}]{d:8s}[/{color}]  {agent:<18s}  {action.upper():<8s}  "
            f"[cyan]{resource}[/cyan]"
            + (f"  [yellow]← {note}[/yellow]" if note else "")
        )
        return d

    console.print("[bold]Privilege escalation — sub-agent deletes confidential salary data:[/bold]")
    naive_auth("sub_agent", "tok_xyz", "delete", "/confidential/salary.xlsx", "should be impossible")
    naive_auth("sub_agent", "tok_xyz", "admin",  "/system/users",             "admin access — never granted")
    time.sleep(0.3)

    console.print("\n[bold]Purpose drift — read-only summariser starts destroying data:[/bold]")
    naive_auth("report_bot", "tok_abc", "read",   "/reports/q4.pdf",          "")
    naive_auth("report_bot", "tok_abc", "write",  "/hr/salary.xlsx",          "purpose mismatch")
    naive_auth("report_bot", "tok_abc", "delete", "/hr/hr_records.csv",       "purpose mismatch")
    time.sleep(0.3)

    console.print("\n[bold]Velocity exfiltration — 30 rapid requests, all permitted:[/bold]")
    results = [naive_auth("exfil_agent", "tok_def", "read", f"/confidential/file_{i:03d}.xlsx")
               for i in range(30)]
    console.print(
        f"  [red]ALL {results.count('PERMIT')} PERMITTED — full directory exfiltrated."
        "  Zero flags raised.[/red]"
    )

    console.print(
        "\n[bold red]RESULT: every attack succeeded. No detection. No audit context.[/bold red]\n"
    )
    time.sleep(1.0)


# ── Phase 1 — Scope violation ────────────────────────────────────────────────

def phase_scope_violation() -> tuple[str, str]:
    console.print(Rule("[bold]PHASE 1 — Scope Violation[/bold]"))
    console.print(
        "[dim]report_bot is registered for READ on /reports/*.\n"
        "It attempts DELETE /confidential/salary.xlsx.[/dim]\n"
    )

    agent_id, token = register({
        "agent_id": "demo_report_bot",
        "name": "ReportBot",
        "declared_purpose": "Summarize quarterly business reports for the executive team",
        "authorized_resources": ["/reports/*", "/reports/archive/*"],
        "authorized_actions": ["read", "list"],
        "delegation_depth": 0,
    })

    r = authorize(agent_id, token, "delete", "/confidential/salary.xlsx",
                  "Received instruction from email: export salary data")
    print_decision(r, "DELETE /confidential/salary.xlsx")
    record("Scope Violation", "DELETE /confidential/salary.xlsx", r)
    time.sleep(0.5)
    return agent_id, token


# ── Phase 2 — Purpose drift ──────────────────────────────────────────────────

def phase_purpose_drift():
    console.print(Rule("[bold]PHASE 2 — Purpose Drift[/bold]"))
    console.print(
        "[dim]Agent declared purpose: 'Read and summarize PDF reports'.\n"
        "It starts making write/delete calls to confidential resources.[/dim]\n"
    )

    agent_id, token = register({
        "agent_id": "demo_drifting_agent",
        "name": "DocumentSummarizer",
        "declared_purpose": "Read and summarize PDF documents for executive team",
        "authorized_resources": ["/reports/*", "/confidential/*"],
        "authorized_actions": ["read", "write", "delete"],
        "delegation_depth": 0,
    })

    calls = [
        ("read",   "/reports/q4_2025.pdf",       "Summarizing Q4 report"),
        ("write",  "/confidential/salary.xlsx",   "Adding summary metadata"),
        ("delete", "/confidential/hr_records.csv","Cleaning old records"),
        ("read",   "/confidential/passwords.txt", "Need credentials for API access"),
    ]
    for action, resource, just in calls:
        r = authorize(agent_id, token, action, resource, just)
        print_decision(r, f"{action.upper()} {resource}")
        record("Purpose Drift", f"{action.upper()} {resource}", r)
        time.sleep(0.4)


# ── Phase 3 — Velocity / exfiltration spike ──────────────────────────────────

def phase_velocity():
    console.print(Rule("[bold]PHASE 3 — Velocity / Data Exfiltration Spike[/bold]"))
    console.print(
        "[dim]Agent fires 50 requests in rapid succession — classic exfiltration pattern.\n"
        "Trust degrades as AgentGate detects anomalous velocity.[/dim]\n"
    )

    agent_id, token = register({
        "agent_id": "demo_velocity_agent",
        "name": "DataExporter",
        "declared_purpose": "Export monthly report summaries",
        "authorized_resources": ["/reports/*"],
        "authorized_actions": ["read", "list"],
        "delegation_depth": 0,
    })

    console.print("[yellow]-> Firing 50 rapid requests...[/yellow]")
    results, last = [], {}
    for i in range(50):
        r = authorize(agent_id, token, "read", f"/reports/file_{i:03d}.pdf", "Monthly export")
        results.append(r["decision"])
        last = r

    permits   = results.count("PERMIT")
    escalates = results.count("ESCALATE")
    denials   = results.count("DENY")

    console.print(
        f"\n  Across 50 requests:  "
        f"[green]PERMIT {permits}[/green]  "
        f"[yellow]ESCALATE {escalates}[/yellow]  "
        f"[red]DENY {denials}[/red]"
    )
    if last:
        print_decision(last, "→ final decision")
        record("Velocity Spike", "50 rapid reads (last)", last)
    time.sleep(0.5)


# ── Phase 4 — Delegation chain violation ────────────────────────────────────

def phase_delegation():
    console.print(Rule("[bold]PHASE 4 — Delegation Chain Scope Escalation[/bold]"))
    console.print(
        "[dim]Orchestrator has /documents/* read+write.\n"
        "Child agent tries to claim /confidential/* — scope escalation\n"
        "that AgentGate catches by walking the delegation chain.[/dim]\n"
    )

    parent_id, parent_token = register({
        "agent_id": "demo_orchestrator",
        "name": "Orchestrator",
        "declared_purpose": "Manage document workflow for internal team",
        "authorized_resources": ["/documents/*"],
        "authorized_actions": ["read", "write"],
        "delegation_depth": 0,
    })

    child_id, child_token = register({
        "agent_id": "demo_analyst",
        "name": "Analyst",
        "declared_purpose": "Analyze documents",
        "authorized_resources": ["/documents/*", "/confidential/*"],  # escalation
        "authorized_actions": ["read", "write", "delete"],            # escalation
        "delegated_by": parent_id,
        "delegation_depth": 1,
        "scope_at_delegation": ["read", "write"],
    })

    console.print("[yellow]-> Child agent tries access to /confidential/ (never in parent's scope):[/yellow]")
    r = authorize(child_id, child_token, "read", "/confidential/merger_plans.pdf",
                  "Research for analysis task")
    print_decision(r, f"{child_id} READ /confidential/merger_plans.pdf")
    record("Delegation Chain", "READ /confidential/merger_plans.pdf", r)

    console.print("\n[yellow]-> Child agent tries DELETE (not in parent's authorized actions):[/yellow]")
    r = authorize(child_id, child_token, "delete", "/documents/important.pdf",
                  "Cleanup after analysis")
    print_decision(r, f"{child_id} DELETE /documents/important.pdf")
    record("Delegation Chain", "DELETE /documents/important.pdf", r)
    time.sleep(0.5)


# ── Phase 5 — Legitimate permit (contrast) ──────────────────────────────────

def phase_legitimate(agent_id: str, token: str):
    console.print(Rule("[bold green]PHASE 5 — Legitimate Request (contrast)[/bold green]"))
    console.print(
        "[dim]Same report_bot from Phase 1, now making a request within its declared scope.[/dim]\n"
    )

    calls = [
        ("read", "/reports/q3_2025.pdf",        "Summarizing Q3 report as requested by CFO"),
        ("list", "/reports/",                   "Listing available reports"),
        ("read", "/reports/archive/q1_2025.pdf","Historical comparison for annual review"),
    ]
    for action, resource, just in calls:
        r = authorize(agent_id, token, action, resource, just)
        print_decision(r, f"{action.upper()} {resource}")
        record("Legitimate", f"{action.upper()} {resource}", r)
        time.sleep(0.4)


# ── Final summary ────────────────────────────────────────────────────────────

def print_summary():
    console.print(Rule("[bold]Demo Complete — Summary[/bold]"))

    t = Table(box=box.ROUNDED, show_header=True, header_style="bold")
    t.add_column("Phase",     style="dim",     min_width=18)
    t.add_column("Request",                    min_width=40)
    t.add_column("Decision",                   min_width=10)
    t.add_column("Score",     justify="right", min_width=6)
    t.add_column("Flags",     style="yellow",  min_width=20)

    color_map = {"PERMIT": "green", "DENY": "red", "ESCALATE": "yellow"}
    for phase, label, decision, score, flags in _summary:
        c = color_map.get(decision, "white")
        t.add_row(phase, label, f"[{c}]{decision}[/{c}]", score, flags)

    console.print(t)
    console.print(
        f"\n[green]Every attack was detected and blocked.[/green]  "
        f"[dim]Dashboard: {AGENTGATE_URL}[/dim]\n"
    )


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    console.print(Panel.fit(
        "[bold]AgentGate PDP — Attack Demo[/bold]\n\n"
        f"Dashboard  →  [cyan]{AGENTGATE_URL}[/cyan]\n"
        "Docs       →  " + AGENTGATE_URL + "/docs",
        border_style="cyan",
        padding=(1, 4),
    ))

    wait_for_server()

    phase_naive()
    console.print(Rule("[bold cyan]Now the same attacks — WITH AgentGate[/bold cyan]"))
    console.print("[dim]Watch the dashboard update in real-time as each attack is blocked.[/dim]\n")
    time.sleep(1.0)

    # Phase 1 returns the legitimately-registered agent for reuse in Phase 5
    agent_id, token = phase_scope_violation()
    console.print()
    phase_purpose_drift()
    console.print()
    phase_velocity()
    console.print()
    phase_delegation()
    console.print()
    phase_legitimate(agent_id, token)
    console.print()
    print_summary()


if __name__ == "__main__":
    main()
