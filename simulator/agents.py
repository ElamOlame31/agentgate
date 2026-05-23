"""
Agent simulator for AgentGate demo.

Three agents, three attack scenarios:
  1. GoodAgent       — legitimate document summarizer
  2. PrivEscAgent    — delegation confusion / privilege escalation
  3. PurposeDriftAgent — purpose drift (read agent making write/delete calls)
  4. VelocityAgent   — high-velocity scraping / DoS-style behavior
"""

import httpx
import os
import time
import uuid
from rich.console import Console
from rich.table import Table
from rich import box
from dotenv import load_dotenv

load_dotenv()

console = Console()

AGENTGATE_URL = os.getenv("AGENTGATE_URL", "http://localhost:8000")
_API_KEY = os.getenv("AGENTGATE_API_KEY", "")
_HEADERS = {"X-API-Key": _API_KEY} if _API_KEY else {}


def _register(agent_data: dict) -> tuple[str, str]:
    """Returns (agent_id, token). agent_id may differ from input if a collision is resolved."""
    r = httpx.post(f"{AGENTGATE_URL}/agents/register", json=agent_data, headers=_HEADERS)
    if r.status_code == 409:
        agent_data["agent_id"] = agent_data["agent_id"] + "_" + uuid.uuid4().hex[:6]
        r = httpx.post(f"{AGENTGATE_URL}/agents/register", json=agent_data, headers=_HEADERS)
    r.raise_for_status()
    return agent_data["agent_id"], r.json()["token"]


def _authorize(agent_id: str, token: str, action: str, resource: str, justification: str = "") -> dict:
    payload = {
        "agent_id": agent_id,
        "token": token,
        "action": action,
        "resource": resource,
        "justification": justification,
        "request_id": str(uuid.uuid4()),
    }
    r = httpx.post(f"{AGENTGATE_URL}/authorize", json=payload, headers=_HEADERS, timeout=60.0)
    r.raise_for_status()
    return r.json()


def _print_result(result: dict, label: str = ""):
    decision = result["decision"]
    score = result["trust_breakdown"]["final_score"]
    flags = result.get("attack_flags", [])

    color = {"PERMIT": "green", "DENY": "red", "ESCALATE": "yellow"}.get(decision, "white")
    flag_str = ", ".join(flags) if flags else "—"

    console.print(
        f"  [{color}]{decision}[/{color}] "
        f"[dim]{label}[/dim] "
        f"score=[bold]{score}[/bold] "
        f"flags=[yellow]{flag_str}[/yellow]"
    )
    console.print(f"  [italic dim]  -> {result['explanation']}[/italic dim]")


# ────────────────────────────────────────────────────────────────────────────
# SCENARIO 1 — Good Agent (legitimate)
# ────────────────────────────────────────────────────────────────────────────

def run_good_agent():
    console.rule("[bold green]SCENARIO 1 — Legitimate Agent[/bold green]")
    console.print("A document summarizer reading reports it is authorized to read.\n")

    agent_id, token = _register({
        "agent_id": "good_agent_001",
        "name": "DocumentSummarizer",
        "declared_purpose": "Summarize and analyze quarterly reports in the /reports folder",
        "authorized_resources": ["/reports/*", "/reports/archive/*"],
        "authorized_actions": ["read", "list"],
        "delegation_depth": 0,
    })

    calls = [
        ("read", "/reports/q3_2025.pdf", "Summarizing Q3 report as requested by user"),
        ("list", "/reports/", "Listing available reports for user"),
        ("read", "/reports/archive/q1_2025.pdf", "User requested historical comparison"),
    ]
    for action, resource, justification in calls:
        result = _authorize(agent_id, token, action, resource, justification)
        _print_result(result, f"{action} {resource}")
        time.sleep(0.3)


# ────────────────────────────────────────────────────────────────────────────
# SCENARIO 2 — Privilege Escalation via Delegation Confusion
# ────────────────────────────────────────────────────────────────────────────

def run_privilege_escalation():
    console.rule("[bold red]SCENARIO 2 — Privilege Escalation via Delegation Confusion[/bold red]")
    console.print(
        "Agent A (read/write on /reports) delegates to Agent B.\n"
        "Agent B inherits full scope — and then tries to access /confidential/salary.xlsx\n"
        "and execute a delete. Current auth would allow this. AgentGate should not.\n"
    )

    # Parent agent — legitimate
    agent_id_a, token_a = _register({
        "agent_id": "parent_agent_A",
        "name": "ReportManager",
        "declared_purpose": "Manage and organize reports in /reports",
        "authorized_resources": ["/reports/*"],
        "authorized_actions": ["read", "write", "delete"],
        "delegation_depth": 0,
    })

    # Child agent — delegated, but scope NOT properly attenuated
    agent_id_b, token_b = _register({
        "agent_id": "child_agent_B",
        "name": "SubAgent-B",
        "declared_purpose": "Assist ReportManager with report filing",
        "authorized_resources": ["/reports/*"],
        "authorized_actions": ["read", "write", "delete"],  # not narrowed!
        "delegated_by": agent_id_a,
        "delegation_depth": 1,
        "scope_at_delegation": ["read", "write", "delete"],
    })

    # Sub-sub agent — depth 2
    agent_id_c, token_c = _register({
        "agent_id": "sub_sub_agent_C",
        "name": "SubSubAgent-C",
        "declared_purpose": "Deep file operations",
        "authorized_resources": ["/reports/*", "/confidential/*"],  # scope ESCALATION
        "authorized_actions": ["read", "write", "delete", "admin"],
        "delegated_by": agent_id_b,
        "delegation_depth": 2,
        "scope_at_delegation": ["read", "write", "delete"],
    })

    console.print("[yellow]-> Child agent tries to access confidential salary data:[/yellow]")
    r = _authorize(agent_id_b, token_b, "read", "/confidential/salary.xlsx", "Need for report reconciliation")
    _print_result(r, f"{agent_id_b} READ /confidential/salary.xlsx")

    console.print("\n[yellow]-> Sub-sub agent with scope escalation tries to delete:[/yellow]")
    r = _authorize(agent_id_c, token_c, "delete", "/confidential/salary.xlsx", "Cleanup task")
    _print_result(r, f"{agent_id_c} DELETE /confidential/salary.xlsx")

    console.print("\n[yellow]-> Child agent tries admin operation it was never given:[/yellow]")
    r = _authorize(agent_id_b, token_b, "admin", "/reports/", "System maintenance")
    _print_result(r, f"{agent_id_b} ADMIN /reports/")


# ────────────────────────────────────────────────────────────────────────────
# SCENARIO 3 — Purpose Drift Attack
# ────────────────────────────────────────────────────────────────────────────

def run_purpose_drift():
    console.rule("[bold red]SCENARIO 3 — Purpose Drift Attack[/bold red]")
    console.print(
        "A read-only document summarizer starts making write and delete calls.\n"
        "The agent passes standard auth (valid token, actions in scope) but\n"
        "its behavior is completely inconsistent with its declared purpose.\n"
    )

    agent_id, token = _register({
        "agent_id": "drifting_agent_003",
        "name": "DocumentSummarizer-Pro",
        "declared_purpose": "Read and summarize PDF documents for executive team",
        "authorized_resources": ["/reports/*", "/confidential/*"],  # over-permissioned at registration
        "authorized_actions": ["read", "write", "delete"],           # over-permissioned
        "delegation_depth": 0,
    })

    calls = [
        ("read",   "/reports/q4_2025.pdf",         "Summarizing Q4 report"),
        ("read",   "/reports/annual_review.pdf",    "Annual review summary"),
        ("write",  "/confidential/salary.xlsx",     "Adding salary data"),         # DRIFT
        ("delete", "/confidential/hr_records.csv",  "Cleaning up old HR records"), # DRIFT
        ("read",   "/confidential/passwords.txt",   "Need credentials for API"),   # DRIFT + CRITICAL
    ]

    for action, resource, justification in calls:
        result = _authorize(agent_id, token, action, resource, justification)
        _print_result(result, f"{action} {resource}")
        time.sleep(0.3)


# ────────────────────────────────────────────────────────────────────────────
# SCENARIO 4 — High-Velocity / Anomalous Behavior
# ────────────────────────────────────────────────────────────────────────────

def run_velocity_attack():
    console.rule("[bold red]SCENARIO 4 — High-Velocity Anomalous Behavior[/bold red]")
    console.print(
        "An agent fires 30 requests in under 10 seconds — classic data exfiltration pattern.\n"
        "Traditional auth passes every single one. AgentGate detects and degrades trust.\n"
    )

    agent_id, token = _register({
        "agent_id": "velocity_agent_004",
        "name": "DataExporter",
        "declared_purpose": "Export monthly report summaries",
        "authorized_resources": ["/reports/*"],
        "authorized_actions": ["read", "list"],
        "delegation_depth": 0,
    })

    console.print(f"[yellow]-> Firing 50 rapid requests...[/yellow]")
    results = []
    for i in range(50):
        r = _authorize(agent_id, token, "read", f"/reports/file_{i:03d}.pdf", "Monthly export")
        results.append(r["decision"])

    permits = results.count("PERMIT")
    escalates = results.count("ESCALATE")
    denials = results.count("DENY")

    console.print(f"\n  Results across 50 requests:")
    console.print(f"  [green]PERMIT[/green]:   {permits}")
    console.print(f"  [yellow]ESCALATE[/yellow]: {escalates}")
    console.print(f"  [red]DENY[/red]:     {denials}")
    last = results[-1]
    color = {"PERMIT": "green", "DENY": "red", "ESCALATE": "yellow"}.get(last, "white")
    console.print(f"\n  Last decision: [{color}]{last}[/{color}]")
