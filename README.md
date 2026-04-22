# AgentGate

**A Policy Decision Point (PDP) for AI agents. Every action evaluated before it executes.**

[![PyPI version](https://img.shields.io/pypi/v/agentgate.svg)](https://pypi.org/project/agentgate/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

AI agents make decisions autonomously. AgentGate makes sure those decisions are **authorized**.

It sits between your agent and its tools. Before any action runs — reading a file, calling an API, writing to a database — AgentGate checks it against identity, scope, purpose, and behavioral context. The response is `PERMIT`, `ESCALATE`, or `DENY` in milliseconds.

```
Agent wants to delete /confidential/salary.xlsx
                    ↓
           AgentGate PDP
    ┌──────────────────────────────┐
    │  Identity check    ✓         │
    │  Scope check       ✗ (!)     │
    │  Purpose alignment ✗         │
    │  Behavioral check  ✓         │
    │                              │
    │  Trust score: 18/100         │
    │  Decision: DENY              │
    └──────────────────────────────┘
                    ↓
         Action never executes
```

## Install

```bash
pip install agentgate-pdp
```

## Quickstart (3 lines)

```python
from agentgate import AgentGate

gate = AgentGate("http://localhost:8000", api_key="your-key")
gate.register("my_agent", "ReportBot", "Summarize quarterly reports",
              authorized_resources=["/reports/*"], authorized_actions=["read"])

result = gate.authorize("read", "/reports/q3.pdf")
# {"decision": "PERMIT", "trust_breakdown": {...}, "explanation": "..."}
```

## LangChain — drop-in enforcement

```bash
pip install agentgate-pdp[langchain]
```

```python
from agentgate.langchain import AgentGateToolkit

toolkit = AgentGateToolkit(
    agentgate_url="http://localhost:8000",
    api_key="your-key",
    agent_id="report_agent",
    name="ReportBot",
    declared_purpose="Summarize quarterly business reports",
    authorized_resources=["/reports/*"],
    authorized_actions=["read"],
    processes_external_content=True,   # enables prompt injection scanning
)

safe_tools = toolkit.wrap([read_document, list_documents, send_email])
agent = create_react_agent(llm, safe_tools)
# Every tool call now goes through AgentGate before executing
```

## What gets caught

| Threat | How AgentGate stops it |
|--------|------------------------|
| Agent reads `/confidential/salary.xlsx` (out of scope) | DENY — `RESOURCE_OUT_OF_SCOPE` |
| Agent tries `delete` (not in authorized actions) | DENY — `UNAUTHORIZED_ACTION` |
| Child agent exceeds parent's delegation scope | DENY — `CHAIN_SCOPE_VIOLATION` |
| Agent makes 80 requests/min (velocity attack) | DENY — `CRITICAL_VELOCITY` |
| Document contains "ignore previous instructions" | Content blocked before agent sees it |
| Unknown agent attempts access | DENY — `UNREGISTERED_AGENT` |

## Multi-agent delegation enforcement

AgentGate validates the full delegation chain. A child agent cannot exceed its parent's scope — enforced at both registration and authorization time.

```python
# Orchestrator registers with full scope
gate.register("orchestrator", "Orchestrator", "Manage document workflow",
              authorized_resources=["/documents/*"], authorized_actions=["read", "write"])

# Analyst is delegated a subset — enforced at registration
resp = httpx.post(f"{url}/agents/delegate", json={
    "parent_agent_id": "orchestrator",
    "parent_token": orchestrator_token,
    "child_agent_id": "analyst",
    "child_resources": ["/documents/public/*"],   # subset of parent
    "child_actions": ["read"],                    # subset of parent
})

# Analyst tries to access /confidential/ — blocked at authorization time
# {"decision": "DENY", "attack_flags": ["CHAIN_SCOPE_VIOLATION"]}
```

## Natural language policies

Write security rules in plain English. AgentGate converts them to enforced policies using Claude.

```python
import httpx

# These become hard rules checked before any trust scoring
httpx.post(f"{url}/policies", json={"rule": "Agents must never delete files"})
httpx.post(f"{url}/policies", json={"rule": "No agent should read salary data outside business hours"})
httpx.post(f"{url}/policies", json={"rule": "Flag any access to /hr folder"})
```

The policy engine runs **before** the trust score — a matching DENY policy is always a hard block regardless of score.

## Human-in-the-loop approval

Mark an agent as requiring human approval for escalated decisions:

```python
gate.register(..., requires_human_approval=True)

result = gate.authorize("read", "/confidential/merger_details.pdf")
if result["decision"] == "PENDING":
    # Agent is paused — human approves or denies via dashboard
    # Wrapper polls automatically; auto-denies after 90 seconds
    request_id = result["request_id"]
```

## Prompt injection detection

```python
# Register as processing external content
gate.register(..., processes_external_content=True)

# Scan before passing content to the agent
scan = gate.scan(document_content)
if scan["level"] == "injection":
    raise ValueError(f"Injection blocked: {scan['evidence']}")
```

## Context manager and decorator

```python
# Decorator
@gate.guard("read", resource_arg="path")
def read_document(path: str) -> str:
    return open(path).read()

# Context manager
with gate.operation("write", "/reports/output.pdf"):
    write_report(data)
```

## Run the server

```bash
# Docker (recommended)
docker compose up

# Or directly
pip install agentgate[server]
python -m agentgate.server
```

Dashboard at `http://localhost:8000` — live feed of every decision, trust scores, delegation tree, policy editor, and compliance report export.

## Architecture

```
Your Agent
    |
AgentGate SDK (pip install agentgate)
    |  POST /authorize
    v
AgentGate PDP Server
    ├── Policy Engine     (NL rules → hard blocks, checked first)
    ├── Trust Scoring     (identity + delegation + purpose + behavioral)
    │     ├── Identity    (token, authorized actions, resource scope)
    │     ├── Delegation  (chain depth, scope attenuation, trust decay)
    │     ├── Purpose     (semantic alignment of request to declared purpose)
    │     └── Behavioral  (per-agent baseline anomaly detection)
    ├── HITL Approval     (ESCALATE → human decision → APPROVED/DENIED)
    └── Audit Log         (every decision, exportable as PDF/CSV)
    |
PERMIT / ESCALATE / DENY / PENDING
    |
Tool executes (or doesn't)
```

## Configuration

Environment variables (`.env`):

```
AGENTGATE_API_KEY=your-secret-key
ANTHROPIC_API_KEY=sk-ant-...         # for NL policy parsing + purpose scoring
AGENTGATE_ALERT_TOPIC=your-ntfy-topic  # for push alerts (ntfy.sh)
AGENTGATE_PORT=8000
```

## License

MIT — see [LICENSE](LICENSE).

---

Built at University of Ottawa · ELG5901 · 2026
