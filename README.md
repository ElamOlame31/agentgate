# AgentGate

**Your AI agents can escalate privileges, drift from their purpose, and exfiltrate data. OAuth has no idea.**

[![PyPI version](https://img.shields.io/pypi/v/agentgate-pdp.svg)](https://pypi.org/project/agentgate-pdp/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

AgentGate is a **Policy Decision Point (PDP)** that sits between your AI agents and their tools. Before any action executes — reading a file, calling an API, writing to a database — AgentGate evaluates it against identity, scope, declared purpose, and real-time behavior. The answer comes back in milliseconds: `PERMIT`, `ESCALATE`, or `DENY`.

## The problem

Current authorization was built for humans logging in, not agents acting autonomously in chains. An agent with a valid token can:

- Read files far outside its declared scope
- Be delegated more permissions than its parent ever had
- Slowly exfiltrate data below rate-limit thresholds
- Be hijacked mid-task via a prompt injection in a document it's processing

OAuth 2.1 and RBAC check *who you are*, not *what you're doing or why*.

## What AgentGate checks

```
Agent: DELETE /confidential/salary.xlsx   justification: "user asked me to clean up"
                          ↓
              ┌─────────────────────────┐
              │  AgentGate PDP          │
              │                         │
              │  Identity        ✓      │
              │  Scope           ✗      │  /confidential/* not in authorized resources
              │  Purpose align   ✗      │  "clean up" ≠ "summarize quarterly reports"
              │  Behavioral      ✗      │  40 requests in 60s — velocity spike
              │                         │
              │  Trust score:  12/100   │
              │  Decision:     DENY     │
              └─────────────────────────┘
                          ↓
                  Action never executes.
                  Audit log entry created.
                  Dashboard alert fired.
```

Trust is scored across 4 dimensions: **identity** (25%), **delegation chain** (25%), **purpose alignment via embeddings** (30%), **behavioral velocity** (20%).

## Install

```bash
pip install agentgate-pdp
```

## Quickstart — 3 lines

```python
from agentgate import AgentGate

gate = AgentGate("http://localhost:8000", api_key="your-key")
gate.register("report_bot", "ReportBot", "Summarize quarterly reports",
              authorized_resources=["/reports/*"], authorized_actions=["read"])

result = gate.authorize("read", "/reports/q3.pdf")
# {"decision": "PERMIT", "trust_score": 87, "trust_breakdown": {...}, "explanation": "..."}

result = gate.authorize("delete", "/confidential/salary.xlsx")
# raises AgentGateDenied — action never runs
```

## Async — LangGraph, CrewAI, Autogen

```python
from agentgate import AsyncAgentGate

gate = AsyncAgentGate("http://localhost:8000", api_key="your-key")
await gate.register("report_bot", "ReportBot", "Summarize quarterly reports",
                    authorized_resources=["/reports/*"], authorized_actions=["read"])

result = await gate.authorize("read", "/reports/q3.pdf")

# Decorator — authorizes before the tool runs
@gate.guard("read", resource_arg="path")
async def read_document(path: str) -> str:
    return open(path).read()

# Context manager
async with gate.operation("write", "/reports/output.pdf"):
    await write_report(data)
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

| Attack | What happens |
|--------|-------------|
| Agent reads `/confidential/salary.xlsx` (out of scope) | `DENY — RESOURCE_OUT_OF_SCOPE` |
| Agent calls `delete` (not in authorized actions) | `DENY — UNAUTHORIZED_ACTION` |
| Child agent claims more scope than parent granted | `DENY — CHAIN_SCOPE_VIOLATION` |
| Agent fires 80 requests/min (data exfiltration) | `DENY — CRITICAL_VELOCITY` |
| Document says "ignore your previous instructions" | Blocked before agent ever reads it |
| Unknown agent attempts access | `DENY — UNREGISTERED_AGENT` |

## Multi-agent delegation

AgentGate enforces scope attenuation across the entire delegation chain. A child agent can never exceed what its parent was authorized to do — checked at both registration and authorization time.

```python
# Parent registers with full scope
gate.register("orchestrator", "Orchestrator", "Manage document workflow",
              authorized_resources=["/documents/*"], authorized_actions=["read", "write"])

# Analyst gets a subset — enforced at delegation time
httpx.post(f"{url}/agents/delegate", json={
    "parent_agent_id": "orchestrator",
    "parent_token": orchestrator_token,
    "child_agent_id": "analyst",
    "child_resources": ["/documents/public/*"],
    "child_actions": ["read"],
})

# Analyst tries /confidential/ — blocked
# {"decision": "DENY", "attack_flags": ["CHAIN_SCOPE_VIOLATION"]}
```

## Human-in-the-loop

```python
gate.register(..., requires_human_approval=True)

# On ESCALATE, the agent pauses. Human approves or denies from the dashboard.
# The SDK polls automatically and unblocks when a decision is made.
result = gate.authorize("read", "/confidential/merger_details.pdf")
# Blocks here until human responds — auto-denies after 90s
```

## Natural language policies

```python
httpx.post(f"{url}/policies", json={"rule": "Agents must never delete files"})
httpx.post(f"{url}/policies", json={"rule": "No agent should read salary data outside business hours"})
httpx.post(f"{url}/policies", json={"rule": "Flag any access to /hr folder"})
```

Plain English rules are parsed by Claude and enforced as hard blocks — they run before trust scoring, so a matching DENY is always final.

## Run the server

```bash
git clone https://github.com/ElamOlame31/agentgate
cd agentgate
pip install -r requirements.txt
python run.py
# Dashboard at http://localhost:8000
```

Docker coming soon.

## See the attacks in action

```bash
# Terminal 1 — start the server
python run.py

# Terminal 2 — run the attack demo
python demo/attack_demo.py     # unprotected: all attacks succeed
python demo/protected_demo.py  # with AgentGate: all attacks blocked
```

Watch the dashboard at `http://localhost:8000` as trust scores drop in real time.

## Architecture

```
Your Agent (LangGraph / CrewAI / Autogen / custom)
    │
    │  pip install agentgate-pdp
    ▼
AgentGate SDK  ──────── POST /authorize ─────────►  AgentGate PDP Server
                                                         │
                                                    ┌────┴──────────────────┐
                                                    │ Policy Engine          │
                                                    │ (NL rules, hard block) │
                                                    ├───────────────────────┤
                                                    │ Trust Scoring          │
                                                    │  · Identity (25%)      │
                                                    │  · Delegation (25%)    │
                                                    │  · Purpose (30%)       │
                                                    │  · Behavioral (20%)    │
                                                    ├───────────────────────┤
                                                    │ HITL Approval          │
                                                    ├───────────────────────┤
                                                    │ Audit Log (PDF / CSV)  │
                                                    └────────────────────────┘
                                                         │
                                                 PERMIT / ESCALATE / DENY
                                                         │
                                                 Tool executes (or doesn't)
```

## Configuration

```env
AGENTGATE_API_KEY=your-secret-key
ANTHROPIC_API_KEY=sk-ant-...            # NL policy parsing + purpose scoring
AGENTGATE_ALERT_TOPIC=your-ntfy-topic   # push alerts via ntfy.sh
AGENTGATE_PORT=8000
```

## Why not just use OPA / OpenFGA / standard RBAC?

Those tools are great at enforcing *static* rules: "can user X access resource Y?"

AgentGate handles what they can't:
- **Dynamic purpose** — was this action actually aligned with what the agent said it would do?
- **Delegation chain integrity** — did each hop in a multi-agent chain stay within scope?
- **Behavioral context** — is this agent acting like itself, or has something changed?
- **Prompt injection** — is the content this agent is about to process trying to hijack it?

## License

MIT — see [LICENSE](LICENSE).
