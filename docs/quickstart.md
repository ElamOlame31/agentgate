# AgentGate — 5-Minute Integration Guide

You don't need to run anything. AgentGate is already running.
Just install the SDK and point your agent at it.

---

## Step 1 — Install the SDK

```bash
pip install agentgate-pdp
```

---

## Step 2 — Connect to AgentGate

```python
from agentgate import AgentGate

gate = AgentGate(
    url="https://YOUR_URL_HERE",   # provided by AgentGate team
    api_key="YOUR_KEY_HERE",       # provided by AgentGate team
)
```

---

## Step 3 — Register your agent

Tell AgentGate what your agent is, what it's supposed to do,
and what it's allowed to access.

```python
gate.register(
    agent_id="my_agent",                         # unique ID for your agent
    name="My Document Bot",                      # human-readable name
    declared_purpose="Summarize PDF reports",    # what this agent is for
    authorized_resources=["/documents/*"],       # what it's allowed to access
    authorized_actions=["read", "search"],       # what it's allowed to do
)
```

---

## Step 4 — Authorize before every tool call

Add one line before any action your agent takes.

```python
# Before reading a file
gate.authorize("read", "/documents/q3_report.pdf")

# Before writing
gate.authorize("write", "/documents/output.pdf")

# Before deleting
gate.authorize("delete", "/documents/old_report.pdf")
```

If the action is allowed → execution continues normally.
If not → `AgentGateDenied` is raised before the tool runs.

---

## Step 5 — Handle the decision

```python
from agentgate.exceptions import AgentGateDenied

try:
    gate.authorize("read", "/documents/q3_report.pdf")
    result = read_file("/documents/q3_report.pdf")   # only runs if PERMITTED
except AgentGateDenied as e:
    print(f"Blocked: {e}")   # action never executed
```

---

## Full example — LangChain agent

```python
from agentgate import AgentGate
from agentgate.exceptions import AgentGateDenied
from langchain_core.tools import tool

gate = AgentGate("https://YOUR_URL_HERE", api_key="YOUR_KEY_HERE")
gate.register(
    agent_id="report_bot",
    name="ReportBot",
    declared_purpose="Read and summarize quarterly business reports",
    authorized_resources=["/reports/*"],
    authorized_actions=["read"],
)

@tool
def read_document(path: str) -> str:
    """Read a document from the file system."""
    try:
        gate.authorize("read", path)
    except AgentGateDenied as e:
        return f"Access denied: {e}"
    with open(path) as f:
        return f.read()
```

---

## Full example — async agent (LangGraph, CrewAI, Autogen)

```python
from agentgate import AsyncAgentGate
from agentgate.exceptions import AgentGateDenied

gate = AsyncAgentGate("https://YOUR_URL_HERE", api_key="YOUR_KEY_HERE")

await gate.register(
    agent_id="report_bot",
    name="ReportBot",
    declared_purpose="Read and summarize quarterly business reports",
    authorized_resources=["/reports/*"],
    authorized_actions=["read"],
)

@gate.guard("read", resource_arg="path")
async def read_document(path: str) -> str:
    with open(path) as f:
        return f.read()
# AgentGate checks authorization automatically before the function runs
```

---

## What you'll see

Every request your agent makes shows up on the AgentGate dashboard in real time:

- **Trust score** — how much AgentGate trusts this specific request (0-100)
- **Decision** — PERMIT, ESCALATE, or DENY
- **Explanation** — why the decision was made
- **Attack flags** — if anything suspicious was detected

Dashboard: `https://YOUR_URL_HERE` (same URL, open in browser)

---

## What AgentGate catches automatically

| Situation | What happens |
|-----------|-------------|
| Agent reads a file outside its declared scope | `DENY — RESOURCE_OUT_OF_SCOPE` |
| Agent performs an action it wasn't registered for | `DENY — UNAUTHORIZED_ACTION` |
| Agent makes 50+ requests in 60 seconds | `DENY — CRITICAL_VELOCITY` |
| Document contains "ignore your previous instructions" | Content blocked before agent processes it |

---

## Questions?

Contact: olame109@gmail.com
