# AgentGate

**Context-aware trust authorization for agentic AI systems.**

AgentGate is a Policy Decision Point (PDP) that sits between your AI agents and their tools. Every action is evaluated before it executes — no more agents reading secrets, deleting files, or getting hijacked by malicious documents.

## Install

```bash
pip install agentgate
```

## Quickstart

```python
from agentgate import AgentGate

# Connect to your AgentGate server
gate = AgentGate("http://localhost:8000")

# Register your agent — declare what it's allowed to do
gate.register(
    agent_id="my_agent",
    name="ReportBot",
    declared_purpose="Summarize quarterly business reports",
    authorized_resources=["/reports/*"],
    authorized_actions=["read"],
)

# Authorize before every action
result = gate.authorize("read", "/reports/q3.pdf")
# result["decision"] → "PERMIT", "ESCALATE", or "DENY"

# Or use the decorator
@gate.guard("read", resource_arg="path")
def read_report(path: str) -> str:
    return open(path).read()

# Or scan content for prompt injection
scan = gate.scan(email_body)
if scan["level"] == "injection":
    raise ValueError("Injection detected — content blocked")
```

## LangChain Integration

```bash
pip install agentgate[langchain]
```

```python
from agentgate.langchain import AgentGateToolkit

toolkit = AgentGateToolkit(
    agentgate_url="http://localhost:8000",
    agent_id="langchain_bot",
    name="ReportBot",
    declared_purpose="Summarize quarterly business reports",
    authorized_resources=["/reports/*"],
    authorized_actions=["read"],
    processes_external_content=True,  # enables injection scanning
)

# Wrap your tools — enforcement is automatic
safe_tools = toolkit.wrap([read_document, list_documents])
agent = create_react_agent(llm, safe_tools)
```

## What AgentGate catches

- Agents reading secrets outside their declared scope
- Compromised agents attempting privilege escalation
- Delegation chains that exceed authorized permissions
- Velocity attacks and repetitive exploit patterns
- Prompt injection in documents, emails, and uploads

## Run the server

```bash
docker compose up
```

Dashboard: `http://localhost:8000`
