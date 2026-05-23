# AgentGate TypeScript SDK

TypeScript/Node.js client for [AgentGate](https://github.com/ElamOlame31/agentgate-public) — trust authorization for autonomous AI agents.

Works with **LangChain.js**, **Vercel AI SDK**, **OpenAI Node SDK**, **Mastra**, and any TypeScript agent framework.

## Install

```bash
npm install agentgate-pdp
```

## Quick start

```typescript
import AgentGate, { AgentGateDeniedError } from "agentgate-pdp";

const gate = new AgentGate({
  url:    "http://localhost:8000",
  apiKey: "your-api-key",
});

// Register the agent with its declared scope
await gate.register({
  agent_id:             "report_bot_001",
  name:                 "ReportBot",
  declared_purpose:     "Read and summarize quarterly business reports for the executive team",
  authorized_resources: ["/reports/*", "/documents/public/*"],
  authorized_actions:   ["read", "search"],
});

// Authorize before each sensitive operation
try {
  const result = await gate.authorize("read", "/reports/q3.pdf", "User requested Q3 summary");
  console.log(result.decision);        // "PERMIT"
  console.log(result.trust_breakdown); // { identity: 0.92, delegation: 1.0, ... }
  console.log(result.explanation);     // Human-readable reasoning
} catch (err) {
  if (err instanceof AgentGateDeniedError) {
    console.log("Blocked:", err.message);
    // Agent never touches the file
  }
}
```

## Operation helper

```typescript
// Block executes only if PERMIT
const content = await gate.operation(
  "read",
  "/reports/q4.pdf",
  () => fs.readFile("/reports/q4.pdf", "utf-8"),
  "Q4 board summary",
);
```

## Guard decorator

```typescript
const safeRead = gate.guard("read", { resourceArg: "path" })(
  async ({ path }: { path: string }) => fs.readFile(path, "utf-8")
);

// Throws AgentGateDeniedError if not authorized
const content = await safeRead({ path: "/reports/q3.pdf" });
```

## LangChain.js integration

```typescript
import { tool } from "@langchain/core/tools";
import { z } from "zod";

const readDocumentTool = tool(
  async ({ path }) => {
    await gate.authorize("read", path, "LangChain agent reading document");
    return fs.readFile(path, "utf-8");
  },
  {
    name: "read_document",
    description: "Read a document from the company file system",
    schema: z.object({ path: z.string() }),
  },
);
```

## Vercel AI SDK integration

```typescript
import { tool } from "ai";
import { z } from "zod";

const readReport = tool({
  description: "Read a quarterly report",
  parameters: z.object({ path: z.string() }),
  execute: async ({ path }) => {
    await gate.authorize("read", path, "AI assistant reading report");
    return fs.readFile(path, "utf-8");
  },
});
```

## Content scanning

```typescript
// Detect prompt injection in external content before passing to the model
const scan = await gate.scan(emailBody);
if (scan.level === "injection") {
  throw new Error(`Injection detected: ${scan.evidence}`);
}
```

## Error types

| Error | When |
|---|---|
| `AgentGateDeniedError` | Decision is DENY (raiseOnDeny=true) |
| `AgentGateEscalatedError` | Decision is ESCALATE (raiseOnEscalate=true) |
| `AgentGateNotRegisteredError` | authorize() called before register() |
| `AgentGatePendingError` | PENDING and autoResolvePending=false |
| `AgentGateUnavailableError` | Server unreachable |

## Configuration

```typescript
const gate = new AgentGate({
  url:                 "http://localhost:8000",
  apiKey:              "your-key",
  raiseOnDeny:         true,   // throw on DENY  (default: true)
  raiseOnEscalate:     false,  // throw on ESCALATE (default: false)
  autoResolvePending:  true,   // poll for human decision (default: true)
  pendingTimeout:      95,     // seconds before auto-deny (default: 95)
  requestTimeout:      30_000, // ms (default: 30000)
});
```
