# Show HN Draft — Post Tuesday May 12, 8-10am Ottawa (ET)

## TITLE

```
Show HN: AgentGate – Authorization layer for AI agents (OAuth has no idea what your agent is doing)
```

## FIRST COMMENT (paste as your first reply to your own post)

```
Hey HN, I'm Elam — I built AgentGate while working on my master's in engineering.

The problem I kept running into: every AI agent deployment I looked at uses OAuth 
or API keys for authorization. Those check *who you are*. They have no idea what 
the agent is actually doing or why.

A LangChain agent with a valid token can:
- Read files far outside its declared scope
- Be delegated more permissions than its parent ever granted
- Fire 80 requests/min and slowly exfiltrate data under the rate-limit radar
- Be hijacked mid-task if a document it processes says "ignore your instructions"

AgentGate is a Policy Decision Point that sits between the agent and its tools. 
Before any action executes, it scores the request 0–100 across 4 dimensions:

- Purpose alignment (30%): embedding similarity between the agent's declared 
  purpose and the current action's justification
- Delegation chain (25%): scope attenuation enforced at every hop — child agents 
  can never exceed what their parent was authorized to do
- Identity + scope (25%): resource path matching, action whitelist
- Behavioral velocity (20%): requests/min, deviation from baseline

The threshold scales with resource sensitivity — a /reports/ folder needs 40+, 
a /confidential/salary.xlsx needs 90+.

Decision comes back in <100ms: PERMIT, ESCALATE (human reviews), or DENY.

Works with LangChain, LangGraph, AutoGen, or any custom agent:

    pip install agentgate-pdp

GitHub (MIT): https://github.com/ElamOlame31/agentgate-public

The part I'm least confident about is the purpose alignment scoring — currently 
cosine similarity on embeddings, which works but feels like it could be gamed. 
Would genuinely love to hear how people here think about that problem.
```

## Instructions
1. Go to news.ycombinator.com
2. Click "submit"
3. Title: paste the title above
4. URL: https://github.com/ElamOlame31/agentgate-public
5. After posting, immediately reply to your own post with the first comment above
