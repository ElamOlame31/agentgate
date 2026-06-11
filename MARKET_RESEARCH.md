# AgentGate Market Research Log

Ongoing competitive intelligence and market analysis for the AgentGate product.
Maintained by the autonomous product engineer. Each dated section is one day's research.

---

## 2026-06-11 — ContextCrush / SAFE-T1001 / Noma MCP Launch

### Findings

**1. Noma launches Agentic Access Control (June 2, 2026)**
- Source: https://www.prnewswire.com/news-releases/noma-launches-agentic-access-control-to-govern-ai-agents-and-mcp-servers-across-the-enterprise-302788534.html
- Source: https://www.helpnetsecurity.com/2026/06/02/noma-brings-visibility-and-access-governance-to-ai-agents-and-mcp-servers/
- Nine days before this entry, Noma ($132M raised) shipped Agent Access Control: agent identity per MCP connection, 3-state governance (Approved/Review/Blocked), tool-level approval/block, runtime behavioral chain monitoring.
- **Gap vs AgentGate**: Noma operates as a POSTURE / GOVERNANCE layer — it discovers agents and lets you approve or block them. It does NOT do 4D trust scoring (identity + delegation chain + purpose alignment + behavioral velocity), does NOT detect kill chains across multi-step sequences, and does NOT scan MCP tool schemas for embedded instructions before the agent loads them. AgentGate operates DEEPER at pre-execution time with behavioral context.

**2. ContextCrush — MCP tool schema poisoning (SAFE-T1001), disclosed March 5, 2026**
- Source: https://techbytes.app/posts/mcp-context-poisoning-adversarial-memory-injection/
- Source: https://www.practical-devsecops.com/mcp-security-vulnerabilities/
- Source: https://arxiv.org/abs/2603.22489
- Source: https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
- Attack: A malicious (or compromised) MCP server returns `tools/list` with hidden instructions embedded in tool `description` fields. These instructions are invisible in UI renderers but consumed verbatim by the LLM's tokenizer, directing the agent to exfiltrate data, call other tools, or bypass its declared purpose — all before any tool call is made.
- MITRE-style taxonomy: SAFE-T1001 (Tool Poisoning Attack), documented by the SAFE-MCP initiative.
- Variant: Zero-width Unicode characters (U+200B, U+200C, U+200D, etc.) are inserted between visible characters to hide instructions from human reviewers while remaining in the token stream.
- Key insight: prior tool poisoning defenses only scanned tool call RESPONSES. The description schema itself was unscanned.

**3. WitnessAI raises $58M (total $85M), launches Agentic Security (January 2026)**
- Source: https://witness.ai/resources/witnessai-raises-58-million-for-global-expansion-and-announces-new-ways-to-secure-ai-agents/
- Source: https://siliconangle.com/2026/01/13/witnessai-debuts-agentic-security-enterprises-deploy-autonomous-ai-agents/
- Extends "confidence layer" from LLMs to autonomous agents. Focus: visibility and control for enterprise AI deployments. Less technical depth on pre-execution enforcement than AgentGate.

**4. NIST AI Agent Standards Initiative (February 2026)**
- Source: https://labs.cloudsecurityalliance.org/agentic/agentic-nist-ai-rmf-profile-v1/
- Source: https://www.nist.gov/itl/ai-risk-management-framework
- NIST launched an AI Agent Standards Initiative via CAISI (Feb 2026). An AI Agent Interoperability Profile is planned for Q4 2026. Key governance gaps acknowledged: irreversible pre-execution actions, distributed accountability in multi-agent orchestration. Both are exactly what AgentGate's 4D trust scoring + kill chain detection address.

**5. $392M+ in agentic AI security funding at RSAC 2026 (March 2026)**
- Source: https://softwarestrategiesblog.com/2026/03/28/agentic-ai-security-startups-funding-mna-rsac-2026/
- Oasis Security raised $120M Series B for non-human identity and agentic access governance. Noma raised $100M for AI agent hardening. Runlayer (Khosla/Felicis seed) signed 8 unicorn customers in 4 months.

**6. CVE-2025-54136: MCP Tool Poisoning**
- Source: https://www.truefoundry.com/blog/blog-mcp-tool-poisoning-gateway-defense
- A formal CVE was assigned to MCP tool poisoning. The fix category identified in the CVE is "pre-execution schema validation" — inserting a policy layer before the tool schema reaches the agent's context.

### Implications for AgentGate

1. **ContextCrush is the most urgent gap** — prior to this day's work, AgentGate scanned tool CALL responses and RESOURCE read content, but `tools/list` responses passed through unscanned. This is SAFE-T1001 / CVE-2025-54136. Today's fix closes it.

2. **Noma is the nearest competitor** — they moved into MCP governance. Their gap: POSTURE not ENFORCEMENT. AgentGate's pitch to enterprise buyers evaluating both: "Noma tells you WHICH agents are connected; AgentGate decides WHETHER each action executes, in real time, against a 4D trust model and a kill-chain detector." These are complementary but AgentGate is deeper.

3. **Runlayer threat**: MCP gateway with 8 unicorn customers. Their gap: gateway-level authz (can you call this tool?) vs. AgentGate's behavioral authz (should this action execute NOW given what this agent has been doing?). Schema poisoning detection gives AgentGate a capability Runlayer doesn't advertise.

4. **NIST AI Agent Profile** (Q4 2026): AgentGate should align terminology with RMF language for the enterprise compliance hook. "Pre-execution authorization enforcement" maps to RMF GOVERN/MANAGE functions.

5. **Sherlocking risk from Anthropic/OpenAI**: MCP is Anthropic's protocol. If they add native tool schema validation to MCP itself, it partially Sherlocks this. AgentGate's defense: behavioral kill-chain and purpose alignment are NOT in the MCP spec and require per-agent context that a protocol-level check can't have.

---
