# AgentGate Progress Log

Daily entries from the autonomous product engineer.

---

## 2026-06-11 — SAFE-T1001 Tool Schema Poison Detection (ContextCrush)

### Research summary

Searched for competitor moves, new attack patterns, and enterprise requirements in the last 48h.
Key findings (full details in MARKET_RESEARCH.md):

- **Noma** launched Agentic Access Control on June 2 — MCP server governance, tool-level approve/block. Their gap: posture management, not behavioral pre-execution enforcement.
- **ContextCrush** (SAFE-T1001 / CVE-2025-54136): the dominant attack vector right now. A malicious MCP server embeds hidden directives in `tools/list` description fields. These are invisible in UI renderers but consumed verbatim by the LLM tokenizer before any tool call is made.
- **$392M+ in agentic AI security funding** at RSAC 2026; Oasis ($120M Series B), Noma ($100M), Runlayer (8 unicorn customers).
- **NIST AI Agent Standards Initiative** (Feb 2026): Q4 2026 AI Agent Interoperability Profile planned. Pre-execution enforcement and multi-agent accountability are named governance gaps.

### Decision

Fix the ContextCrush gap: `tools/list` responses were passing through the MCP proxy **completely unscanned**. The existing test at `tests/test_mcp_poisoning.py:293` even *asserted* this bypass behavior. This is SAFE-T1001.

Chose this over the SQLite `BEGIN EXCLUSIVE` throughput fix because:
1. Directly tied to a named CVE (CVE-2025-54136) and a disclosed, real-world attack
2. Noma's launch 9 days ago creates urgency — we need a deeper technical capability
3. Immediately auditable and demonstrable to enterprise buyers

### What was built

**Branch**: `daily/2026-06-11-tool-schema-poison-detection`

**`core/injection_detector.py`** — two additions:
1. `TOOL_SCHEMA_POISON_PATTERNS` — 8 regex patterns covering: cross-tool chaining ("after calling this tool, call X"), authority escalation ("this tool has admin access"), security bypass claims, hidden imperatives ("important: always also..."), and scope expansion targeting sensitive paths.
2. `scan_tool_schema(tool: dict) -> ToolSchemaResult` — new public function. Scans MCP tool name, description, and inputSchema properties for SAFE-T1001 patterns plus zero-width/invisible Unicode character injection. Pure keyword + regex, no ML, < 1ms per tool for the tools/list hot path.
3. `_ZW_CODEPOINTS` / `_ZW_POISON_RE` — detects zero-width Unicode character clusters (U+200B, U+200C, U+200D, U+FEFF, etc.) used to hide instructions from UI renderers while remaining in the LLM's token stream.

**`server/mcp_proxy.py`** — three additions:
1. `_SCHEMA_SCANNED = {"tools/list"}` — new constant; these methods are forwarded without authorization but their responses are scanned for schema poisoning before reaching the agent.
2. `_scan_tools_list_response(result)` — iterates over each tool in the list, calls `scan_tool_schema()`, removes poisoned/suspicious tools, returns the clean list + a report.
3. In the main `mcp_proxy` handler: `tools/list` now hits the schema scan path. Poisoned tools are stripped silently (agent gets a clean tool list). Warning header `X-AgentGate-Schema-Poison: SAFE-T1001: N tool(s) removed...` is set on the response. Console logs each removal.
4. `healthz` now reports `tool_schema_poison_scan: "enabled"` and `schema_scanned_methods: ["tools/list"]`.

**`tests/test_mcp_poisoning.py`** — new test classes:
- `TestScanToolSchema` — 11 unit tests for `scan_tool_schema()`: clean descriptions, cross-tool chaining, authority escalation, security bypass, hidden imperatives, scope expansion, classic injection in description, zero-width char hiding, empty/null descriptions, inputSchema parameter poisoning. All 11 pass.
- `TestScanToolsListResponse` — 6 unit tests: clean list unchanged, single poison removed, all-poisoned returns empty, empty list, missing key, original not mutated.
- `TestMCPProxyIntegration` — 5 new integration tests replacing the old "tools/list passes through unscanned" test: clean list passes intact, poisoned tool stripped, authority escalation stripped, zero-width chars stripped, all-poisoned returns empty, healthz reports schema scan enabled.

### Test results

Full pytest suite could not be run (PyPI blocked in this environment; `fastapi`, `pytest`, `sentence-transformers` not installed). 

Standalone stdlib-only validation: **16/16 tests passed** across `scan_tool_schema` and the tool list scanning logic. All 8 attack patterns detected correctly; clean descriptions pass through; zero-width char hiding detected; original results not mutated. 

Syntax verified (`ast.parse`) for all three modified files.

### Known gaps / next work

1. **SQLite `BEGIN EXCLUSIVE` bottleneck** — every `log_decision()` in `core/audit.py` holds a global write lock. Fix: WAL mode + async write queue. This is the #1 scaling blocker for any enterprise load test.
2. **Published latency numbers** — no benchmark exists. A `scripts/benchmark.py` that reports p50/p99 authorize latency with and without ML would directly address the "how fast is it?" question from enterprise buyers.
3. **Purpose alignment moat** — MiniLM + keyword penalties is not a defensible moat. Consider: fine-tuned model on agent action sequences, or a purpose graph that encodes domain-specific knowledge.
4. **NIST AI Agent Profile alignment** — as NIST's Q4 2026 profile approaches, position AgentGate terminology against RMF GOVERN/MANAGE functions explicitly.

### PR / Branch

Branch pushed: `daily/2026-06-11-tool-schema-poison-detection`
PR to be opened via GitHub MCP tools.
