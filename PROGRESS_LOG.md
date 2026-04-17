# AgentGate — Progress Log
**14-Day Build Sprint | Start: April 17, 2026**

---

## What is AgentGate? (Simple Version)

Imagine a company uses an AI agent to read and summarize documents.
That agent has a password (token) to access the system.

**The problem today:** The system only checks the password.
It does NOT check:
- Is this agent supposed to be doing THIS specific action?
- Does deleting a salary file make sense for a "document summarizer"?
- Who gave this agent permission, and was that chain of permission legitimate?
- Is this agent making 30 requests in 5 seconds — suspicious behavior?

**AgentGate is the missing security layer.**
It sits between the AI agent and the resource (files, databases, APIs),
and asks 4 questions before allowing anything through.

---

## The 4 Questions AgentGate Asks (The Trust Score)

Every request gets scored 0-100 on 4 dimensions:

| Dimension | What it checks | Weight |
|---|---|---|
| **Identity** | Valid token? Action allowed? Resource in scope? | 25% |
| **Delegation Chain** | Who authorized this agent? Was scope narrowed at each step? | 25% |
| **Purpose Alignment** | Does this action match what the agent said it was built to do? | 30% |
| **Behavioral** | Is the agent making too many requests too fast? Unusual patterns? | 20% |

Final score = weighted average.
Then compared to the sensitivity of the resource being accessed:
- LOW sensitivity file → need score 40+ to pass
- MEDIUM → 60+
- HIGH → 75+
- CRITICAL (passwords, salary) → 90+

Result: **PERMIT** / **ESCALATE** (flag but allow) / **DENY**

---

## DAY 1 — April 17, 2026

### What We Built

**1. The Core Engine (`core/`)**
- `models.py` — defines all data structures: what an Agent looks like, what a Request looks like, what a Decision looks like
- `trust_engine.py` — the brain. Takes an agent + a request, computes the 4 scores, returns a decision
- `purpose_engine.py` — uses AI embeddings (sentence-transformers) to compare what an agent *said* it does vs what it's actually *trying to do*. Example: "summarize documents" vs "delete salary.xlsx" → similarity score near 0
- `audit.py` — saves every single decision to a SQLite database with full details
- `explainer.py` — calls Claude AI to generate a one-sentence plain-English explanation of why a decision was made

**2. The Server (`server/main.py`)**
- A FastAPI web server running on `localhost:8000`
- Exposes endpoints: `/authorize` (the main PDP), `/agents/register`, `/audit/recent`, `/audit/stats`
- Has a WebSocket (`/ws`) that pushes every decision to the dashboard in real time

**3. The Dashboard (`dashboard/index.html`)**
- A single HTML file (no frameworks, no build step)
- Shows: total requests, permits, denials, attack flags
- Live feed of every authorization decision with color-coded badges
- Right panel: trust score breakdown for the last decision (4 bars + final score)
- Chart: trust score over last 40 requests — you can see the score drop during attacks

**4. The Simulator (`simulator/agents.py`)**
- Fake AI agents that make real HTTP calls to AgentGate
- Used to demonstrate attack scenarios

**5. Demo Scripts (`demo/`)**
- `attack_demo.py` — shows what happens WITHOUT AgentGate (all attacks succeed, zero detection)
- `protected_demo.py` — shows what happens WITH AgentGate (attacks detected and blocked)

---

### What We Demonstrated (4 Attack Scenarios)

**Attack 1 — Privilege Escalation via Delegation Confusion**
- Scenario: Agent A (manager) delegates to Agent B (sub-agent). Agent B then tries to access confidential salary data and do admin operations it was never authorized for.
- WITHOUT AgentGate: PERMITTED. Valid token = full access.
- WITH AgentGate: ESCALATE (score 63/100, needs 90 for CRITICAL resource) + DENY for scope escalation flag.

**Attack 2 — Purpose Drift**
- Scenario: A "document summarizer" agent (read-only purpose) starts making write and delete calls on confidential files.
- WITHOUT AgentGate: PERMITTED. Token is valid, actions are technically in the ACL.
- WITH AgentGate: ESCALATE. Purpose alignment score drops to 3-17/100 — the system knows "delete hr_records.csv" is inconsistent with "summarize PDF documents."

**Attack 3 — High-Velocity Data Exfiltration**
- Scenario: An agent fires 30 requests in under 10 seconds — classic sign of automated data scraping/exfiltration.
- WITHOUT AgentGate: ALL 30 PERMITTED. No rate awareness whatsoever.
- WITH AgentGate: First 6 permitted, then behavioral score degrades as velocity exceeds 20 RPM. 24 ESCALATE with flag `HIGH_VELOCITY:23_RPM`.

**Attack 4 — Audit Gap (Accountability Black Hole)**
- Scenario: Malicious actions happen, logs show only "DELETE /salary.xlsx | 200 OK" — no agent identity, no reason, no delegation chain.
- WITHOUT AgentGate: Impossible to know who did it, why, or how.
- WITH AgentGate: Every decision logged with agent_id, declared purpose, trust score, delegation chain, and plain-English explanation.

---

### What is Real vs Simulated

| Component | Status | Notes |
|---|---|---|
| Trust scoring engine | ✅ REAL | Runs real math on real inputs |
| Purpose alignment (AI embeddings) | ✅ REAL | Uses sentence-transformers model |
| Delegation chain detection | ✅ REAL | Tracks depth, scope attenuation |
| Behavioral velocity scoring | ✅ REAL | Queries SQLite for request history |
| Audit trail (SQLite) | ✅ REAL | Persists across restarts |
| WebSocket real-time dashboard | ✅ REAL | Live push, no polling |
| Claude-generated explanations | ✅ REAL | Calls Claude Haiku API (fallback if no key) |
| The AI agents making requests | ❌ SIMULATED | Python scripts pretending to be agents |
| The files being "accessed" | ❌ SIMULATED | Paths are strings, no real filesystem |

**Key point for the pitch:** The security layer is fully implemented and production-ready in design. The agents are simulated to demonstrate attack patterns. Connecting a real LLM agent (LangChain, Claude, GPT-4) is straightforward and is planned for Day 3-4.

---

### What Works

- Server starts with one command: `python run.py`
- Dashboard connects live via WebSocket and shows real-time decisions
- All 4 attack scenarios are detected as designed
- Explanations correctly identify the weakest score or the attack flag
- Delegation chain is visible on the dashboard (SubAgent-B ← parent_agent_A)
- Trust score chart updates live during the demo

### What Doesn't Work Yet / Known Limitations

- The velocity attack results in ESCALATE, not DENY — the scoring degrades but never fully denies a legitimate-resource read. Intentional for now (tuning needed).
- No real LLM agent connected yet — all agents are simulated scripts.
- No user authentication on the AgentGate server itself — anyone can register an agent or call `/authorize`. (Fine for prototype, must fix before production.)
- Explanations use fallback text (no Claude API key configured yet) — functional but less impressive than the AI-generated version.
- No persistent agent registry — agents are lost when the server restarts (in-memory only for now).

---

### Key Numbers from Day 1 Demo

- 83 total requests processed
- 23 permitted (legitimate traffic)
- 2 denied (hard blocks)
- 54 attack flags raised
- Purpose alignment score on "delete salary.xlsx" for a summarizer agent: **3.23/100**
- Trust score on scope-escalation delete attempt: **55.39/100** → DENY

---

## DAY 2 — (Coming)

Planned:
- Natural language policy generator (admin writes rules in plain English → auto-enforced)
- Connect a real LLM agent to AgentGate
- Harden velocity attack to produce DENY, not just ESCALATE

---

*Updated daily. Last update: April 17, 2026.*
