# Architecture

AgentGate is a policy decision point reached over HTTP. An agent asks before it
acts; the answer is a receipt.

```
Your agent  ──POST /authorize──►  AgentGate PDP  ──►  receipt
            ◄───────────────────                      (action_ref, flow, signatures)
            ──POST /receipts/redeem──►               spend it, once
            ──executes──►
```

---

## Where the code lives

`core/` is grouped by **what each module guarantees**, because the difference
is the product.

### `core/receipts/` — provable to someone who was not there

| Module | Role |
|---|---|
| `action_ref` | content address of an operation, recomputable by the caller |
| `response_signing` | HMAC over the decision — the issuer's own check |
| `receipt_signing` | Ed25519 over the same bytes — everyone else's |
| `receipts` | one-time redemption |
| `merkle` | batch commitment over the audit log |

See [receipts.md](receipts.md).

### `core/enforcement/` — may this run, may this data leave

| Module | Nature |
|---|---|
| `labels` | information-flow lattice — a violation is a **fact** |
| `trust_engine` | weighted 4-dimension score — a **judgement** |
| `policy_engine` | operator rules, hard block before scoring |
| `delegation` | chain walk, scope attenuation |

The distinction is load-bearing. Flow violations are checked outside the score
rather than folded into it: a high score must not be able to buy its way past a
flow that must not happen. See [information-flow.md](information-flow.md).

### `core/detection/` — signals that something looks wrong

`kill_chain` · `injection_detector` · `output_sanitizer` · `quarantine` ·
`contagion` · `purpose_engine`

Heuristics, and labelled as such. They find what the lattice cannot see — a
sequence of individually legitimate reads, an instruction hidden in a document —
at the cost of being arguable and occasionally wrong.

### `core/platform/` — the machinery the rest stands on

`audit` · `models` · `token` · `approvals` · `alerts` · `report` · `explainer`

---

## The path a request takes

```
POST /authorize
  │
  ├─ API key                                          401
  ├─ resource normalization (decode ×2, posix, null)  400 on traversal
  ├─ agent known?                                     DENY UNREGISTERED_AGENT
  ├─ token valid (Ed25519 JWT)?                       401
  ├─ quarantined?                                     DENY QUARANTINED
  ├─ operator policy                                  DENY, hard, before scoring
  ├─ injection scan (when content submitted)          DENY INJECTION_DETECTED
  │
  ├─ trust score      identity · delegation · purpose · behaviour
  ├─ kill chain       sequence patterns across the session
  ├─ contagion        penalty from a quarantined neighbour
  │
  ├─ INFORMATION FLOW  ← outside the score. A violation denies outright.
  │
  ├─ decision: PERMIT | ESCALATE | DENY | PENDING
  ├─ seal: action_ref, flow, nonce, HMAC, Ed25519
  └─ audit write — synchronous, before the response leaves
```

Two ordering choices matter:

**The audit write is synchronous.** The caller executes on a PERMIT, so an entry
still sitting in a writer queue would mean an action can run with no record of
what authorized it — the one guarantee this system exists to provide.

**The seal happens before the audit write**, so the sealed values are what lands
in the log rather than a stripped copy of it.

---

## What runs on the hot path, and what does not

Measured over HTTP against uvicorn, not in process:

| | median | p99 |
|---|---|---|
| `POST /authorize` | 130 ms | 294 ms |
| `POST /receipts/redeem` | 48 ms | 221 ms |
| authorize + redeem | 181 ms | 409 ms |
| client-side binding check | 0.0 ms | 0.1 ms |

Nothing on this path reaches a third party. The prose explanation used to call a
language model synchronously on the event loop with no timeout — 1175 ms median,
25 s worst case — and now lives at `GET /decisions/{id}/explain`, generated when
someone reads a decision rather than when one is made. A fail-closed gate whose
latency depends on another provider's uptime blocks agents when that provider is
slow.

The remaining 130 ms is dominated by the sentence-transformers embedding
computed for purpose alignment. That is the next thing to attack.

---

## State

SQLite, single file, path set by `AGENTGATE_DB_PATH`.

| Table | Holds |
|---|---|
| `audit_log` | every decision, HMAC-chained by insertion order |
| `request_history` | per-agent reads, the source of velocity and flow state |
| `agent_baselines` | one rate sample per window per agent |
| `redeemed_receipts` | spent nonces |
| `merkle_checkpoints` | batch roots |
| `agent_quarantine` | active quarantines |
| `pending_approvals` | the human-in-the-loop queue |

The HMAC chain is built and verified in **insertion order** (`rowid`), not
timestamp order. Timestamps record when a response object was built, which for
queued writes can tie or invert, and a chain built in one order and verified in
another breaks for reasons that look like tampering.

**Honest limit:** one process, one file. No HA, no horizontal scale. Acceptable
for consequential actions — the ones that move money, delete, or export — and
not for mediating every call a high-volume agent makes.

---

## Deployment

```bash
cp .env.example .env          # set AGENTGATE_API_KEY and AGENTGATE_SIGNING_KEY
pip install -r requirements.txt
python run.py                 # http://localhost:8000
```

Two variables decide whether the guarantees hold:

- `AGENTGATE_SIGNING_KEY` — derives the Ed25519 receipt key. On the default,
  every deployment shares a signing identity and a signature proves nothing
  about which instance issued what.
- `AGENTGATE_LOG_KEY` — the audit chain HMAC. Rotating it makes every prior
  entry fail verification, which is indistinguishable from tampering to anyone
  reading the trail afterwards.

Set both explicitly, once, and keep them.
