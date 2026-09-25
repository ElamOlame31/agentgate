# AgentGate Threat Model — MITRE ATLAS v5.1.0

> **Scope:** AI agents calling tools, APIs, and data stores in autonomous workflows.
> **Framework:** MITRE ATLAS v5.1.0 (October 2025 expansion — agent-specific techniques added).
> **How to read this document:** For each ATLAS technique, the table shows which AgentGate control
> blocks it, what the control does, and whether the block is *hard* (always DENY regardless of
> score) or *scored* (factors into the trust score).

---

## 1. Reconnaissance & Discovery

| ATLAS Technique | ID | AgentGate Control | Block Type |
|---|---|---|---|
| AI System Information Gathering | AML.T0007 | Agent must pre-declare `authorized_resources`. Resources outside scope trigger `RESOURCE_OUT_OF_SCOPE` flag → hard DENY. | Hard |
| Directory traversal / path confusion | — | Double URL-decode + `posixpath.normpath` before every authorization. `..` in decoded path → HTTP 400 before scoring. | Hard |
| Directory sweep (broad recon) | AML.T0007.002 | Kill chain detector: ≥ 6 distinct top-level resource prefixes in 5-minute window → `KILL_CHAIN:DIRECTORY_SWEEP` flag → ESCALATE or DENY. | Scored |
| Sensitivity escalation probing | AML.T0007.003 | Kill chain detector: LOW/MEDIUM requests accumulate, then first CRITICAL request → `KILL_CHAIN:SENSITIVITY_RAMP` → ESCALATE. | Scored |

---

## 2. Resource Development / Identity Manipulation

| ATLAS Technique | ID | AgentGate Control | Block Type |
|---|---|---|---|
| Forged agent identity | AML.T0008 | Ed25519 JWT signature; tampered token → `InvalidSignatureError` → HTTP 401 before any decision. Offline-verifiable with public key. | Hard |
| Replay attack (reused token) | AML.T0008.001 | JWT `exp` claim + `token_expires_at` in DB. Expired tokens → HTTP 401. `TOKEN_TTL` configurable per deployment. | Hard |
| Token theft / credential leak | AML.T0009 | Only the JWT (not the signing key) is returned to callers. JTI stored server-side; token theft without the private key produces an unverifiable signature. | Hard |
| Agent self-escalation at registration | — | Registration endpoint enforces server-controlled `delegated_by`, `delegation_depth`, `scope_at_delegation`. Client-supplied values are discarded. | Hard |
| Scope creep at delegation | AML.T0010 | `validate_delegation()` rejects child scope ⊄ parent scope at delegation time. `score_delegation()` applies `SCOPE_ESCALATION_AT_DELEGATION` penalty. | Hard |

---

## 3. Initial Access / Injection

| ATLAS Technique | ID | AgentGate Control | Block Type |
|---|---|---|---|
| Prompt injection via external content | AML.T0051 | `/scan` endpoint + inline `content` field scan (when `processes_external_content=True`). Injection → `INJECTION_DETECTED` → hard DENY before authorization. | Hard |
| Indirect prompt injection (tool output) | AML.T0051.001 | Same injection scanner applied to tool-returned content when agent submits it with authorization request. | Hard |
| Homoglyph / Unicode obfuscation | — | `unicodedata.normalize("NFKC", …)` applied before all secret and injection pattern matching. Lookalike characters normalized before regex evaluation. | Hard |

---

## 4. Execution / Lateral Movement

| ATLAS Technique | ID | AgentGate Control | Block Type |
|---|---|---|---|
| Unauthorized tool invocation | AML.T0017 | `UNAUTHORIZED_ACTION` flag (action not in declared `authorized_actions`) → hard DENY. | Hard |
| Out-of-scope resource access | AML.T0017.001 | `RESOURCE_OUT_OF_SCOPE` flag (resource not matched by `authorized_resources` glob patterns) → hard DENY. | Hard |
| MCP tool hijacking | AML.T0017.002 | MCP proxy intercepts every `tools/call` and `resources/read`, submits to AgentGate before forwarding. Unregistered tools blocked without reaching upstream server. | Hard |
| Agent-to-agent impersonation | AML.T0018 | Delegation chain walked at every authorization call: `check_chain_scope()` verifies action+resource against every ancestor's scope. `CHAIN_SCOPE_VIOLATION` → hard DENY. | Hard |
| Orphan delegation chain | — | `ORPHAN_DELEGATION` flag: parent claimed in `delegated_by` but absent from registry → hard DENY (unverifiable chain). | Hard |
| Excessive delegation depth | AML.T0018.001 | `MAX_DELEGATION_DEPTH` enforced at delegation time and re-verified at authorization. `EXCESSIVE_DELEGATION_DEPTH` → hard DENY. | Hard |

---

## 5. Collection / Exfiltration

| ATLAS Technique | ID | AgentGate Control | Block Type |
|---|---|---|---|
| Bulk data collection | AML.T0035 | Kill chain detector: ≥ 10 reads in 5-minute window before exfil or destroy action → `KILL_CHAIN:BULK_READ_THEN_EXFIL` or `BULK_READ_THEN_DESTROY` → hard DENY. | Hard |
| Data exfiltration action | AML.T0035.001 | `EXFILTRATION_ACTIONS` set (`send`, `email`, `upload`, `post`, `forward`, `export`, `transfer`, `publish`) → resource automatically classified as CRITICAL sensitivity (threshold 90.0). | Scored |
| Read-then-delete (cover tracks) | AML.T0036 | Kill chain detector: agent reads a resource, then requests delete of the same path → `KILL_CHAIN:READ_THEN_DELETE` → hard DENY. | Hard |
| Secrets in request args | — | Regex patterns (OpenAI keys, AWS AKIA, GitHub PATs, RSA/EC private keys, `password=`, `Bearer …`) applied to resource path + justification + concatenation. `SECRETS_IN_ARGS` → hard DENY. | Hard |

---

## 6. Impact / Manipulation

| ATLAS Technique | ID | AgentGate Control | Block Type |
|---|---|---|---|
| Credential-bearing resource access | AML.T0048 | Critical keyword list (`password`, `private_key`, `.pem`, `jwt_secret`, `vault`, …) in resource path → CRITICAL sensitivity → threshold 90.0. | Scored |
| High-velocity abuse (DDoS-style) | AML.T0050 | Per-agent baseline RPM with adaptive threshold (2.5× avg). Cold-start global cap (20 RPM). `CRITICAL_VELOCITY` → hard DENY; `HIGH_VELOCITY` → score penalty. | Mixed |
| Contract violation — rate limit | — | Deterministic: agent declares `max_requests_per_minute` at registration. Exceeding it → `CONTRACT_RPM_EXCEEDED` → hard DENY (no trust score involved). | Hard |
| Contract violation — time window | — | Agent declares `allowed_time_windows` (UTC). Request outside window → `CONTRACT_OUTSIDE_TIME_WINDOW` → hard DENY. | Hard |
| Contract violation — action repetition | — | Agent declares `max_consecutive_same_action`. Exceeded → `CONTRACT_CONSECUTIVE_ACTION` → hard DENY. | Hard |
| Repetitive action (replay/amplification) | AML.T0050.001 | Covered by the per-agent velocity baseline (volume) and the resource hammering detector (one resource repeatedly). A previous `REPETITIVE_ACTION` check counted action *types* and flagged every working agent, so it was removed. | Scored |
| Purpose misalignment (goal hijacking) | AML.T0049 | Purpose alignment score: embedding similarity of (action + resource) vs declared purpose (85% weight) + justification (15% weight, attacker-controlled weight capped). Sub-threshold → DENY. | Scored |
| Audit log tampering | — | HMAC-SHA256 chain: each entry signed over the previous entry's hash. `/audit/verify` endpoint detects any gap or modification. | Detective |

---

## 7. Persistence

| ATLAS Technique | ID | AgentGate Control | Block Type |
|---|---|---|---|
| Persistent rogue agent | AML.T0022 | `POST /agents/{id}/revoke` nulls the stored JTI → all subsequent auth requests from that agent fail with HTTP 401 immediately. | Hard |
| Rogue delegation subtree | AML.T0022.001 | `POST /agents/{id}/revoke_chain` BFS-walks delegated_by pointers and atomically nulls tokens for the agent and every descendant. | Hard |
| Agent re-registration after revocation | — | Revoked agent's `agent_id` remains in the registry (token=NULL). Re-registration attempts receive HTTP 409 Conflict. | Hard |

---

## 8. Defense Evasion

| ATLAS Technique | ID | AgentGate Control | Block Type |
|---|---|---|---|
| Gradual baseline poisoning | AML.T0053 | Baseline only updated with *clean* observations (no VELOCITY flags). Anomalous requests excluded from average — baseline cannot be drifted upward via sustained abuse. | Hard |
| Policy bypass via NL justification | AML.T0053.001 | Justification weight capped at 15% of purpose score. Cannot overcome a structurally misaligned action+resource (85% weight). | Scored |
| URL encoding / path confusion | AML.T0053.002 | Double decode + null-byte strip + `posixpath.normpath` on every resource before authorization. Encoded traversal blocked before trust scoring. | Hard |

---

## 9. Controls not yet implemented (roadmap)

| Gap | Planned Control |
|---|---|
| LLM output verification (did the agent faithfully execute the authorized action?) | Post-action attestation hook |
| Cross-agent collusion (two registered agents cooperating to exceed combined scope) | Cross-agent correlation in kill-chain window |
| Agent supply-chain compromise (malicious agent SDK) | SDK signing + SBOM attestation |

---

## Quick-reference: hard DENY flags

The following flags always produce `DENY` regardless of trust score:

```
KILL_CHAIN:BULK_READ_THEN_EXFIL
KILL_CHAIN:BULK_READ_THEN_DESTROY
KILL_CHAIN:READ_THEN_DELETE
CONTRACT_RPM_EXCEEDED
CONTRACT_OUTSIDE_TIME_WINDOW
CONTRACT_CONSECUTIVE_ACTION
SECRETS_IN_ARGS
CRITICAL_VELOCITY
CHAIN_SCOPE_VIOLATION
ORPHAN_DELEGATION
EXCESSIVE_DELEGATION_DEPTH
UNAUTHORIZED_ACTION
RESOURCE_OUT_OF_SCOPE
INJECTION_DETECTED
```

---

*Generated: 2026-05-24 | Framework: MITRE ATLAS v5.1.0 | AgentGate v0.2.0*
