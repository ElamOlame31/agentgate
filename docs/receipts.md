# Receipts

A receipt is what AgentGate produces instead of a log line. It answers three
questions about an agent action, to someone who was not there and has no reason
to trust whoever hands it to them:

- **Who authorized it** — an Ed25519 signature from the instance that decided.
- **What exactly** — a digest over the operation, every material argument
  included, that the holder can recompute.
- **Under what information flow** — what the session had been exposed to, and
  whether anything the agent did not author influenced the decision.

A log says an action happened. A receipt says what was permitted, and lets
someone else check it against what actually ran.

---

## The shape

```json
{
  "request_id":      "3ebe7a0c-3f28-449a-883b-2b60ecb7a7b8",
  "agent_id":        "pay_bot",
  "action":          "transfer",
  "resource":        "/payments/outbound",
  "decision":        "PERMIT",
  "timestamp":       1790347211.233,
  "action_ref":      "0d1bbad7c9fd3ff1ff520cfc105543cada6398df5f9a7f0803d4dbf555b98ecd",
  "response_nonce":  "8c2f…",
  "response_sig":    "…",          // HMAC — the issuer's own check
  "receipt_sig":     "…",          // Ed25519 — everyone else's
  "key_id":          "ebdf1d012508e7ae",
  "flow": {
    "confidentiality":  "PUBLIC",
    "integrity":        "TRUSTED",
    "sources":          [],
    "untrusted_reason": ""
  }
}
```

---

## action_ref — which operation, exactly

```
action_ref = SHA-256( canonical_json({
    v, agent_id, action, resource, arguments, policy_version
}) )
```

Deliberately absent: nonce, timestamp, decision. Those belong to a single
authorization *event* and differ between the request and the dispatch that
follows it. Including them would make the reference unrecomputable, which is
the opposite of what it is for. They are bound separately, by the signature,
which covers `action_ref` alongside them.

Two operations share an `action_ref` exactly when every field above matches.
Change the amount, the recipient, the path or the agent and the reference
changes with it. Change only the order of the JSON keys, or spell the path
`/payments/./outbound`, and it does not.

**Why this matters.** A decision that says "PERMIT for request 4f2c…" proves
who decided and when. It does not prove *what* was decided, so nothing stops
that verdict being spent on a different operation — the failure
[Loopjacking](https://arxiv.org/abs/2609.21081) describes and reproduces in
Agno AgentOS and LangGraph Agent Server. The reference is what closes it.

### Canonicalization

JSON with sorted keys, no insignificant whitespace, unescaped UTF-8.

This is a **subset of JCS (RFC 8785), not JCS**. The two agree on objects,
arrays, strings, booleans, null and integers, and can disagree on how some
floating-point values serialize. Keep money in minor units and other quantities
integral and they are interchangeable; send a float and a JCS-based verifier may
compute a different digest. ATAP and algovoi-substrate canonicalize with JCS, so
full compliance matters once receipts cross between implementations. It is a
known, bounded gap.

---

## Two signatures, on purpose

| | Algorithm | Who can verify | Who can issue |
|---|---|---|---|
| `response_sig` | HMAC-SHA256 | anyone with the shared secret | anyone with the shared secret |
| `receipt_sig` | Ed25519 | **anyone** | the instance only |

The HMAC is right for the server checking its own receipt at redemption, and
useless for the case this exists to serve. Handing an auditor the HMAC key would
let them mint receipts, so a symmetric scheme can only offer *trust us, or
become us*.

The public key is served at `GET /receipts/public-key`, **unauthenticated**. A
verifier is usually not a customer — an auditor, a regulator, an insurer's
assessor — and requiring a credential to check a signature defeats the point of
having one.

Both signatures cover the same canonical string:

```
nonce | request_id | agent_id | DECISION | timestamp | action_ref | flow
```

Altering the flow claim to present a session as cleaner than it was invalidates
both.

---

## Redemption — spent once

A signature proves a receipt is genuine and fresh. It does not stop the same
valid receipt being presented twice inside the freshness window, which is the
difference between resisting forgery and resisting replay.

```
POST /authorize        -> receipt
... caller is about to execute ...
POST /receipts/redeem  -> 200, or 409 with the reason
caller executes
```

`409` rather than `403`: the receipt may well have been valid — it is spending
it that conflicts with what already happened. The reason comes back so a caller
can tell a replay from a forgery.

Only redeemed nonces are stored. The signature already proves we issued it, so
presence means spent and absence means not yet, and recording every issued nonce
would double the write cost of every decision to buy nothing. The `INSERT` is
both the test and the mark, so concurrent redemptions of one receipt produce
exactly one winner.

Redemption is also the first record that an authorized action was actually
dispatched. A trail holding only decisions can say what was allowed; one holding
redemptions can say what was allowed **and taken** — the question asked after an
incident.

---

## Verifying, offline

```bash
pip install agentgate-pdp[verify]

curl -s http://your-pdp:8000/receipts/public-key \
  | jq -r .public_key_pem > agentgate.pem

python -m agentgate.verify receipt.json \
       --public-key agentgate.pem \
       --operation  operation.json
```

```
  PASS

  decision      PERMIT
  agent         pay_bot
  signing key   ebdf1d012508e7ae

  signature     valid — signed by the holder of this key
  binding       matches — this receipt authorizes exactly this operation

  information flow
    session had been exposed to public material
    decision inputs were trusted
```

With an operation whose amount was changed after authorization:

```
  FAIL
  signature     valid — signed by the holder of this key
  binding       MISMATCH — this receipt does not authorize that operation
      authorized: 0d1bbad7c9fd3ff1…
      supplied:   e3af41c88f0b6ae9…
```

Exit code is `1` on failure, so it drops into a pipeline without being parsed.

Without `--operation` the verifier checks the signature only and says so: a
receipt with nothing to compare proves who issued what verdict, not that a
particular thing was authorized.

The verifier reimplements the canonical form rather than importing it from the
server — one that needs the server installed is not a verifier. A test computes
the same operation through both paths and fails if either side drifts.

---

## Key rotation

`AGENTGATE_SIGNING_KEY` derives the Ed25519 pair deterministically, so a restart
keeps the same key and a rotated secret produces a new one. Rotation invalidates
previously issued receipts, which is correct: a receipt attests that a specific
instance authorized something, and after rotation that claim can no longer be
confirmed. `key_id` travels with every receipt so a verifier can tell a rotation
from a forgery.

Set the key explicitly. On the default, every deployment shares a signing
identity and the signature proves nothing about which instance issued what.

---

## What a receipt does not prove

- **That the action succeeded.** It proves it was authorized and, if redeemed,
  dispatched. What happened next is the application's record to keep.
- **That the agent used the data it was allowed to read.** Flow labels are
  session-grained; see [information-flow.md](information-flow.md).
- **That the operation description is truthful.** If a caller submits arguments
  that differ from what it will really execute, the receipt binds the lie. The
  binding is only as good as the integration, which is why `guard()` derives
  arguments from the function signature rather than trusting a hand-written dict.
