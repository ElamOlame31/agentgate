# agentgate-pdp

Runtime authorization for autonomous AI agents, with receipts an auditor can
verify offline.

```bash
npm install agentgate-pdp
```

Node 18+. No runtime dependencies.

---

## What this is for

Your agent has credentials and it is allowed to use them. The question a
security review actually asks is the next one: when it moves money on a Friday,
what do you hand someone on Monday?

A log answers that badly. It is written after the fact, by the system being
questioned, and anyone holding the database could have typed it. A receipt is
different: it is sealed *before* the action, it binds the exact operation —
this recipient, this amount, this file — and it is signed with a key you do not
hold, so an auditor can check it without trusting you or reaching your servers.

This SDK gets receipts and makes the dispatch-time check hard to skip.

---

## Authorize and execute

```ts
import { AgentGate } from "agentgate-pdp";

const gate = new AgentGate({
  url: "https://agentgate.internal",
  apiKey: process.env.AGENTGATE_API_KEY,
});

await gate.register({
  agent_id: "billing-agent",
  name: "Billing agent",
  declared_purpose: "Settle approved supplier invoices",
  authorized_resources: ["/payments/*"],
  authorized_actions: ["transfer", "read"],
  allowed_destinations: ["acct_9931", "acct_4402"],
});

const payment = { amount_cents: 25_000, currency: "EUR", to: "acct_9931" };

await gate.run("transfer", "/payments/outbound", { arguments: payment }, () =>
  stripe.transfers.create(payment),
);
```

`run()` authorizes the operation, re-derives its content address from the
values it is about to pass, and calls your function only if the two agree. If
anything rewrote `payment` in between — a poisoned tool argument, a retry that
picked up different state, an ordinary bug — it throws `AgentGateBindingError`
and the transfer does not happen.

Pass **`arguments`**. What you leave out is not covered by the receipt and can
change afterwards without anything noticing; that is the confused-deputy hole,
not a detail.

### If you need the two halves apart

```ts
const decision = await gate.authorize("transfer", "/payments/outbound", {
  arguments: payment,
});

// ... anything at all happens here ...

gate.checkBinding(decision, {
  action: "transfer",
  resource: "/payments/outbound",
  arguments: payment,          // read from the variable the real call uses
});

await stripe.transfers.create(payment);
await gate.redeem(decision);   // burns the nonce, so it cannot be replayed
```

---

## Verify a receipt offline

The part that makes it evidence. No server, no account, no network — just the
receipt and the published key.

```ts
import { verifyReceipt } from "agentgate-pdp";

const result = verifyReceipt(receipt, publicKeyPem, {
  agent_id: "billing-agent",
  action: "transfer",
  resource: "/payments/outbound",
  arguments: { amount_cents: 25_000, currency: "EUR", to: "acct_9931" },
});

result.verified;          // authentic AND bound to this operation
result.signatureValid;    // Ed25519, against the published key
result.operationMatches;  // false if the receipt covers something else
result.flow;              // what the session had been exposed to
```

The interesting case is `signatureValid: true` with `operationMatches: false`.
The receipt is genuine; it simply does not authorize what you are holding it up
against. That distinction is the whole product.

Get the key from `GET /receipts/public-key`, which is unauthenticated on
purpose — someone checking evidence should not need an account with the party
being audited.

---

## Errors

| Error | When |
| --- | --- |
| `AgentGateDeniedError` | `DENY`. Thrown by default; `raiseOnDeny: false` to handle it as a value. |
| `AgentGateBindingError` | The dispatch does not match the receipt. Carries both digests. |
| `AgentGateUnboundError` | A `PERMIT` with no `action_ref`, so it binds no operation. `requireBinding: false` to accept it. |
| `AgentGateEscalatedError` | `ESCALATE`, when `raiseOnEscalate: true`. |
| `AgentGatePendingError` | `PENDING` with `autoResolvePending: false`. |
| `AgentGateUnavailableError` | The server could not be reached. |

An unreachable server is not a permit. Nothing here degrades open.

---

## Parity with the server

`action_ref` is computed twice — once by the server in Python, once here — and
the two must agree byte for byte or every dispatch check fails silently, by
refusing operations that were in fact authorized. `test/vectors.json` is
generated from the code the server runs (`npm run vectors`), and the suite
asserts this implementation reproduces it across path normalization, double
encoding, unicode, nested arguments, key ordering and numeric forms.

```bash
npm test     # 32 tests, including the vectors above
```

One known bound, shared with the Python implementation: canonicalization is a
subset of JCS (RFC 8785). The two agree on objects, arrays, strings, booleans,
null and integers, and can disagree on how some floating-point values
serialize. Keep money in minor units and quantities integral and they are
interchangeable.

---

## License

MIT. A verification layer nobody can inspect is asking for exactly the trust it
claims to make unnecessary.
