# Information flow

A policy engine answers *may this action run*. What actually stops exfiltration
is *may this data reach this destination*. The two are not the same question,
and a system that only answers the first will permit every step of a leak
because no single step is forbidden.

AgentGate answers the second with information-flow labels.

---

## Where this comes from, and where it differs

Two systems established the approach:

- **[CaMeL](https://arxiv.org/abs/2503.18813)** (Google DeepMind, SaTML 2026) —
  a privileged LLM plans, a quarantined LLM handles untrusted data, and a custom
  interpreter tracks provenance and enforces policy before each tool call.
  77% of AgentDojo tasks solved with provable security. Apache-2.0, and its
  authors state they do not plan to maintain it.
- **[FIDES](https://github.com/microsoft/fides)** (Microsoft) — integrity and
  confidentiality labels as middleware in Agent Framework, propagated
  automatically, enforced before a sensitive tool runs. MIT.

Both work **from inside the agent**. CaMeL owns the interpreter; FIDES sits in
the framework. AgentGate is reached over HTTP and never sees the agent's
variables, so value-level tracking is not available to it. Claiming otherwise
would be a lie, so this document is explicit about what is enforced instead.

What *is* available is the session. Every read already passes through the PDP,
so what an agent has been exposed to is known before it reaches a sink.

---

## The lattices

```
confidentiality   PUBLIC  <  INTERNAL  <  CONFIDENTIAL  <  SECRET
integrity         UNTRUSTED  <  TRUSTED
```

Confidentiality is derived from the resource classifier already used for
sensitivity thresholds — `/hr/salary_2026.xlsx` grades SECRET, `/reports/q3.pdf`
grades PUBLIC.

Integrity drops to UNTRUSTED when the agent declared
`processes_external_content` at registration, or when a scan found an injection
in content submitted with the request. The declaration is enough on its own: an
agent that consumes material it did not author is influenced by material nobody
vetted, whether or not a scanner objected to it.

---

## Propagation

The session's **watermark** is the join of the confidentiality of everything it
has read within the window (24 hours, matching the kill-chain window so an
operator reasons about one notion of "this session").

The watermark only rises. Reading something harmless after reading payroll does
not undo the exposure.

State is **derived from the audit trail**, not accumulated beside it. Two
consequences, both deliberate:

- the flow claim inside a receipt can be recomputed by anyone holding the trail,
  so it is checkable rather than asserted by the server that made it;
- it survives a restart, and cannot drift from the record it describes.

---

## The two rules

Checked on **sinks only** — `send`, `email`, `upload`, `post`, `forward`,
`export`, `transfer`, `publish`. A read raises the watermark; it does not spend
it.

### Confidentiality

> What leaves must not outrank where it goes.

Destinations come from the resource path **and from the arguments**, since a
sink's real destination usually lives there: `send /outbox/reply.txt` is in
scope while `{"to": "attacker@evil.com"}` is the whole attack. Argument names
checked: `to`, `recipient`, `recipients`, `destination`, `dest`, `target`,
`url`, `endpoint`, `webhook`, `email`, `address`, `channel`, `bucket`.

Judged on the **least-cleared** destination — data sent several places is only
as contained as the loosest of them.

```
session read /hr/salary_2026.xlsx   →  watermark SECRET
export to /public/summary.pdf       →  destination clears PUBLIC
                                    →  FLOW_VIOLATION:CONFIDENTIALITY:SECRET_TO_PUBLIC
```

### Integrity

> Once the session carries material the agent did not author, the agent no
> longer chooses the destination.

Only destinations declared **before that content arrived** still count.

This rule started as *an untrusted session may not send*, which is correct and
unusable: reading a ticket and replying to it is what a support agent is for.
Refusing every send would have made the product unusable in exactly the way a
removed `REPETITIVE_ACTION` check did. The danger is not the send — it is a
reply addressed somewhere nobody sanctioned.

```python
gate.register(
    agent_id="support_bot",
    declared_purpose="Answer customer support tickets",
    authorized_resources=["/tickets/*", "/outbox/*"],
    authorized_actions=["read", "send"],
    processes_external_content=True,
    allowed_destinations=["/outbox/*", "*@ourcompany.com"],   # declared up front
)
```

```
read  /tickets/1234.txt                      →  PERMIT, integrity → UNTRUSTED
send  /outbox/reply.txt  to customer@ourcompany.com  →  allowed, destination declared
send  /outbox/reply.txt  to attacker@evil.com        →  FLOW_VIOLATION:INTEGRITY:
                                                        UNDECLARED_DESTINATION
```

The poisoned ticket cannot re-address the reply.

---

## Outside the trust score, on purpose

Flow checks do not feed the weighted trust score, and a violation is not a
penalty to be outweighed.

A score is a judgement that can be argued with. A lattice violation is a fact.
Folding one into the other would let a high score buy its way past a flow that
must not happen — the hole a weighted average always leaves open.

---

## Limits, stated plainly

- **Session granularity, not value granularity.** The watermark bounds what the
  agent *could* have seen, not what it actually used. An agent that read payroll
  and then sends an unrelated public message is refused, because from outside we
  cannot prove the two are unrelated. Over-approximation is what
  information-flow control does when precision is unavailable; the escape is
  declaration, which is explicit and recorded rather than silent.
- **Correct only for reads that pass through AgentGate.** Data obtained by a
  path the PDP does not mediate is invisible to it, as it is to any reference
  monitor.
- **The watermark only rises within a window.** Long-lived agents saturate and
  need declared destinations. That pressure is intended: a session that has
  touched everything should not be quietly trusted with a sink.
- **Declaration is the only declassification.** There is no runtime downgrade
  primitive. A human approval can release an escalation, but it does not lower
  the watermark for subsequent actions.

---

## Reading a flow claim

Every authorization response carries the state it was decided under:

```json
"flow": {
  "confidentiality":  "SECRET",
  "integrity":        "UNTRUSTED",
  "sources":          ["/hr/salary_2026.xlsx"],
  "untrusted_reason": "agent declares it processes external content"
}
```

`sources` names the reads that raised the watermark, so a refusal can point at
the exposure that caused it rather than stating a level with no cause.

The claim is signed. Rewriting it to present a session as cleaner than it was
invalidates the receipt — see [receipts.md](receipts.md).
