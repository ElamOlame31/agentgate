# AgentGate

**Proof that an agent action was authorized — checkable by someone who wasn't there.**

```bash
pip install agentgate-pdp
```

Your agent asks before it acts. It gets back a receipt: who authorized this,
what exactly, and under what information flow. An auditor verifies it offline,
with a public key, without an account and without being able to forge one.

```
$ python -m agentgate.verify receipt.json --public-key agentgate.pem \
                             --operation what_actually_ran.json

  PASS
  decision      PERMIT
  signature     valid — signed by the holder of this key
  binding       matches — this receipt authorizes exactly this operation

  information flow
    session had been exposed to public material
    decision inputs were trusted
```

Change the amount after authorization and the same command says:

```
  FAIL
  binding       MISMATCH — this receipt does not authorize that operation
      authorized: 0d1bbad7c9fd3ff1…
      supplied:   e3af41c88f0b6ae9…
```

---

## Why a receipt and not a log

A log says an action happened. It is written by the system being questioned,
after the fact, and anyone holding it could have written it.

A receipt is sealed **before** the action, binds the exact operation, and is
signed with a key its holder does not have. That is the difference between *we
say this was fine* and *check it yourself*.

Three things make it work:

**The operation is bound.** `action_ref` is a digest over the agent, the action,
the resource, **every material argument**, and the policy version. A decision
that only names a request id proves who decided and when — it does not prove
*what* was decided, so nothing stops that verdict being spent on a different
operation. This is [Loopjacking](https://arxiv.org/abs/2609.21081), reproduced
in September 2026 against Agno AgentOS and LangGraph Agent Server.

**The signature is asymmetric.** An HMAC authenticates a receipt to whoever
holds the shared secret — which would let an auditor mint receipts. Symmetric
signing can only offer *trust us, or become us*. Receipts carry Ed25519, and the
public key is served unauthenticated: a verifier is usually not a customer.

**The flow is part of the claim.** The receipt records what the session had been
exposed to and whether anything the agent did not author influenced the
decision. Rewriting that to look cleaner invalidates the signature.

---

## Information flow, not just policy

A policy engine answers *may this action run*. What stops exfiltration is *may
this data reach this destination*.

```
read   /hr/salary_2026.xlsx        →  PERMIT      watermark rises to SECRET
export /public/summary.pdf         →  DENY        SECRET_TO_PUBLIC
```

```
read   /tickets/1234.txt           →  PERMIT      integrity → UNTRUSTED
send   to customer@ourcompany.com  →  allowed     destination was declared
send   to attacker@evil.com        →  DENY        UNDECLARED_DESTINATION
```

The second case is the prompt-injection path: a poisoned ticket cannot
re-address the reply, because once a session carries content the agent did not
author, the agent no longer chooses where data goes — only destinations declared
before that content arrived still count.

This follows [CaMeL](https://arxiv.org/abs/2503.18813) (Google DeepMind, SaTML
2026) and [FIDES](https://github.com/microsoft/fides) (Microsoft). Both enforce
from **inside** the agent — CaMeL owns an interpreter, FIDES is framework
middleware. AgentGate is reached over HTTP and never sees the agent's variables,
so it enforces at session granularity instead of value granularity, and says so:
[docs/information-flow.md](docs/information-flow.md) states the limits.

Neither of them emits a receipt. That is the part nobody had built.

---

## Integrating

```python
from agentgate import AgentGate

gate = AgentGate("http://localhost:8000", api_key="your-key")
gate.register(
    agent_id="pay_bot",
    name="PayBot",
    declared_purpose="Send approved supplier payments to known accounts",
    authorized_resources=["/payments/*"],
    authorized_actions=["transfer"],
    allowed_destinations=["/payments/*"],
)

@gate.guard("transfer", resource_arg="account")
def transfer(account: str, amount_minor: int, recipient: str):
    ...
```

One decorator. On every call it authorizes with **every argument**, recomputes
the digest locally before dispatch, spends the receipt, then runs the body. If
anything changed in between, the body does not run.

Binding every argument is the default because the alternative is the bug. A
`transfer(account, amount, recipient)` guarded only on `account` authorizes any
amount to anyone — the confused-deputy gap
[arXiv 2606.28679](https://arxiv.org/html/2606.28679) pins on LangChain,
LlamaIndex and the Stripe Agent Toolkit. An argument that cannot be serialized
raises rather than being dropped quietly; name it in `exclude=(...)` to state
that it cannot affect what the call does.

---

## What else is in the box

A weighted trust score across identity, delegation chain, purpose alignment and
behaviour. Kill-chain detection across a 24-hour session. Prompt-injection
scanning. Quarantine, delegation-chain contagion, human-in-the-loop approval,
an HMAC-chained audit log with Merkle batching, PDF/CSV export, Splunk and
Sentinel connectors, and toolkits for LangChain, LangGraph, AutoGen, the OpenAI
Agents SDK and the Vercel AI SDK.

These are **heuristics**, and the code says so — `core/detection/` carries that
in its package docstring. They catch what a lattice cannot see: a sequence of
individually legitimate reads, an instruction hidden in a document. They are
also arguable, occasionally wrong, and not what the product rests on.

---

## Honest limits

- **One process, one SQLite file.** No HA, no horizontal scale. Fine for
  consequential actions — money, deletion, export — not for mediating every call
  a high-volume agent makes.
- **130 ms median** on `/authorize` over HTTP, 181 ms end to end with
  redemption. Dominated by the embedding computed for purpose alignment.
- **Session-grained flow, not value-grained.** The watermark bounds what an
  agent *could* have seen, not what it used. It over-approximates; declared
  destinations are the escape.
- **Canonicalization is a subset of JCS**, not JCS. Integers and strings agree;
  some floats may not. Keep money in minor units.
- **No published npm package yet**, despite what older docs said. Python only.

---

## Docs

| | |
|---|---|
| [docs/receipts.md](docs/receipts.md) | the receipt format, signing, redemption, verifying |
| [docs/information-flow.md](docs/information-flow.md) | the lattices, the two rules, the limits |
| [docs/architecture.md](docs/architecture.md) | where the code lives, the request path, state |
| [docs/threat-model.md](docs/threat-model.md) | MITRE ATLAS mapping, control by control |
| [docs/quickstart.md](docs/quickstart.md) | five-minute integration |

---

## Running it

```bash
cp .env.example .env     # set AGENTGATE_API_KEY and AGENTGATE_SIGNING_KEY
pip install -r requirements.txt
python run.py            # dashboard at http://localhost:8000
pytest -q                # 872 tests
```

Set `AGENTGATE_SIGNING_KEY` and `AGENTGATE_LOG_KEY` explicitly. On the defaults
every deployment shares a signing identity, and a rotated log key makes every
prior audit entry fail verification — indistinguishable from tampering to
whoever reads the trail later.

---

MIT. Built by [Elam Olame Mugabo](https://elamolamemugabo.com) ·
[tryagentgate.com](https://tryagentgate.com)
