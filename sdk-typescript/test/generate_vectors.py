"""
Generate cross-language test vectors from the Python implementation.

    python test/generate_vectors.py

The TypeScript SDK computes action_ref independently of the server, and the two
have to agree byte for byte or every dispatch check fails — silently, by
refusing operations that were in fact authorized. Asserting that in a unit test
written against the TypeScript implementation alone proves nothing, so the
expected values come from the code the server actually runs.

Run this again whenever action_ref or the receipt canonicalization changes. A
diff in test/vectors.json is then a deliberate, reviewable statement that the
digest changed, rather than something discovered in production.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from core.receipts import action_ref as _action_ref  # noqa: E402
from core.receipts import receipt_signing as _receipt_signing  # noqa: E402
from core.receipts import response_signing as _response_signing  # noqa: E402

# Operations chosen for the places the two languages can disagree: path
# normalization, double encoding, unicode, nested structures, key ordering,
# numeric forms, and the empty case.
OPERATIONS = [
    {
        "name": "plain payment",
        "agent_id": "billing-agent",
        "action": "transfer",
        "resource": "/payments/outbound",
        "arguments": {"amount_cents": 25000, "currency": "EUR", "to": "acct_9931"},
        "policy_version": "",
    },
    {
        "name": "argument order must not matter",
        "agent_id": "billing-agent",
        "action": "transfer",
        "resource": "/payments/outbound",
        "arguments": {"to": "acct_9931", "currency": "EUR", "amount_cents": 25000},
        "policy_version": "",
    },
    {
        "name": "action is lowercased",
        "agent_id": "billing-agent",
        "action": "TRANSFER",
        "resource": "/payments/outbound",
        "arguments": {"amount_cents": 25000},
        "policy_version": "",
    },
    {
        "name": "no arguments at all",
        "agent_id": "reader",
        "action": "read",
        "resource": "/docs/readme.md",
        "arguments": None,
        "policy_version": "",
    },
    {
        "name": "traversal is normalized away",
        "agent_id": "reader",
        "action": "read",
        "resource": "/var/data/../../etc/passwd",
        "arguments": {},
        "policy_version": "",
    },
    {
        "name": "double encoding is decoded twice",
        "agent_id": "reader",
        "action": "read",
        "resource": "/var/%252e%252e/etc/passwd",
        "arguments": {},
        "policy_version": "",
    },
    {
        "name": "two leading slashes are preserved",
        "agent_id": "reader",
        "action": "read",
        "resource": "//etc/passwd",
        "arguments": {},
        "policy_version": "",
    },
    {
        "name": "three leading slashes collapse",
        "agent_id": "reader",
        "action": "read",
        "resource": "///etc/passwd",
        "arguments": {},
        "policy_version": "",
    },
    {
        "name": "relative path gains a leading slash",
        "agent_id": "reader",
        "action": "read",
        "resource": "docs/./notes//draft.md",
        "arguments": {},
        "policy_version": "",
    },
    {
        "name": "stray percent survives",
        "agent_id": "reader",
        "action": "read",
        "resource": "/reports/100%/summary",
        "arguments": {},
        "policy_version": "",
    },
    {
        "name": "invalid escape survives",
        "agent_id": "reader",
        "action": "read",
        "resource": "/files/%zz/report.txt",
        "arguments": {},
        "policy_version": "",
    },
    {
        "name": "unicode is not escaped",
        "agent_id": "agent-fr",
        "action": "send",
        "resource": "/outbox/résumé.pdf",
        "arguments": {"subject": "Café — naïve façade", "to": "élodie@example.com"},
        "policy_version": "",
    },
    {
        "name": "nested structures and mixed types",
        "agent_id": "ops",
        "action": "deploy",
        "resource": "/clusters/prod",
        "arguments": {
            "replicas": 3,
            "canary": True,
            "rollback": None,
            "targets": ["eu-west-1", "us-east-1"],
            "limits": {"cpu": "2", "memory_mb": 4096},
        },
        "policy_version": "v7",
    },
    {
        "name": "control characters in a string",
        "agent_id": "ops",
        "action": "write",
        "resource": "/logs/app.log",
        "arguments": {"line": "first\nsecond\ttabbed"},
        "policy_version": "",
    },
    {
        "name": "non-integral number",
        "agent_id": "metrics",
        "action": "record",
        "resource": "/metrics/latency",
        "arguments": {"p99_ms": 293.5, "ratio": 0.125},
        "policy_version": "",
    },
    {
        "name": "empty resource",
        "agent_id": "reader",
        "action": "read",
        "resource": "",
        "arguments": {},
        "policy_version": "",
    },
]

# Receipts, for the offline verifier. Timestamps include one that lands exactly
# on a whole second, because that is where Python's "1758888888.0" and
# JavaScript's "1758888888" part company.
RECEIPTS = [
    {
        "name": "permitted with flow",
        "request_id": "req-0001",
        "agent_id": "billing-agent",
        "decision": "PERMIT",
        "timestamp": 1758888888.1234,
        "action_ref": "",  # filled in below
        "flow": {"confidentiality": "CONFIDENTIAL", "integrity": "TRUSTED"},
    },
    {
        "name": "whole-second timestamp",
        "request_id": "req-0002",
        "agent_id": "billing-agent",
        "decision": "PERMIT",
        "timestamp": 1758888888.0,
        "action_ref": "",
        "flow": {"confidentiality": "INTERNAL", "integrity": "UNTRUSTED"},
    },
    {
        "name": "denied, no flow recorded",
        "request_id": "req-0003",
        "agent_id": "reader",
        "decision": "DENY",
        "timestamp": 1758888900.5,
        "action_ref": "",
        "flow": None,
    },
]


def main() -> int:
    operations = []
    for op in OPERATIONS:
        operations.append(
            {
                "name": op["name"],
                "operation": {
                    "agent_id": op["agent_id"],
                    "action": op["action"],
                    "resource": op["resource"],
                    "arguments": op["arguments"],
                    "policy_version": op["policy_version"],
                },
                "normalized_resource": _action_ref.normalize_resource(op["resource"]),
                "descriptor_json": _action_ref.canonical_json(
                    _action_ref.build_descriptor(
                        op["agent_id"],
                        op["action"],
                        op["resource"],
                        op["arguments"],
                        op["policy_version"],
                    )
                ),
                "action_ref": _action_ref.compute_action_ref(
                    agent_id=op["agent_id"],
                    action=op["action"],
                    resource=op["resource"],
                    arguments=op["arguments"],
                    policy_version=op["policy_version"],
                ),
            }
        )

    receipts = []
    reference_ref = operations[0]["action_ref"]
    for r in RECEIPTS:
        flow = r["flow"]
        flow_str = f"{flow['confidentiality']}|{flow['integrity']}" if flow else ""
        nonce, mac = _response_signing.sign_response(
            r["request_id"], r["agent_id"], r["decision"], r["timestamp"],
            reference_ref, flow_str,
        )
        canonical = _response_signing.canonical_receipt_bytes(
            nonce, r["request_id"], r["agent_id"], r["decision"], r["timestamp"],
            reference_ref, flow_str,
        )
        receipts.append(
            {
                "name": r["name"],
                "canonical": canonical.decode("utf-8"),
                "receipt": {
                    "request_id": r["request_id"],
                    "agent_id": r["agent_id"],
                    "decision": r["decision"],
                    "timestamp": r["timestamp"],
                    "action_ref": reference_ref,
                    "flow": flow,
                    "response_nonce": nonce,
                    "response_sig": mac,
                    "receipt_sig": _receipt_signing.sign(canonical),
                    "key_id": _receipt_signing.key_id(),
                },
            }
        )

    out = {
        "_generated_by": "test/generate_vectors.py against core/receipts/*.py",
        "_signing_key": "agentgate-dev-signing-key-change-in-production (the default)",
        "descriptor_version": _action_ref.DESCRIPTOR_VERSION,
        "public_key_pem": _receipt_signing.public_key_pem(),
        "operations": operations,
        "receipts": receipts,
        "reference_operation": operations[0]["operation"],
    }

    path = Path(__file__).resolve().parent / "vectors.json"
    path.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {path} — {len(operations)} operations, {len(receipts)} receipts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
