"""
Offline receipt verifier.

    python -m agentgate.verify receipt.json --public-key agentgate.pem

Answers three questions about an agent action, with no server, no account and
no network:

    1. Did this instance really authorize it?      (Ed25519 signature)
    2. What exactly did it authorize?              (action_ref over the operation)
    3. Under what information flow?                (the labels the session carried)

The point is that none of those answers require trusting whoever hands you the
receipt. The signature is asymmetric, so the holder cannot have produced it. The
operation digest is recomputable, so "this authorized a 250 EUR payment to
acct_9931" can be checked against the payment that actually happened rather than
believed. That is the difference between a log and evidence.

Verification needs the `cryptography` package, which the SDK does not otherwise
require:

    pip install agentgate-pdp[verify]
"""

import argparse
import json
import sys
from pathlib import Path

from agentgate import action_ref as _action_ref

CANONICAL_SEP = "|"

# Mirrors core/response_signing. Duplicated rather than imported for the same
# reason action_ref is: a verifier that needs the server installed is not a
# verifier. The field order is published at GET /receipts/public-key, so a
# mismatch is detectable rather than silent.
CANONICAL_FIELDS = (
    "response_nonce", "request_id", "agent_id", "decision", "timestamp",
    "action_ref", "flow",
)


class VerificationError(Exception):
    pass


def canonical_bytes(receipt: dict) -> bytes:
    """Rebuild the exact bytes the issuer signed."""
    flow = receipt.get("flow") or {}
    flow_str = (
        f"{flow['confidentiality']}|{flow['integrity']}"
        if flow.get("confidentiality") else ""
    )
    parts = [
        receipt.get("response_nonce") or "",
        receipt.get("request_id") or "",
        receipt.get("agent_id") or "",
        (receipt.get("decision") or "").upper(),
        str(round(float(receipt.get("timestamp") or 0.0), 3)),
        receipt.get("action_ref") or "",
        flow_str,
    ]
    return CANONICAL_SEP.join(parts).encode("utf-8")


def check_signature(receipt: dict, public_key_pem: str) -> tuple[bool, str]:
    """Whether the receipt was issued by the holder of that key."""
    try:
        import base64

        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        raise VerificationError(
            "signature checking needs the cryptography package: "
            "pip install agentgate-pdp[verify]"
        )

    signature = receipt.get("receipt_sig")
    if not signature:
        return False, "receipt carries no Ed25519 signature"

    try:
        public = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        if not isinstance(public, Ed25519PublicKey):
            return False, "the supplied key is not an Ed25519 public key"
        public.verify(base64.b64decode(signature), canonical_bytes(receipt))
        return True, "signed by the holder of this key"
    except InvalidSignature:
        return False, "signature does not match — forged, altered, or a different key"
    except (ValueError, TypeError) as exc:
        return False, f"could not check the signature: {exc}"


def check_operation(receipt: dict, operation: dict | None) -> tuple[bool | None, str]:
    """
    Whether the receipt authorizes the operation you are asking about.

    Without an operation to compare, a receipt says only that *something* was
    authorized. Supplying what actually ran is what turns it into proof that
    this specific thing was.
    """
    if operation is None:
        return None, "no operation supplied — signature checked, binding not"

    expected = receipt.get("action_ref") or ""
    if not expected:
        return False, "receipt carries no action_ref, so it binds no operation"

    actual = _action_ref.compute_action_ref(
        agent_id=operation.get("agent_id") or receipt.get("agent_id") or "",
        action=operation.get("action") or "",
        resource=operation.get("resource") or "",
        arguments=operation.get("arguments"),
        policy_version=operation.get("policy_version") or "",
    )
    if actual == expected:
        return True, "this receipt authorizes exactly this operation"
    return False, (
        f"this receipt does not authorize that operation\n"
        f"      authorized: {expected}\n"
        f"      supplied:   {actual}"
    )


def describe_flow(receipt: dict) -> list[str]:
    """Plain sentences for what the session carried when the decision was made."""
    flow = receipt.get("flow") or {}
    if not flow:
        return ["no information-flow state recorded"]

    lines = [
        f"session had been exposed to {flow.get('confidentiality', '?').lower()} material",
        f"decision inputs were {flow.get('integrity', '?').lower()}",
    ]
    if flow.get("sources"):
        lines.append("raised by: " + ", ".join(flow["sources"][:3]))
    if flow.get("untrusted_reason"):
        lines.append("untrusted because: " + flow["untrusted_reason"])
    return lines


def verify(receipt: dict, public_key_pem: str, operation: dict | None = None) -> dict:
    """Run every check and return a structured result."""
    signed, sig_detail = check_signature(receipt, public_key_pem)
    bound, bind_detail = check_operation(receipt, operation)
    return {
        "signature_valid": signed,
        "signature_detail": sig_detail,
        "operation_matches": bound,
        "operation_detail": bind_detail,
        "decision": receipt.get("decision"),
        "agent_id": receipt.get("agent_id"),
        "request_id": receipt.get("request_id"),
        "key_id": receipt.get("key_id"),
        "flow": describe_flow(receipt),
        # A receipt is only evidence when it is authentic and binds the
        # operation in question. Either check failing makes it inadmissible.
        "verified": bool(signed) and bound is not False,
    }


def _render(result: dict) -> str:
    ok = "PASS" if result["verified"] else "FAIL"
    lines = [
        f"  {ok}",
        "",
        f"  decision      {result['decision']}",
        f"  agent         {result['agent_id']}",
        f"  request       {result['request_id']}",
        f"  signing key   {result['key_id']}",
        "",
        f"  signature     {'valid' if result['signature_valid'] else 'INVALID'}"
        f" — {result['signature_detail']}",
    ]
    if result["operation_matches"] is None:
        lines.append(f"  binding       not checked — {result['operation_detail']}")
    elif result["operation_matches"]:
        lines.append(f"  binding       matches — {result['operation_detail']}")
    else:
        lines.append(f"  binding       MISMATCH — {result['operation_detail']}")
    lines.append("")
    lines.append("  information flow")
    lines.extend(f"    {line}" for line in result["flow"])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agentgate.verify",
        description="Check an AgentGate receipt offline.",
    )
    parser.add_argument("receipt", type=Path, help="receipt JSON, as returned by /authorize")
    parser.add_argument("--public-key", type=Path, required=True,
                        help="PEM from GET /receipts/public-key")
    parser.add_argument("--operation", type=Path,
                        help="JSON of the operation that actually ran, to check the binding")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
    public_key = args.public_key.read_text(encoding="utf-8")
    operation = (
        json.loads(args.operation.read_text(encoding="utf-8"))
        if args.operation else None
    )

    try:
        result = verify(receipt, public_key, operation)
    except VerificationError as exc:
        print(f"  FAIL\n\n  {exc}", file=sys.stderr)
        return 2

    print(json.dumps(result, indent=2) if args.json else _render(result))
    # Non-zero on failure so this drops into a pipeline without being parsed.
    return 0 if result["verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
