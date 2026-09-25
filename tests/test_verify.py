"""
The offline verifier.

Everything here runs the way a third party would run it: from a receipt and a
published key, with no server, no shared secret and no access to the instance
that issued it. The point of each test is that the answer cannot be faked by
whoever hands you the receipt.
"""

import json
import time

import pytest

from agentgate import verify as V
from core.receipts.receipts import receipt_signing, response_signing
from core.receipts.receipts.action_ref import compute_action_ref


OPERATION = dict(
    agent_id="pay_bot",
    action="transfer",
    resource="/payments/outbound",
    arguments={"amount_minor": 25_000, "currency": "EUR", "recipient": "acct_9931"},
)


def issue(decision="PERMIT", flow=None, ref=None, ts=None):
    """Mint a receipt the way /authorize does."""
    ref = compute_action_ref(**OPERATION) if ref is None else ref
    ts = time.time() if ts is None else ts
    flow = flow if flow is not None else {
        "confidentiality": "PUBLIC", "integrity": "TRUSTED",
        "sources": [], "untrusted_reason": "",
    }
    claim = f"{flow['confidentiality']}|{flow['integrity']}" if flow else ""
    nonce, mac = response_signing.sign_response(
        "req-1", OPERATION["agent_id"], decision, ts, ref, claim)
    canonical = response_signing.canonical_receipt_bytes(
        nonce, "req-1", OPERATION["agent_id"], decision, ts, ref, claim)
    return {
        "request_id": "req-1",
        "agent_id": OPERATION["agent_id"],
        "action": OPERATION["action"],
        "resource": OPERATION["resource"],
        "decision": decision,
        "timestamp": ts,
        "action_ref": ref,
        "response_nonce": nonce,
        "response_sig": mac,
        "receipt_sig": receipt_signing.sign(canonical),
        "key_id": receipt_signing.key_id(),
        "flow": flow,
    }


@pytest.fixture
def public_key():
    return receipt_signing.public_key_pem()


# ── The verifier reconstructs what the issuer signed ──────────────────────────

class TestCanonicalReconstruction:
    def test_the_verifier_rebuilds_the_issuer_bytes(self):
        """
        The verifier reimplements the canonical form rather than importing it,
        so the two must agree byte for byte or nothing else here is meaningful.
        """
        receipt = issue()
        mine = V.canonical_bytes(receipt)
        theirs = response_signing.canonical_receipt_bytes(
            receipt["response_nonce"], receipt["request_id"], receipt["agent_id"],
            receipt["decision"], receipt["timestamp"], receipt["action_ref"],
            "PUBLIC|TRUSTED")
        assert mine == theirs

    def test_a_receipt_with_no_flow_still_reconstructs(self):
        receipt = issue(flow={})
        assert V.canonical_bytes(receipt).endswith(b"|")


# ── Authenticity ──────────────────────────────────────────────────────────────

class TestSignature:
    def test_a_genuine_receipt_verifies(self, public_key):
        ok, detail = V.check_signature(issue(), public_key)
        assert ok, detail

    @pytest.mark.parametrize("field,value", [
        ("decision", "PERMIT"),
        ("agent_id", "someone_else"),
        ("request_id", "req-other"),
        ("action_ref", "0" * 64),
    ])
    def test_altering_any_signed_field_is_caught(self, public_key, field, value):
        receipt = issue(decision="ESCALATE")
        receipt[field] = value
        ok, _ = V.check_signature(receipt, public_key)
        assert not ok

    def test_altering_the_flow_claim_is_caught(self, public_key):
        """A receipt cannot be re-presented as if the session had been cleaner."""
        receipt = issue(flow={"confidentiality": "SECRET", "integrity": "UNTRUSTED",
                              "sources": ["/hr/pay.xlsx"], "untrusted_reason": "x"})
        receipt["flow"] = {"confidentiality": "PUBLIC", "integrity": "TRUSTED",
                           "sources": [], "untrusted_reason": ""}
        ok, _ = V.check_signature(receipt, public_key)
        assert not ok

    def test_a_different_key_does_not_verify(self, monkeypatch):
        receipt = issue()
        monkeypatch.setenv("AGENTGATE_SIGNING_KEY", "a-completely-different-secret")
        monkeypatch.setattr(receipt_signing, "_keypair", None)
        other_key = receipt_signing.public_key_pem()
        ok, detail = V.check_signature(receipt, other_key)
        assert not ok
        assert "different key" in detail or "does not match" in detail

    def test_a_receipt_without_a_public_signature_is_refused(self, public_key):
        receipt = issue()
        receipt.pop("receipt_sig")
        ok, detail = V.check_signature(receipt, public_key)
        assert not ok
        assert "no Ed25519 signature" in detail

    def test_garbage_in_place_of_a_key_is_refused(self):
        ok, _ = V.check_signature(issue(), "not a pem")
        assert not ok

    def test_the_holder_cannot_mint_one(self, public_key):
        """
        The published key verifies and nothing else. If a receipt could be
        produced from it, the signature would prove nothing about who issued it.
        """
        from cryptography.hazmat.primitives import serialization

        loaded = serialization.load_pem_public_key(public_key.encode())
        assert not hasattr(loaded, "sign")


# ── Binding: which operation, exactly ─────────────────────────────────────────

class TestOperationBinding:
    def test_the_authorized_operation_matches(self):
        matched, _ = V.check_operation(issue(), OPERATION)
        assert matched is True

    def test_a_changed_amount_does_not_match(self):
        tampered = dict(OPERATION, arguments=dict(OPERATION["arguments"],
                                                  amount_minor=2_500_000))
        matched, detail = V.check_operation(issue(), tampered)
        assert matched is False
        assert "does not authorize" in detail

    def test_a_redirected_recipient_does_not_match(self):
        tampered = dict(OPERATION, arguments=dict(OPERATION["arguments"],
                                                  recipient="acct_attacker"))
        assert V.check_operation(issue(), tampered)[0] is False

    def test_no_operation_supplied_leaves_the_binding_unchecked(self):
        matched, detail = V.check_operation(issue(), None)
        assert matched is None
        assert "not" in detail

    def test_a_receipt_binding_nothing_is_refused(self):
        matched, detail = V.check_operation(issue(ref=""), OPERATION)
        assert matched is False
        assert "no action_ref" in detail


# ── The verdict ───────────────────────────────────────────────────────────────

class TestOverallVerdict:
    def test_authentic_and_bound_is_verified(self, public_key):
        assert V.verify(issue(), public_key, OPERATION)["verified"] is True

    def test_authentic_but_unbound_operation_is_not_verified(self, public_key):
        tampered = dict(OPERATION, arguments={"amount_minor": 1})
        assert V.verify(issue(), public_key, tampered)["verified"] is False

    def test_a_forged_receipt_is_not_verified(self, public_key):
        receipt = issue(decision="ESCALATE")
        receipt["decision"] = "PERMIT"
        assert V.verify(receipt, public_key, OPERATION)["verified"] is False

    def test_signature_alone_is_enough_when_no_operation_is_claimed(self, public_key):
        """A receipt with nothing to compare still proves who issued what verdict."""
        assert V.verify(issue(), public_key, None)["verified"] is True

    def test_the_flow_state_is_reported(self, public_key):
        receipt = issue(flow={"confidentiality": "SECRET", "integrity": "UNTRUSTED",
                              "sources": ["/hr/salary.xlsx"],
                              "untrusted_reason": "external content"})
        described = " ".join(V.verify(receipt, public_key, None)["flow"])
        assert "secret" in described
        assert "untrusted" in described
        assert "/hr/salary.xlsx" in described


# ── The command line ──────────────────────────────────────────────────────────

class TestCommandLine:
    def _files(self, tmp_path, receipt, operation=None):
        (tmp_path / "receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
        (tmp_path / "key.pem").write_text(receipt_signing.public_key_pem(), encoding="utf-8")
        args = [str(tmp_path / "receipt.json"), "--public-key", str(tmp_path / "key.pem")]
        if operation is not None:
            (tmp_path / "op.json").write_text(json.dumps(operation), encoding="utf-8")
            args += ["--operation", str(tmp_path / "op.json")]
        return args

    def test_exit_zero_when_it_checks_out(self, tmp_path, capsys):
        assert V.main(self._files(tmp_path, issue(), OPERATION)) == 0
        assert "PASS" in capsys.readouterr().out

    def test_exit_one_on_a_mismatch(self, tmp_path, capsys):
        """Non-zero so this drops into a pipeline without being parsed."""
        tampered = dict(OPERATION, arguments={"amount_minor": 1})
        assert V.main(self._files(tmp_path, issue(), tampered)) == 1
        assert "FAIL" in capsys.readouterr().out

    def test_exit_one_on_a_forgery(self, tmp_path):
        receipt = issue(decision="ESCALATE")
        receipt["decision"] = "PERMIT"
        assert V.main(self._files(tmp_path, receipt)) == 1

    def test_json_output_is_machine_readable(self, tmp_path, capsys):
        args = self._files(tmp_path, issue(), OPERATION) + ["--json"]
        V.main(args)
        parsed = json.loads(capsys.readouterr().out)
        assert parsed["verified"] is True
        assert parsed["signature_valid"] is True
