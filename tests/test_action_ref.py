"""
Tests for action_ref — the operation binding that closes the Loopjacking gap.

The property under test throughout: a decision issued for one operation cannot
be spent on a different one. Every material field belongs to the digest, and
only cosmetic differences (key order, an equivalent path spelling) are allowed
to collapse.
"""

import json
import time

import pytest

from core import action_ref, response_signing
from core.action_ref import ActionRefError, compute_action_ref, matches


BASE = dict(
    agent_id="pay_bot",
    action="transfer",
    resource="/payments/outbound",
    arguments={"amount_minor": 25_000, "currency": "EUR", "recipient": "acct_9931"},
)


# ── Determinism ───────────────────────────────────────────────────────────────

class TestDeterminism:
    def test_same_operation_same_ref(self):
        assert compute_action_ref(**BASE) == compute_action_ref(**BASE)

    def test_ref_is_sha256_hex(self):
        ref = compute_action_ref(**BASE)
        assert len(ref) == 64
        assert all(c in "0123456789abcdef" for c in ref)

    def test_argument_key_order_is_irrelevant(self):
        shuffled = dict(BASE, arguments={
            "recipient": "acct_9931", "currency": "EUR", "amount_minor": 25_000,
        })
        assert compute_action_ref(**shuffled) == compute_action_ref(**BASE)

    def test_nested_key_order_is_irrelevant(self):
        a = dict(BASE, arguments={"meta": {"b": 2, "a": 1}, "x": 0})
        b = dict(BASE, arguments={"x": 0, "meta": {"a": 1, "b": 2}})
        assert compute_action_ref(**a) == compute_action_ref(**b)

    def test_none_and_empty_arguments_agree(self):
        a = dict(BASE, arguments=None)
        b = dict(BASE, arguments={})
        assert compute_action_ref(**a) == compute_action_ref(**b)

    def test_action_case_is_normalized(self):
        assert compute_action_ref(**dict(BASE, action="TRANSFER")) == compute_action_ref(**BASE)


# ── Every material field is bound ─────────────────────────────────────────────

class TestMaterialFieldsAreBound:
    def test_amount_change_breaks_the_ref(self):
        tampered = dict(BASE["arguments"], amount_minor=2_500_000)
        assert compute_action_ref(**dict(BASE, arguments=tampered)) != compute_action_ref(**BASE)

    def test_recipient_redirect_breaks_the_ref(self):
        tampered = dict(BASE["arguments"], recipient="acct_attacker")
        assert compute_action_ref(**dict(BASE, arguments=tampered)) != compute_action_ref(**BASE)

    def test_dropping_an_argument_breaks_the_ref(self):
        fewer = {"amount_minor": 25_000, "currency": "EUR"}
        assert compute_action_ref(**dict(BASE, arguments=fewer)) != compute_action_ref(**BASE)

    def test_adding_an_argument_breaks_the_ref(self):
        more = dict(BASE["arguments"], memo="urgent")
        assert compute_action_ref(**dict(BASE, arguments=more)) != compute_action_ref(**BASE)

    def test_action_change_breaks_the_ref(self):
        assert compute_action_ref(**dict(BASE, action="refund")) != compute_action_ref(**BASE)

    def test_resource_change_breaks_the_ref(self):
        assert compute_action_ref(**dict(BASE, resource="/payments/internal")) != compute_action_ref(**BASE)

    def test_agent_change_breaks_the_ref(self):
        """One agent's decision must not authorize another agent's identical call."""
        assert compute_action_ref(**dict(BASE, agent_id="other_bot")) != compute_action_ref(**BASE)

    def test_policy_version_change_breaks_the_ref(self):
        a = compute_action_ref(**BASE, policy_version="2026-09-01")
        b = compute_action_ref(**BASE, policy_version="2026-09-24")
        assert a != b

    def test_string_and_numeric_amount_differ(self):
        """25000 and "25000" are different values and must not collapse."""
        as_str = dict(BASE["arguments"], amount_minor="25000")
        assert compute_action_ref(**dict(BASE, arguments=as_str)) != compute_action_ref(**BASE)


# ── Resource normalization is shared, so only real differences count ──────────

class TestResourceNormalization:
    @pytest.mark.parametrize("spelling", [
        "/payments/outbound",
        "/payments/./outbound",
        "/payments//outbound",
        "/payments/inbound/../outbound",
        "/payments/%2e/outbound",
        "payments/outbound",
    ])
    def test_equivalent_spellings_agree(self, spelling):
        assert compute_action_ref(**dict(BASE, resource=spelling)) == compute_action_ref(**BASE)

    def test_traversal_resolves_before_hashing(self):
        escaped = compute_action_ref(**dict(BASE, resource="/payments/../secrets/keys"))
        direct = compute_action_ref(**dict(BASE, resource="/secrets/keys"))
        assert escaped == direct

    def test_double_encoded_traversal_resolves(self):
        assert action_ref.normalize_resource("/payments/%252e%252e/secrets") == "/secrets"

    def test_null_bytes_are_stripped(self):
        assert action_ref.normalize_resource("/payments/out\x00bound") == "/payments/outbound"


# ── Refusals ──────────────────────────────────────────────────────────────────

class TestRefusals:
    def test_non_object_arguments_refused(self):
        with pytest.raises(ActionRefError):
            compute_action_ref(**dict(BASE, arguments=["not", "an", "object"]))

    def test_unserializable_arguments_refused(self):
        with pytest.raises(ActionRefError):
            compute_action_ref(**dict(BASE, arguments={"when": object()}))

    def test_nan_refused(self):
        """NaN has no canonical JSON form; accepting it would make the digest unstable."""
        with pytest.raises(ActionRefError):
            compute_action_ref(**dict(BASE, arguments={"amount": float("nan")}))

    def test_infinity_refused(self):
        with pytest.raises(ActionRefError):
            compute_action_ref(**dict(BASE, arguments={"amount": float("inf")}))

    def test_oversized_arguments_refused_not_truncated(self):
        """Truncating would leave everything past the cutoff unbound."""
        huge = {"blob": "x" * (action_ref.MAX_ARGUMENTS_BYTES + 1)}
        with pytest.raises(ActionRefError):
            compute_action_ref(**dict(BASE, arguments=huge))

    def test_just_under_the_limit_is_accepted(self):
        payload = "x" * (action_ref.MAX_ARGUMENTS_BYTES - 64)
        assert compute_action_ref(**dict(BASE, arguments={"blob": payload}))


# ── matches(): the dispatch-time check ────────────────────────────────────────

class TestMatches:
    def test_unchanged_operation_matches(self):
        assert matches(compute_action_ref(**BASE), **BASE)

    def test_changed_operation_does_not_match(self):
        ref = compute_action_ref(**BASE)
        tampered = dict(BASE["arguments"], recipient="acct_attacker")
        assert not matches(ref, **dict(BASE, arguments=tampered))

    def test_uncanonicalizable_operation_fails_closed(self):
        """A check that cannot be computed must read as 'no match', never raise past the caller."""
        ref = compute_action_ref(**BASE)
        assert matches(ref, **dict(BASE, arguments={"bad": object()})) is False

    def test_empty_ref_never_matches_a_real_operation(self):
        assert not matches("", **BASE)


# ── The signature binds the reference ─────────────────────────────────────────

class TestSignatureBinding:
    # Inside the freshness window, so these exercise the MAC rather than expiry.
    TS = None

    def setup_method(self):
        self.TS = time.time()

    def _sign(self, ref):
        return response_signing.sign_response("req-1", "pay_bot", "PERMIT", self.TS, ref)

    def _verify(self, nonce, mac, ref):
        return response_signing.verify_response(
            nonce, mac, "req-1", "pay_bot", "PERMIT", self.TS, ref)

    def test_signature_verifies_with_its_own_ref(self):
        ref = compute_action_ref(**BASE)
        nonce, mac = self._sign(ref)
        ok, why = self._verify(nonce, mac, ref)
        assert ok, why

    def test_swapping_the_ref_invalidates_the_signature(self):
        """The whole point: a verdict cannot be moved onto another operation."""
        nonce, mac = self._sign(compute_action_ref(**BASE))
        other = compute_action_ref(**dict(BASE, arguments={"amount_minor": 1}))
        ok, why = self._verify(nonce, mac, other)
        assert not ok
        assert why == "SIGNATURE_MISMATCH"

    def test_dropping_the_ref_invalidates_the_signature(self):
        nonce, mac = self._sign(compute_action_ref(**BASE))
        ok, _ = self._verify(nonce, mac, "")
        assert not ok

    def test_unbound_receipt_still_round_trips(self):
        """A receipt issued with no ref stays verifiable, so older clients keep working."""
        nonce, mac = self._sign("")
        ok, why = self._verify(nonce, mac, "")
        assert ok, why

    def test_signing_info_advertises_the_ref_field(self):
        assert "action_ref" in response_signing.get_signing_info()["canonical_fields"]


# ── Through the API ───────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def gate():
    """A registered payment agent, created once for the module.

    Re-registering the same agent_id returns 409 by design, so every test in
    the class below shares one registration.
    """
    from fastapi.testclient import TestClient
    from server.main import app
    import server.main as sm

    key = sm._get_api_key() or ""
    client = TestClient(app)
    headers = {"X-API-Key": key} if key else {}
    reg = client.post("/agents/register", headers=headers, json={
        "agent_id": "api_pay_bot", "name": "PayBot",
        "declared_purpose": "Send approved supplier payments to known accounts",
        "authorized_resources": ["/payments/*"],
        "authorized_actions": ["transfer"],
    })
    assert reg.status_code in (200, 201), reg.text
    return client, headers, reg.json().get("token")


class TestThroughTheAPI:
    def _authorize(self, gate, arguments):
        client, headers, token = gate
        return client.post("/authorize", headers=headers, json={
            "agent_id": "api_pay_bot", "token": token, "action": "transfer",
            "resource": "/payments/outbound", "arguments": arguments,
        }).json()

    def test_response_carries_a_ref_and_the_normalized_resource(self, gate):
        body = self._authorize(gate, BASE["arguments"])
        assert body["action_ref"]
        assert body["normalized_resource"] == "/payments/outbound"

    def test_response_ref_matches_a_locally_recomputed_one(self, gate):
        """A client must be able to reproduce the digest without the server."""
        args = BASE["arguments"]
        body = self._authorize(gate, args)
        assert matches(body["action_ref"], agent_id="api_pay_bot", action="transfer",
                       resource="/payments/outbound", arguments=args)

    def test_response_signature_covers_the_ref(self, gate):
        body = self._authorize(gate, BASE["arguments"])
        flow = body.get("flow") or {}
        claim = (f"{flow['confidentiality']}|{flow['integrity']}"
                 if flow.get("confidentiality") else "")
        ok, why = response_signing.verify_response(
            body["response_nonce"], body["response_sig"], body["request_id"],
            body["agent_id"], body["decision"], body["timestamp"],
            body["action_ref"], claim)
        assert ok, why

    def test_different_arguments_yield_different_refs(self, gate):
        a = self._authorize(gate, BASE["arguments"])
        b = self._authorize(gate, dict(BASE["arguments"], amount_minor=9_999_999))
        assert a["action_ref"] != b["action_ref"]

    def test_sealed_values_are_inside_the_audit_entry(self, gate):
        """The seal must be in the record, not only in the reply."""
        from core import audit

        body = self._authorize(gate, BASE["arguments"])
        entry = next(e for e in audit.get_recent_decisions(limit=25)
                     if e["id"] == body["request_id"])
        stored = json.loads(entry["full_json"])
        assert stored["action_ref"] == body["action_ref"]
        assert stored["response_sig"] == body["response_sig"]

    def test_request_without_arguments_still_gets_a_ref(self, gate):
        """Actions with no payload are bound on agent, action and resource alone."""
        body = self._authorize(gate, None)
        assert body["action_ref"]
        assert matches(body["action_ref"], agent_id="api_pay_bot", action="transfer",
                       resource="/payments/outbound", arguments=None)
