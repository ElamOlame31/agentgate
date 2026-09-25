"""
Stdlib-only tests for core/response_signing.py.

Tests cover the full public API: sign_response, verify_response,
get_signing_info, plus internal helpers (_canonical_bytes, _compute_mac).
No external dependencies — runs in environments without pydantic/fastapi.
"""

import hashlib
import hmac as _hmac
import os
import sys
import time
import unittest
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.response_signing as rs


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_response(
    decision: str = "PERMIT",
    ts: float | None = None,
) -> tuple[str, str, str, str, float]:
    """Return (request_id, agent_id, decision, nonce, timestamp) for signing."""
    return (
        str(uuid.uuid4()),
        "test_agent",
        decision,
        str(uuid.uuid4()),
        ts if ts is not None else time.time(),
    )


# ── TestSignAndVerify ─────────────────────────────────────────────────────────

class TestSignAndVerify(unittest.TestCase):
    """Round-trip: sign_response → verify_response must pass."""

    def test_permit_round_trip(self):
        request_id = str(uuid.uuid4())
        ts = time.time()
        nonce, mac = rs.sign_response(request_id, "agent_a", "PERMIT", ts)
        ok, reason = rs.verify_response(nonce, mac, request_id, "agent_a", "PERMIT", ts)
        self.assertTrue(ok)
        self.assertEqual(reason, "OK")

    def test_deny_round_trip(self):
        request_id = str(uuid.uuid4())
        ts = time.time()
        nonce, mac = rs.sign_response(request_id, "agent_b", "DENY", ts)
        ok, reason = rs.verify_response(nonce, mac, request_id, "agent_b", "DENY", ts)
        self.assertTrue(ok)
        self.assertEqual(reason, "OK")

    def test_escalate_round_trip(self):
        request_id = str(uuid.uuid4())
        ts = time.time()
        nonce, mac = rs.sign_response(request_id, "agent_c", "ESCALATE", ts)
        ok, reason = rs.verify_response(nonce, mac, request_id, "agent_c", "ESCALATE", ts)
        self.assertTrue(ok)
        self.assertEqual(reason, "OK")

    def test_pending_round_trip(self):
        request_id = str(uuid.uuid4())
        ts = time.time()
        nonce, mac = rs.sign_response(request_id, "agent_d", "PENDING", ts)
        ok, reason = rs.verify_response(nonce, mac, request_id, "agent_d", "PENDING", ts)
        self.assertTrue(ok)
        self.assertEqual(reason, "OK")

    def test_nonce_is_uuid4(self):
        request_id = str(uuid.uuid4())
        ts = time.time()
        nonce, _ = rs.sign_response(request_id, "agent_a", "PERMIT", ts)
        # UUID4: 36 chars, 4 dashes, starts with 8-4-4-4-12 pattern
        self.assertEqual(len(nonce), 36)
        self.assertEqual(nonce.count("-"), 4)

    def test_nonce_is_unique_per_call(self):
        request_id = str(uuid.uuid4())
        ts = time.time()
        nonce1, _ = rs.sign_response(request_id, "agent_a", "PERMIT", ts)
        nonce2, _ = rs.sign_response(request_id, "agent_a", "PERMIT", ts)
        self.assertNotEqual(nonce1, nonce2)

    def test_mac_is_64_hex_chars(self):
        request_id = str(uuid.uuid4())
        ts = time.time()
        _, mac = rs.sign_response(request_id, "agent_a", "PERMIT", ts)
        self.assertEqual(len(mac), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in mac))

    def test_different_request_ids_give_different_macs(self):
        ts = time.time()
        _, mac1 = rs.sign_response(str(uuid.uuid4()), "agent", "PERMIT", ts)
        _, mac2 = rs.sign_response(str(uuid.uuid4()), "agent", "PERMIT", ts)
        self.assertNotEqual(mac1, mac2)

    def test_same_inputs_different_nonces_give_different_macs(self):
        request_id = str(uuid.uuid4())
        ts = time.time()
        _, mac1 = rs.sign_response(request_id, "agent", "PERMIT", ts)
        _, mac2 = rs.sign_response(request_id, "agent", "PERMIT", ts)
        # Different nonces → different MACs even for identical other fields
        self.assertNotEqual(mac1, mac2)


# ── TestTamperedFields ────────────────────────────────────────────────────────

class TestTamperedFields(unittest.TestCase):
    """Any field change must invalidate the MAC."""

    def setUp(self):
        self.request_id = str(uuid.uuid4())
        self.ts = time.time()
        self.nonce, self.mac = rs.sign_response(
            self.request_id, "original_agent", "PERMIT", self.ts
        )

    def test_tampered_request_id(self):
        ok, reason = rs.verify_response(
            self.nonce, self.mac, str(uuid.uuid4()),
            "original_agent", "PERMIT", self.ts,
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "SIGNATURE_MISMATCH")

    def test_tampered_agent_id(self):
        ok, reason = rs.verify_response(
            self.nonce, self.mac, self.request_id,
            "attacker_agent", "PERMIT", self.ts,
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "SIGNATURE_MISMATCH")

    def test_tampered_decision(self):
        ok, reason = rs.verify_response(
            self.nonce, self.mac, self.request_id,
            "original_agent", "DENY", self.ts,
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "SIGNATURE_MISMATCH")

    def test_tampered_timestamp(self):
        ok, reason = rs.verify_response(
            self.nonce, self.mac, self.request_id,
            "original_agent", "PERMIT", self.ts + 1.0,
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "SIGNATURE_MISMATCH")

    def test_tampered_nonce(self):
        ok, reason = rs.verify_response(
            str(uuid.uuid4()), self.mac, self.request_id,
            "original_agent", "PERMIT", self.ts,
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "SIGNATURE_MISMATCH")

    def test_tampered_mac_single_char(self):
        # Flip one hex digit in the MAC
        bad_mac = ("f" if self.mac[0] != "f" else "0") + self.mac[1:]
        ok, reason = rs.verify_response(
            self.nonce, bad_mac, self.request_id,
            "original_agent", "PERMIT", self.ts,
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "SIGNATURE_MISMATCH")

    def test_empty_mac(self):
        ok, reason = rs.verify_response(
            self.nonce, "", self.request_id,
            "original_agent", "PERMIT", self.ts,
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "SIGNATURE_MISMATCH")


# ── TestDecisionCaseInsensitivity ─────────────────────────────────────────────

class TestDecisionCaseInsensitivity(unittest.TestCase):
    """Decision is uppercased before signing, so case variants must verify."""

    def test_lowercase_decision_sign_uppercase_verify(self):
        request_id = str(uuid.uuid4())
        ts = time.time()
        nonce, mac = rs.sign_response(request_id, "agent", "permit", ts)
        ok, reason = rs.verify_response(nonce, mac, request_id, "agent", "PERMIT", ts)
        self.assertTrue(ok)
        self.assertEqual(reason, "OK")

    def test_uppercase_sign_lowercase_verify(self):
        request_id = str(uuid.uuid4())
        ts = time.time()
        nonce, mac = rs.sign_response(request_id, "agent", "DENY", ts)
        ok, reason = rs.verify_response(nonce, mac, request_id, "agent", "deny", ts)
        self.assertTrue(ok)
        self.assertEqual(reason, "OK")


# ── TestExpiry ────────────────────────────────────────────────────────────────

class TestExpiry(unittest.TestCase):
    """Expired and future-dated responses must be rejected."""

    def test_expired_response_rejected(self):
        request_id = str(uuid.uuid4())
        stale_ts = time.time() - (rs.RESPONSE_MAX_AGE_SECONDS + 10)
        nonce, mac = rs.sign_response(request_id, "agent", "PERMIT", stale_ts)
        ok, reason = rs.verify_response(nonce, mac, request_id, "agent", "PERMIT", stale_ts)
        self.assertFalse(ok)
        self.assertIn("RESPONSE_EXPIRED", reason)
        self.assertIn("max=", reason)

    def test_expired_reason_contains_age(self):
        request_id = str(uuid.uuid4())
        stale_ts = time.time() - (rs.RESPONSE_MAX_AGE_SECONDS + 60)
        nonce, mac = rs.sign_response(request_id, "agent", "PERMIT", stale_ts)
        _, reason = rs.verify_response(nonce, mac, request_id, "agent", "PERMIT", stale_ts)
        self.assertIn("age=", reason)

    def test_future_response_rejected(self):
        request_id = str(uuid.uuid4())
        future_ts = time.time() + rs.RESPONSE_MAX_FUTURE_SKEW_SECONDS + 10
        nonce, mac = rs.sign_response(request_id, "agent", "PERMIT", future_ts)
        ok, reason = rs.verify_response(nonce, mac, request_id, "agent", "PERMIT", future_ts)
        self.assertFalse(ok)
        self.assertIn("RESPONSE_FROM_FUTURE", reason)

    def test_fresh_response_is_accepted(self):
        request_id = str(uuid.uuid4())
        ts = time.time()
        nonce, mac = rs.sign_response(request_id, "agent", "PERMIT", ts)
        ok, _ = rs.verify_response(nonce, mac, request_id, "agent", "PERMIT", ts)
        self.assertTrue(ok)

    def test_exactly_at_max_age_boundary_is_rejected(self):
        request_id = str(uuid.uuid4())
        ts = time.time() - rs.RESPONSE_MAX_AGE_SECONDS - 0.001
        nonce, mac = rs.sign_response(request_id, "agent", "PERMIT", ts)
        ok, _ = rs.verify_response(nonce, mac, request_id, "agent", "PERMIT", ts)
        self.assertFalse(ok)

    def test_within_max_age_boundary_is_accepted(self):
        request_id = str(uuid.uuid4())
        ts = time.time() - (rs.RESPONSE_MAX_AGE_SECONDS - 1)
        nonce, mac = rs.sign_response(request_id, "agent", "PERMIT", ts)
        ok, _ = rs.verify_response(nonce, mac, request_id, "agent", "PERMIT", ts)
        self.assertTrue(ok)

    def test_small_positive_skew_accepted(self):
        """Responses timestamped up to RESPONSE_MAX_FUTURE_SKEW_SECONDS ahead are OK."""
        request_id = str(uuid.uuid4())
        future_ts = time.time() + rs.RESPONSE_MAX_FUTURE_SKEW_SECONDS - 0.5
        nonce, mac = rs.sign_response(request_id, "agent", "PERMIT", future_ts)
        ok, _ = rs.verify_response(nonce, mac, request_id, "agent", "PERMIT", future_ts)
        self.assertTrue(ok)


# ── TestConstants ─────────────────────────────────────────────────────────────

class TestConstants(unittest.TestCase):
    """Module constants must be within sensible bounds."""

    def test_max_age_is_positive(self):
        self.assertGreater(rs.RESPONSE_MAX_AGE_SECONDS, 0)

    def test_max_age_is_at_least_60_seconds(self):
        self.assertGreaterEqual(rs.RESPONSE_MAX_AGE_SECONDS, 60)

    def test_max_age_does_not_exceed_one_day(self):
        self.assertLessEqual(rs.RESPONSE_MAX_AGE_SECONDS, 86_400)

    def test_future_skew_is_positive(self):
        self.assertGreater(rs.RESPONSE_MAX_FUTURE_SKEW_SECONDS, 0)

    def test_future_skew_is_small(self):
        self.assertLessEqual(rs.RESPONSE_MAX_FUTURE_SKEW_SECONDS, 60)

    def test_canonical_sep_is_single_char(self):
        self.assertEqual(len(rs.CANONICAL_SEP), 1)

    def test_signing_key_is_32_bytes(self):
        self.assertEqual(len(rs._RESPONSE_SIGN_KEY), 32)

    def test_signing_key_is_bytes(self):
        self.assertIsInstance(rs._RESPONSE_SIGN_KEY, bytes)


# ── TestDomainSeparation ──────────────────────────────────────────────────────

class TestDomainSeparation(unittest.TestCase):
    """Signing key must differ from the Ed25519 token seed and the audit HMAC key."""

    def _token_seed(self) -> bytes:
        """Reproduce the token.py key derivation (SHA-256 of env var)."""
        base = os.getenv(
            "AGENTGATE_SIGNING_KEY",
            "agentgate-dev-signing-key-change-in-production",
        ).encode("utf-8")
        return hashlib.sha256(base).digest()

    def _audit_key(self) -> bytes:
        """Reproduce the audit.py HMAC key (raw env var bytes)."""
        return os.getenv("AGENTGATE_LOG_KEY", "agentgate-log-integrity-default").encode()

    def test_response_key_differs_from_token_seed(self):
        self.assertNotEqual(rs._RESPONSE_SIGN_KEY, self._token_seed())

    def test_response_key_differs_from_audit_key(self):
        self.assertNotEqual(rs._RESPONSE_SIGN_KEY, self._audit_key())

    def test_different_env_var_gives_different_key(self):
        original = os.environ.get("AGENTGATE_SIGNING_KEY")
        try:
            os.environ["AGENTGATE_SIGNING_KEY"] = "changed-key-for-test-only"
            new_key = rs._build_signing_key()
            self.assertNotEqual(new_key, rs._RESPONSE_SIGN_KEY)
        finally:
            if original is None:
                os.environ.pop("AGENTGATE_SIGNING_KEY", None)
            else:
                os.environ["AGENTGATE_SIGNING_KEY"] = original


# ── TestSigningInfo ───────────────────────────────────────────────────────────

class TestSigningInfo(unittest.TestCase):
    """get_signing_info() must return well-formed metadata."""

    def setUp(self):
        self.info = rs.get_signing_info()

    def test_returns_dict(self):
        self.assertIsInstance(self.info, dict)

    def test_algorithm_is_hmac_sha256(self):
        self.assertEqual(self.info["algorithm"], "HMAC-SHA256")

    def test_key_id_present_and_16_chars(self):
        self.assertIn("key_id", self.info)
        self.assertEqual(len(self.info["key_id"]), 16)

    def test_key_id_is_hex(self):
        self.assertTrue(all(c in "0123456789abcdef" for c in self.info["key_id"]))

    def test_max_age_matches_constant(self):
        self.assertEqual(self.info["max_age_seconds"], rs.RESPONSE_MAX_AGE_SECONDS)

    def test_canonical_fields_present(self):
        fields = self.info["canonical_fields"]
        self.assertIn("nonce", fields)
        self.assertIn("request_id", fields)
        self.assertIn("agent_id", fields)
        self.assertIn("decision", fields)
        self.assertIn("timestamp", fields)

    def test_canonical_sep_present(self):
        self.assertEqual(self.info["canonical_sep"], rs.CANONICAL_SEP)

    def test_no_secret_material(self):
        info_str = str(self.info)
        # Key itself must not appear in any value
        key_hex = rs._RESPONSE_SIGN_KEY.hex()
        self.assertNotIn(key_hex, info_str)

    def test_key_id_stable_across_calls(self):
        info2 = rs.get_signing_info()
        self.assertEqual(self.info["key_id"], info2["key_id"])


# ── TestCanonicalBytes ────────────────────────────────────────────────────────

class TestCanonicalBytes(unittest.TestCase):
    """Internal canonical encoding must produce consistent, well-formed output."""

    def test_returns_bytes(self):
        result = rs._canonical_bytes("n", "r", "a", "PERMIT", 1.0)
        self.assertIsInstance(result, bytes)

    def test_canonical_contains_all_fields(self):
        result = rs._canonical_bytes("my_nonce", "req_id", "agent_x", "DENY", 1234567890.123)
        decoded = result.decode("utf-8")
        self.assertIn("my_nonce", decoded)
        self.assertIn("req_id", decoded)
        self.assertIn("agent_x", decoded)
        self.assertIn("DENY", decoded)
        self.assertIn("1234567890.123", decoded)

    def test_timestamp_rounded_to_3dp(self):
        result = rs._canonical_bytes("n", "r", "a", "PERMIT", 1234567890.123456)
        decoded = result.decode("utf-8")
        # str(round(1234567890.123456, 3)) = "1234567890.123"
        self.assertIn("1234567890.123", decoded)
        self.assertNotIn("1234567890.1234", decoded)

    def test_fields_joined_by_sep(self):
        # nonce | request_id | agent_id | decision | timestamp | action_ref.
        # action_ref joined the canonical string when the MAC started binding
        # the operation and not only the verdict; it is last so that a receipt
        # issued before it existed still verifies with an empty value.
        result = rs._canonical_bytes("n", "r", "a", "PERMIT", 1.0, "ref")
        decoded = result.decode("utf-8")
        parts = decoded.split(rs.CANONICAL_SEP)
        self.assertEqual(len(parts), 6)
        self.assertEqual(parts[-1], "ref")

    def test_action_ref_defaults_to_empty_and_keeps_the_field(self):
        parts = rs._canonical_bytes("n", "r", "a", "PERMIT", 1.0).decode("utf-8").split(
            rs.CANONICAL_SEP)
        self.assertEqual(len(parts), 6)
        self.assertEqual(parts[-1], "")

    def test_a_different_action_ref_changes_the_canonical_bytes(self):
        a = rs._canonical_bytes("n", "r", "a", "PERMIT", 1.0, "ref-one")
        b = rs._canonical_bytes("n", "r", "a", "PERMIT", 1.0, "ref-two")
        self.assertNotEqual(a, b)

    def test_decision_is_uppercased(self):
        lower = rs._canonical_bytes("n", "r", "a", "permit", 1.0)
        upper = rs._canonical_bytes("n", "r", "a", "PERMIT", 1.0)
        self.assertEqual(lower, upper)


# ── TestReplayPrevention ──────────────────────────────────────────────────────

class TestReplayPrevention(unittest.TestCase):
    """Replaying a valid (nonce, mac) pair from the same response must still verify
    (the nonce uniqueness property is upheld by the caller storing seen nonces —
    this module ensures the nonce is bound to the MAC so forging a replay with a
    new nonce but old MAC is impossible)."""

    def test_same_nonce_mac_replayed_verifies_within_window(self):
        """Server-side nonce dedup is the caller's responsibility; the MAC itself is valid."""
        request_id = str(uuid.uuid4())
        ts = time.time()
        nonce, mac = rs.sign_response(request_id, "agent", "PERMIT", ts)
        ok1, _ = rs.verify_response(nonce, mac, request_id, "agent", "PERMIT", ts)
        ok2, _ = rs.verify_response(nonce, mac, request_id, "agent", "PERMIT", ts)
        self.assertTrue(ok1)
        self.assertTrue(ok2)  # module doesn't track seen nonces — caller must

    def test_swapped_nonces_between_two_responses_fails(self):
        """A nonce from one response cannot be swapped into another."""
        ts = time.time()
        rid1, rid2 = str(uuid.uuid4()), str(uuid.uuid4())
        nonce1, mac1 = rs.sign_response(rid1, "agent", "PERMIT", ts)
        nonce2, mac2 = rs.sign_response(rid2, "agent", "DENY", ts)
        # Swap nonces
        ok, reason = rs.verify_response(nonce2, mac1, rid1, "agent", "PERMIT", ts)
        self.assertFalse(ok)
        self.assertEqual(reason, "SIGNATURE_MISMATCH")


if __name__ == "__main__":
    unittest.main()
