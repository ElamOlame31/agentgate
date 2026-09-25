"""
Tests for receipt redemption — spending an authorization exactly once.

The properties under test: a receipt is honoured once and only once, a receipt
that fails its signature check never burns the nonce it names, and the record
of redemption survives a restart.
"""

import threading
import time

import pytest

from core.receipts.receipts.receipts import receipts, response_signing
from core.receipts.receipts.receipts.action_ref import compute_action_ref


OPERATION = dict(
    agent_id="pay_bot",
    action="transfer",
    resource="/payments/outbound",
    arguments={"amount_minor": 25_000, "currency": "EUR", "recipient": "acct_9931"},
)


def issue(decision: str = "PERMIT", request_id: str = "req-1", ts: float | None = None):
    """Mint a receipt the way /authorize does, and return everything needed to redeem it."""
    ref = compute_action_ref(**OPERATION)
    timestamp = time.time() if ts is None else ts
    nonce, mac = response_signing.sign_response(
        request_id, OPERATION["agent_id"], decision, timestamp, ref
    )
    return dict(
        nonce=nonce, mac=mac, request_id=request_id,
        agent_id=OPERATION["agent_id"], decision=decision,
        timestamp=timestamp, action_ref=ref,
    )


# ── Spending once ─────────────────────────────────────────────────────────────

class TestSingleUse:
    def test_a_valid_receipt_redeems(self):
        ok, why = receipts.redeem(**issue())
        assert ok, why
        assert why == "OK"

    def test_the_same_receipt_cannot_be_redeemed_twice(self):
        """The whole point of the nonce: a replay inside the freshness window."""
        r = issue(request_id="req-twice")
        assert receipts.redeem(**r)[0]
        ok, why = receipts.redeem(**r)
        assert not ok
        assert why == "RECEIPT_ALREADY_SPENT"

    def test_distinct_receipts_for_the_same_operation_both_redeem(self):
        """Two authorizations of the same call are two rights, not one."""
        assert receipts.redeem(**issue(request_id="req-a"))[0]
        assert receipts.redeem(**issue(request_id="req-b"))[0]

    def test_redemption_is_recorded(self):
        r = issue(request_id="req-recorded")
        receipts.redeem(**r)
        assert receipts.is_redeemed(r["nonce"])
        record = receipts.get_redemption(r["nonce"])
        assert record["request_id"] == "req-recorded"
        assert record["action_ref"] == r["action_ref"]
        assert record["redeemed_at"] >= record["issued_at"]

    def test_an_unredeemed_nonce_reads_as_unspent(self):
        assert not receipts.is_redeemed(issue()["nonce"])
        assert receipts.get_redemption("never-issued") is None


# ── Refusals ──────────────────────────────────────────────────────────────────

class TestRefusals:
    def test_a_deny_receipt_authorizes_nothing(self):
        ok, why = receipts.redeem(**issue(decision="DENY"))
        assert not ok
        assert why == "RECEIPT_NOT_PERMIT"

    def test_an_escalate_receipt_authorizes_nothing(self):
        ok, why = receipts.redeem(**issue(decision="ESCALATE"))
        assert not ok
        assert why == "RECEIPT_NOT_PERMIT"

    def test_a_tampered_mac_is_refused(self):
        r = issue()
        r["mac"] = "0" * 64
        ok, why = receipts.redeem(**r)
        assert not ok
        assert why == "SIGNATURE_MISMATCH"

    def test_a_swapped_action_ref_is_refused(self):
        """A receipt for one operation cannot be spent on another."""
        r = issue()
        r["action_ref"] = compute_action_ref(
            **dict(OPERATION, arguments={"amount_minor": 9_999_999})
        )
        ok, why = receipts.redeem(**r)
        assert not ok
        assert why == "SIGNATURE_MISMATCH"

    def test_an_expired_receipt_is_refused(self):
        stale = time.time() - (response_signing.RESPONSE_MAX_AGE_SECONDS + 60)
        ok, why = receipts.redeem(**issue(ts=stale))
        assert not ok
        assert why.startswith("RESPONSE_EXPIRED")

    def test_a_receipt_from_the_future_is_refused(self):
        ahead = time.time() + (response_signing.RESPONSE_MAX_FUTURE_SKEW_SECONDS + 60)
        ok, why = receipts.redeem(**issue(ts=ahead))
        assert not ok
        assert why.startswith("RESPONSE_FROM_FUTURE")

    def test_a_failed_signature_does_not_burn_the_nonce(self):
        """
        The signature is checked before the store is touched. Otherwise anyone
        able to guess a nonce could spend it first and deny service to the agent
        actually holding the receipt.
        """
        r = issue(request_id="req-not-burned")
        forged = dict(r, mac="f" * 64)
        assert not receipts.redeem(**forged)[0]
        assert not receipts.is_redeemed(r["nonce"])
        ok, why = receipts.redeem(**r)
        assert ok, why


# ── Concurrency ───────────────────────────────────────────────────────────────

class TestConcurrency:
    def test_only_one_of_many_simultaneous_redemptions_wins(self):
        """The INSERT is both the test and the mark, so there is no race window."""
        r = issue(request_id="req-race")
        results = []
        barrier = threading.Barrier(8)

        def attempt():
            barrier.wait()
            results.append(receipts.redeem(**r)[0])

        threads = [threading.Thread(target=attempt) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert sum(results) == 1, f"expected exactly one winner, got {sum(results)}"


# ── Durability ────────────────────────────────────────────────────────────────

class TestDurability:
    def test_redemption_survives_a_reconnect(self):
        """
        Redemptions live on disk, not in memory: a restart must not hand an
        attacker a fresh window to replay into.
        """
        r = issue(request_id="req-durable")
        assert receipts.redeem(**r)[0]
        # is_redeemed opens its own connection, so this reads the persisted row
        # rather than any in-process state.
        assert receipts.is_redeemed(r["nonce"])
        assert receipts.redeem(**r)[1] == "RECEIPT_ALREADY_SPENT"


# ── Pruning ───────────────────────────────────────────────────────────────────

class TestCleanup:
    def test_expired_rows_are_pruned_and_fresh_ones_kept(self):
        fresh = issue(request_id="req-fresh")
        receipts.redeem(**fresh)

        # Write a row directly with an old issued_at: redeem() would refuse it
        # at the signature stage, which is exactly why such rows can be dropped.
        import sqlite3
        from core.platform import audit

        stale_nonce = "stale-nonce-0001"
        conn = sqlite3.connect(audit.DB_PATH)
        conn.execute(
            "INSERT INTO redeemed_receipts VALUES (?,?,?,?,?,?)",
            (stale_nonce, "req-stale", "pay_bot", "ref", time.time() - 10_000, time.time() - 10_000),
        )
        conn.commit()
        conn.close()

        removed = receipts.cleanup_expired()
        assert removed >= 1
        assert not receipts.is_redeemed(stale_nonce)
        assert receipts.is_redeemed(fresh["nonce"])
