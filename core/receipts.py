"""
Receipt redemption — spend an authorization exactly once.

response_signing proves a receipt came from this instance and is fresh.
action_ref proves which operation it authorizes. Neither stops the same valid
receipt being presented twice inside the freshness window, which is the
difference between resisting forgery and resisting replay. The branch that
introduced signing was honest about this in its own tests even though the
module docstring claimed otherwise; this module is what makes the claim true.

The flow it enables:

    /authorize        -> receipt (action_ref, nonce, signature)
    ... caller is about to execute ...
    /receipts/redeem  -> the nonce is spent, atomically, or the call is refused
    caller executes

Redemption is also the first record that an authorized action was actually
dispatched. An audit trail that only holds decisions can say what was allowed;
one that holds redemptions can say what was allowed *and taken*, which is the
question asked after an incident.

Storage notes
-------------
Only redeemed nonces are stored. Recording every issued nonce would double the
write cost of every decision to buy nothing: the signature already proves we
issued it, so presence in this table means "already spent" and absence means
"not yet". The PRIMARY KEY makes the check-and-mark a single atomic INSERT,
so two concurrent redemptions of one receipt cannot both win.

Rows are kept on disk rather than in memory because a process restart must not
hand an attacker a fresh window to replay into. They are prunable once past the
freshness horizon, after which the signature check rejects the receipt anyway.
"""

import sqlite3
import time

from core import audit
from core import response_signing


class RedemptionError(Exception):
    """A receipt was presented that must not be honoured."""


def _connect() -> sqlite3.Connection:
    # Read audit.DB_PATH at call time rather than import time: the path is
    # configurable and tests repoint it per module.
    conn = sqlite3.connect(audit.DB_PATH)
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_receipts_table() -> None:
    conn = _connect()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS redeemed_receipts (
                nonce       TEXT PRIMARY KEY,
                request_id  TEXT NOT NULL,
                agent_id    TEXT NOT NULL,
                action_ref  TEXT NOT NULL,
                issued_at   REAL NOT NULL,
                redeemed_at REAL NOT NULL
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_redeemed_at ON redeemed_receipts(redeemed_at)"
        )
        conn.commit()
    finally:
        conn.close()


def redeem(
    nonce: str,
    mac: str,
    request_id: str,
    agent_id: str,
    decision: str,
    timestamp: float,
    action_ref: str = "",
) -> tuple[bool, str]:
    """
    Spend a receipt. Returns (redeemed, reason).

    Refuses, in this order:
      RECEIPT_NOT_PERMIT    the receipt does not authorize anything
      <signature reason>    forged, tampered with, expired, or clock-skewed
      RECEIPT_ALREADY_SPENT this nonce was redeemed before

    The signature is checked before the store is touched so that an unsigned
    guess can never consume a nonce it did not hold, which would otherwise let
    an attacker burn legitimate receipts.
    """
    if decision.upper() != "PERMIT":
        return False, "RECEIPT_NOT_PERMIT"

    valid, reason = response_signing.verify_response(
        nonce, mac, request_id, agent_id, decision, timestamp, action_ref
    )
    if not valid:
        return False, reason

    init_receipts_table()
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO redeemed_receipts "
            "(nonce, request_id, agent_id, action_ref, issued_at, redeemed_at) "
            "VALUES (?,?,?,?,?,?)",
            (nonce, request_id, agent_id, action_ref, timestamp, time.time()),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        # PRIMARY KEY collision: someone already spent this receipt. The insert
        # is the test as well as the mark, so there is no window between them.
        return False, "RECEIPT_ALREADY_SPENT"
    finally:
        conn.close()

    return True, "OK"


def is_redeemed(nonce: str) -> bool:
    init_receipts_table()
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT 1 FROM redeemed_receipts WHERE nonce=?", (nonce,)
        ).fetchone()
    finally:
        conn.close()
    return row is not None


def get_redemption(nonce: str) -> dict | None:
    """Return the redemption record for a nonce, for audit queries."""
    init_receipts_table()
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT * FROM redeemed_receipts WHERE nonce=?", (nonce,)
        ).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def cleanup_expired(max_age_seconds: float | None = None) -> int:
    """
    Drop redemption rows past the freshness horizon and return how many went.

    Safe because a receipt older than the horizon is refused by the signature
    check before this table is ever consulted, so the row can no longer change
    any outcome.
    """
    horizon = (
        max_age_seconds
        if max_age_seconds is not None
        else response_signing.RESPONSE_MAX_AGE_SECONDS
    )
    cutoff = time.time() - horizon
    init_receipts_table()
    conn = _connect()
    try:
        cur = conn.execute("DELETE FROM redeemed_receipts WHERE issued_at < ?", (cutoff,))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()
