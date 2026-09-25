"""
Authorization response MAC (HMAC-SHA256 + nonce).

Every authorization response carries a MAC over the decision payload,
enabling the calling agent or SDK to verify:

  1. Origin — only the holder of AGENTGATE_SIGNING_KEY can produce a valid MAC.
  2. Freshness — signed_at is checked against AGENTGATE_RESPONSE_MAX_AGE (default 300 s).
  3. Replay prevention — the nonce is unique per response (UUID4).

MAC algorithm: HMAC-SHA256 over the canonical string
  nonce|request_id|agent_id|decision|str(round(timestamp, 3))
where fields are joined by "|" (CANONICAL_SEP), UTF-8 encoded.

The signing key is domain-separated from the Ed25519 token-issuance seed
and from the audit-log HMAC key so that a compromise of any one key does
not affect the others. Domain prefix: b"agentgate-response-mac|".

NSA alignment: CSI U/OO/6030316-26 (May 2026), requirement:
"Sign tool responses with a unique nonce and timestamp within a bounded
time window so the calling agent can verify origin, integrity, and
freshness, preventing spoofing, tampering, and replay."
"""

import hashlib
import hmac as _hmac
import os
import time
import uuid

CANONICAL_SEP = "|"

# Responses older than this are rejected by verify_response().
# Configurable so operators with high-latency networks can widen the window.
RESPONSE_MAX_AGE_SECONDS: int = int(os.getenv("AGENTGATE_RESPONSE_MAX_AGE", "300"))

# Maximum clock-skew tolerance: reject responses timestamped more than this
# many seconds in the future (handles minor NTP drift).
RESPONSE_MAX_FUTURE_SKEW_SECONDS: float = 5.0

_DOMAIN_PREFIX = b"agentgate-response-mac|"


def _build_signing_key() -> bytes:
    """
    Derive the HMAC key at module load time.

    SHA-256(domain_prefix + operator_secret) gives a 32-byte key that is:
    - Deterministic: same env var → same key across restarts.
    - Domain-separated: cannot equal the Ed25519 seed or the audit HMAC key.
    """
    base = os.getenv(
        "AGENTGATE_SIGNING_KEY",
        "agentgate-dev-signing-key-change-in-production",
    ).encode("utf-8")
    return hashlib.sha256(_DOMAIN_PREFIX + base).digest()


_RESPONSE_SIGN_KEY: bytes = _build_signing_key()


def _canonical_bytes(
    nonce: str,
    request_id: str,
    agent_id: str,
    decision: str,
    timestamp: float,
    action_ref: str = "",
    flow: str = "",
) -> bytes:
    """Return the canonical UTF-8 byte string over which the MAC is computed.

    action_ref binds the MAC to the operation itself. Without it the signature
    attests that this instance issued a verdict for a request id at a time —
    true, and not enough: nothing stops that verdict being spent on a different
    operation. It is appended last so that a receipt issued before this field
    existed (empty string) still verifies under the same code path.
    """
    return CANONICAL_SEP.join([
        nonce,
        request_id,
        agent_id,
        decision.upper(),
        str(round(timestamp, 3)),
        action_ref,
        flow,
    ]).encode("utf-8")


def _compute_mac(canonical: bytes, key: bytes | None = None) -> str:
    """HMAC-SHA256 hex digest. Uses module-level key when key=None."""
    k = key if key is not None else _RESPONSE_SIGN_KEY
    return _hmac.new(k, canonical, hashlib.sha256).hexdigest()


def canonical_receipt_bytes(
    nonce: str,
    request_id: str,
    agent_id: str,
    decision: str,
    timestamp: float,
    action_ref: str = "",
    flow: str = "",
) -> bytes:
    """The exact bytes both signature schemes cover.

    Public, because an offline verifier has to reconstruct them from a receipt
    without importing anything that holds a secret.
    """
    return _canonical_bytes(
        nonce, request_id, agent_id, decision, timestamp, action_ref, flow
    )


def sign_response(
    request_id: str,
    agent_id: str,
    decision: str,
    timestamp: float,
    action_ref: str = "",
    flow: str = "",
) -> tuple[str, str]:
    """
    Generate (nonce, mac) for an authorization response.

    Both values should be embedded in the response returned to the caller.
    nonce is a random UUID4; mac is an HMAC-SHA256 hex digest (64 hex chars).

    The caller passes these back into verify_response() to confirm the
    response has not been tampered with or replayed.
    """
    nonce = str(uuid.uuid4())
    canon = _canonical_bytes(nonce, request_id, agent_id, decision, timestamp, action_ref, flow)
    mac = _compute_mac(canon)
    return nonce, mac


def verify_response(
    nonce: str,
    mac: str,
    request_id: str,
    agent_id: str,
    decision: str,
    timestamp: float,
    action_ref: str = "",
    flow: str = "",
) -> tuple[bool, str]:
    """
    Verify an authorization response MAC.

    Returns (valid: bool, reason: str).
    reason is "OK" on success, or a SCREAMING_SNAKE_CASE diagnostic on failure.

    Checks (in order to prevent oracle attacks):
      1. Age — rejects stale responses (> RESPONSE_MAX_AGE_SECONDS old).
      2. Future skew — rejects responses timestamped > RESPONSE_MAX_FUTURE_SKEW_SECONDS
         in the future (clock-skew guard, not a security boundary).
      3. MAC — constant-time comparison via hmac.compare_digest.
    """
    now = time.time()
    age = now - timestamp

    if age > RESPONSE_MAX_AGE_SECONDS:
        return (
            False,
            f"RESPONSE_EXPIRED:age={round(age)}s_max={RESPONSE_MAX_AGE_SECONDS}s",
        )
    if age < -RESPONSE_MAX_FUTURE_SKEW_SECONDS:
        return (
            False,
            f"RESPONSE_FROM_FUTURE:skew={round(-age, 1)}s",
        )

    expected = _compute_mac(
        _canonical_bytes(nonce, request_id, agent_id, decision, timestamp, action_ref, flow)
    )
    if not _hmac.compare_digest(expected, mac):
        return False, "SIGNATURE_MISMATCH"

    return True, "OK"


def get_signing_info() -> dict:
    """
    Return metadata about the response signing scheme.

    Exposed via GET /signing-info. No secret material is included:
    key_id is a short fingerprint so clients can detect key rotation
    without exposing the key itself.
    """
    key_id = hashlib.sha256(b"agentgate-key-id|" + _RESPONSE_SIGN_KEY).hexdigest()[:16]
    return {
        "algorithm": "HMAC-SHA256",
        "key_id": key_id,
        "max_age_seconds": RESPONSE_MAX_AGE_SECONDS,
        "canonical_fields": ["nonce", "request_id", "agent_id", "decision", "timestamp", "action_ref", "flow"],
        "canonical_sep": CANONICAL_SEP,
        "nonce_format": "UUID4",
        "mac_encoding": "hex",
    }
