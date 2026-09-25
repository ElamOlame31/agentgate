"""
AgentGate JWT token module.

Tokens are signed Ed25519 JWTs. The key pair is derived deterministically from
AGENTGATE_SIGNING_KEY so tokens survive server restarts — same key, same pair.

Why Ed25519:
  - 32-byte private key, 64-byte signature (vs RSA-2048's 256-byte signature)
  - Signing and verification are both faster than RSA or ECDSA
  - No parameter choices that can go wrong (unlike ECDSA with weak RNG)
  - Widely supported in PyJWT >= 2.4 with the cryptography backend

Why embedded claims matter:
  - authorized_resources and authorized_actions are embedded in the signed token
  - Scope is immutable after issuance — a compromised DB cannot silently expand it
  - Auditors can verify any past decision offline with the public key alone
  - No database lookup required for basic identity verification

Backward compatibility:
  - Agents registered before this version have SHA-256-hashed UUID tokens (64 hex chars)
  - Those tokens continue to work — detection is by stored token length (64 = old, 36 = new jti)
  - New registrations always get JWT tokens
"""

import hashlib
import os
import time
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_ISSUER = "agentgate"
TOKEN_TTL = max(60.0, float(os.getenv("AGENTGATE_TOKEN_TTL", str(24 * 3600))))


def _derive_keypair() -> tuple:
    """
    Derive Ed25519 key pair from AGENTGATE_SIGNING_KEY.
    SHA-256 of the env var gives a stable 32-byte seed — same string, same key pair.
    """
    seed_str = os.getenv(
        "AGENTGATE_SIGNING_KEY",
        "agentgate-dev-signing-key-change-in-production",
    )
    seed = hashlib.sha256(seed_str.encode()).digest()  # always 32 bytes
    private = Ed25519PrivateKey.from_private_bytes(seed)
    return private, private.public_key()


_PRIVATE_KEY, _PUBLIC_KEY = _derive_keypair()


# ── Issuance ──────────────────────────────────────────────────────────────────

def issue_agent_token(
    agent_id: str,
    declared_purpose: str,
    authorized_resources: list[str],
    authorized_actions: list[str],
    delegation_depth: int = 0,
    delegated_by: str | None = None,
) -> tuple[str, str, float]:
    """
    Issue a signed JWT for an agent.

    Returns (jwt_string, jti, expires_at).
    Store jti in the database as the token reference — it is checked against
    the JWT's jti claim on every authorization to enable per-token revocation.
    The full jwt_string is returned to the caller (client) only.
    """
    jti = str(uuid.uuid4())
    now = time.time()
    expires_at = now + TOKEN_TTL

    payload = {
        "iss": _ISSUER,
        "sub": agent_id,
        "jti": jti,
        "iat": int(now),
        "exp": int(expires_at),
        # Embedded scope — immutable after signing
        "purpose": declared_purpose,
        "resources": authorized_resources,
        "actions": authorized_actions,
        "depth": delegation_depth,
        "parent": delegated_by,
    }

    token_str = jwt.encode(payload, _PRIVATE_KEY, algorithm="EdDSA")
    return token_str, jti, expires_at


# ── Verification ──────────────────────────────────────────────────────────────

def verify_agent_jwt(token_str: str) -> dict:
    """
    Verify an AgentGate JWT and return its claims.
    Raises jwt.InvalidTokenError (or subclass) on failure:
      - InvalidSignatureError: tampered or forged token
      - ExpiredSignatureError: token past its exp claim
      - InvalidIssuerError: not issued by this AgentGate instance
    """
    return jwt.decode(
        token_str,
        _PUBLIC_KEY,
        algorithms=["EdDSA"],
        issuer=_ISSUER,
        options={"verify_iss": True, "verify_exp": True},
    )


# ── Public key export ─────────────────────────────────────────────────────────

def get_public_key_pem() -> str:
    """
    Return the server's Ed25519 public key in PEM format.
    Share this with auditors or external systems that need to verify tokens
    without calling AgentGate — the signature either checks out or it doesn't.
    """
    return _PUBLIC_KEY.public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode()


# ── Format detection ──────────────────────────────────────────────────────────

def is_jwt_format(token: str) -> bool:
    """True if the token string looks like a JWT (three base64url segments)."""
    return isinstance(token, str) and token.startswith("eyJ") and token.count(".") == 2


def is_jti(stored_token: str) -> bool:
    """
    True if the value stored in the agents table is a JTI (UUID format).
    New-style JWT agents store a 36-char UUID jti.
    Old-style agents store a 64-char SHA-256 hex digest.
    Both are distinguishable by length alone.
    """
    return (
        isinstance(stored_token, str)
        and len(stored_token) == 36
        and stored_token.count("-") == 4
    )
