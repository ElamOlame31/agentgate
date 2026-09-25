"""
Publicly verifiable receipt signatures.

response_signing uses HMAC, which authenticates a receipt to anyone holding the
shared secret. That is right for the server checking its own receipt at
redemption, and useless for the case the product exists to serve: an auditor,
a regulator or an insurer confirming what was authorized. Handing them the HMAC
key would let them mint receipts, so a symmetric scheme cannot deliver
"verify this without trusting us" — it can only deliver "trust us, or become us".

Receipts therefore also carry an Ed25519 signature. The public key is published;
the private half never leaves the instance. Anyone can check a receipt offline,
nobody but the issuer can produce one, and the check needs no server, no account
and no network.

The key is domain-separated from the agent-token key even though both derive
from AGENTGATE_SIGNING_KEY. They sign different kinds of statement — "this agent
is who it says" versus "this operation was authorized" — and one key signing
both would let a signature be presented as the other kind.
"""

import base64
import hashlib
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

_DOMAIN = b"agentgate-receipt-ed25519|"
_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey] | None = None


def _derive_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Deterministic from the operator secret, so a restart keeps the same key.

    A rotated secret rotates the key, which invalidates previously issued
    receipts. That is the correct behaviour — a receipt attests that a specific
    instance authorized something, and after rotation that instance's claim can
    no longer be confirmed. Publish key_id alongside receipts so a verifier can
    tell a rotation from a forgery.
    """
    global _keypair
    if _keypair is None:
        secret = os.getenv(
            "AGENTGATE_SIGNING_KEY",
            "agentgate-dev-signing-key-change-in-production",
        ).encode("utf-8")
        seed = hashlib.sha256(_DOMAIN + secret).digest()  # 32 bytes
        private = Ed25519PrivateKey.from_private_bytes(seed)
        _keypair = (private, private.public_key())
    return _keypair


def public_key_pem() -> str:
    """The published half. Safe to hand to anyone; required to verify."""
    _, public = _derive_keypair()
    return public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def key_id() -> str:
    """Short fingerprint of the public key, so a verifier can detect rotation."""
    return hashlib.sha256(public_key_pem().encode("utf-8")).hexdigest()[:16]


def sign(canonical: bytes) -> str:
    """Sign the canonical receipt bytes. Returns base64."""
    private, _ = _derive_keypair()
    return base64.b64encode(private.sign(canonical)).decode("ascii")


def verify(canonical: bytes, signature_b64: str, public_key_pem_str: str) -> bool:
    """
    Check a receipt against a published key.

    Deliberately takes the key as an argument and reads no module state: this is
    the function a third party runs, and it must not depend on anything only the
    issuer has.
    """
    try:
        public = serialization.load_pem_public_key(public_key_pem_str.encode("utf-8"))
        if not isinstance(public, Ed25519PublicKey):
            return False
        public.verify(base64.b64decode(signature_b64), canonical)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
