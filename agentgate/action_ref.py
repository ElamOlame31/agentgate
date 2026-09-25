"""
Client-side action_ref — the same operation digest the server computes.

This mirrors core/action_ref.py deliberately rather than importing it. The SDK
ships as a standalone package whose only dependency is httpx; a client that had
to install the server to check a receipt would not be checkable at all, and the
offline verifier depends on this being self-contained.

The cost of mirroring is that the two must not drift. They are pinned together
by DESCRIPTOR_VERSION and by a test that computes the same operation through
both paths and asserts the digests match; change one side and that test fails.

See core/action_ref.py for why the descriptor holds what it holds.
"""

import hashlib
import json
import posixpath
import urllib.parse
from typing import Any

DESCRIPTOR_VERSION = 1
MAX_ARGUMENTS_BYTES = 16_384


class ActionRefError(ValueError):
    """The operation could not be canonicalized, so it cannot be bound."""


def normalize_resource(resource: str) -> str:
    """Normalize a resource path to the form the digest is computed over."""
    decoded = urllib.parse.unquote(urllib.parse.unquote(resource))
    decoded = decoded.replace("\x00", "")
    normalized = posixpath.normpath(decoded)
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized


def canonical_json(value: Any) -> str:
    """Serialize to the canonical form the digest is taken over."""
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ActionRefError(f"operation is not canonicalizable: {exc}") from exc


def build_descriptor(
    agent_id: str,
    action: str,
    resource: str,
    arguments: dict | None = None,
    policy_version: str = "",
) -> dict:
    args = arguments or {}
    if not isinstance(args, dict):
        raise ActionRefError("arguments must be a JSON object")

    size = len(canonical_json(args).encode("utf-8"))
    if size > MAX_ARGUMENTS_BYTES:
        raise ActionRefError(
            f"arguments too large to bind: {size} bytes > {MAX_ARGUMENTS_BYTES}"
        )

    return {
        "v": DESCRIPTOR_VERSION,
        "agent_id": agent_id,
        "action": action.lower(),
        "resource": normalize_resource(resource),
        "arguments": args,
        "policy_version": policy_version,
    }


def compute_action_ref(
    agent_id: str,
    action: str,
    resource: str,
    arguments: dict | None = None,
    policy_version: str = "",
) -> str:
    """Return the SHA-256 hex digest that addresses this operation."""
    descriptor = build_descriptor(agent_id, action, resource, arguments, policy_version)
    return hashlib.sha256(canonical_json(descriptor).encode("utf-8")).hexdigest()


def matches(action_ref: str, *, agent_id: str, action: str, resource: str,
            arguments: dict | None = None, policy_version: str = "") -> bool:
    """Whether an operation still resolves to the reference issued for it."""
    try:
        recomputed = compute_action_ref(
            agent_id, action, resource, arguments, policy_version
        )
    except ActionRefError:
        return False
    return recomputed == action_ref
