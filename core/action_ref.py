"""
action_ref — a content address for the operation an agent is about to perform.

A decision that says "PERMIT for request 4f2c…" proves who decided and when.
It does not prove *what* was decided, which is the gap Loopjacking describes:
a human — or a policy — approves operation A while the caller goes on to
execute operation B. Closing it needs a value both sides can compute
independently from the operation itself, so the caller can check at dispatch
that what it is about to run is what was authorized.

That value is action_ref:

    action_ref = SHA-256( canonical_json( descriptor ) )

The descriptor holds the whole operation and nothing else:

    {"v": 1, "agent_id": …, "action": …, "resource": …,
     "arguments": {…}, "policy_version": …}

Deliberately absent: nonce, timestamps, decision. Those belong to a single
authorization *event* and differ between the request and the dispatch that
follows it, which would make the reference unrecomputable — the opposite of
what it is for. They are bound separately, by the response signature, which
covers action_ref alongside them.

Two operations share an action_ref exactly when every field above matches.
Change the amount, the recipient, the path, or the agent, and the reference
changes with it.

Canonicalization is JSON with sorted keys, no insignificant whitespace and
unescaped UTF-8. This is a *subset* of JCS (RFC 8785), not JCS: the two agree
on objects, arrays, strings, booleans, null and integers, and can disagree on
how some floating-point values serialize. Keep money in minor units and other
quantities integral and the two are interchangeable; send a float and a
JCS-based verifier may compute a different digest. ATAP and algovoi-substrate
canonicalize with JCS, so full compliance matters once receipts cross between
implementations — it is a known, bounded gap, not an oversight.
"""

import hashlib
import json
import posixpath
import urllib.parse
from typing import Any

# Bump when the descriptor shape changes in a way that alters digests, so an
# old receipt is never silently compared against a new descriptor layout.
DESCRIPTOR_VERSION = 1

# Arguments are bound in full, so a runaway payload would be hashed in full
# too. A request carrying more than this is refused rather than truncated:
# truncation would let anything past the cutoff vary without changing the digest.
MAX_ARGUMENTS_BYTES = 16_384


class ActionRefError(ValueError):
    """The operation could not be canonicalized, so no reference can be issued."""


def normalize_resource(resource: str) -> str:
    """
    Normalize a resource path to the form the reference is computed over.

    Client and server must agree byte for byte or every dispatch check fails,
    so this is the single definition both sides use.

    Steps:
      1. URL-decode twice (%252e%252e → %2e%2e → ..), catching double encoding
      2. Strip null bytes
      3. posixpath.normpath — resolves .., collapses //, drops ./
      4. Guarantee a leading /
    """
    decoded = urllib.parse.unquote(urllib.parse.unquote(resource))
    decoded = decoded.replace("\x00", "")
    normalized = posixpath.normpath(decoded)
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized


def canonical_json(value: Any) -> str:
    """
    Serialize to the canonical form the digest is taken over.

    Sorted keys and no insignificant whitespace make the output independent of
    how the caller happened to build the object. ensure_ascii=False keeps real
    UTF-8 rather than \\uXXXX escapes, so a verifier in another language reads
    the same bytes.
    """
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
    """
    Assemble the operation descriptor.

    `arguments` carries every material argument of the call — the amount, the
    recipient, the body. Anything omitted here is unbound: it can change
    between authorization and execution without invalidating the receipt, which
    is precisely the confused-deputy hole. Omit only what genuinely cannot
    affect the consequence.
    """
    args = arguments or {}
    if not isinstance(args, dict):
        raise ActionRefError("arguments must be a JSON object")

    encoded = canonical_json(args)
    size = len(encoded.encode("utf-8"))
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
    descriptor = build_descriptor(
        agent_id, action, resource, arguments, policy_version
    )
    return hashlib.sha256(canonical_json(descriptor).encode("utf-8")).hexdigest()


def matches(action_ref: str, *, agent_id: str, action: str, resource: str,
            arguments: dict | None = None, policy_version: str = "") -> bool:
    """
    Whether an operation still resolves to the reference issued for it.

    This is the dispatch-time check. A False means the operation drifted after
    authorization and must not run on the strength of that decision.
    """
    try:
        recomputed = compute_action_ref(
            agent_id, action, resource, arguments, policy_version
        )
    except ActionRefError:
        return False
    # Plain comparison: both values are public digests, not secrets, so there
    # is no timing signal worth hiding here.
    return recomputed == action_ref
