"""
Kill chain detector — identifies multi-step attack patterns across a request sequence.

Each individual request may pass every single-request check cleanly.
This module examines the full sequence to catch patterns that only become
visible across multiple calls — reconnaissance → exfiltration, gradual
sensitivity escalation, read-then-destroy, and broad directory sweeps.

Flags are tiered:
  KILL_CHAIN:BULK_READ_THEN_*    hard DENY — bulk reads before exfil or destroy
  KILL_CHAIN:READ_THEN_DELETE    hard DENY — read a resource, then delete it
  KILL_CHAIN:SENSITIVITY_RAMP    ESCALATE  — progressive sensitivity increase
  KILL_CHAIN:DIRECTORY_SWEEP     ESCALATE  — broad cross-directory reconnaissance
"""

import posixpath
from urllib.parse import unquote
from core import audit
from core.models import ResourceSensitivity, EXFILTRATION_ACTIONS as _EXFIL_ACTIONS

# Analysis window: longer than velocity detection (60 s) to catch slow-burn attacks
KILL_CHAIN_WINDOW_SECONDS = 300.0  # 5 minutes

# Reads in the window before a bulk-read-then-X pattern fires
BULK_READ_THRESHOLD = 10

# Distinct top-level resource prefixes that signal directory reconnaissance
SWEEP_PREFIX_THRESHOLD = 6

# Minimum low/medium requests before a sensitivity ramp fires on a first CRITICAL hit
SENSITIVITY_RAMP_MIN_HISTORY = 5

_DESTRUCTIVE_ACTIONS = {
    "delete", "remove", "drop", "truncate",
    "wipe", "purge", "destroy", "overwrite",
}


def _normalize_path(resource: str) -> str:
    """URL-decode then POSIX-normalize and lowercase to prevent bypass via encoding or casing."""
    return posixpath.normpath(unquote(resource)).lower()


def _top_prefix(resource: str) -> str:
    """Extract the first path component: /reports/q3/q3.pdf → /reports"""
    parts = _normalize_path(resource).split("/")
    return "/" + parts[1] if len(parts) > 1 and parts[1] else "/"


def _sensitivity(resource: str, action: str) -> ResourceSensitivity:
    # Deferred import to avoid circular dependency with trust_engine
    from core.trust_engine import classify_resource_sensitivity
    return classify_resource_sensitivity(resource, action)


def analyze_kill_chain(agent_id: str, action: str, resource: str) -> list[str]:
    """
    Examine the agent's 5-minute request history for multi-step attack patterns.
    History is ordered most-recent first. Returns KILL_CHAIN:* flags.
    """
    history = audit.get_agent_request_history(
        agent_id, window_seconds=KILL_CHAIN_WINDOW_SECONDS
    )
    if not history:
        return []

    flags = []
    action_lower = action.lower()

    # ── Detector 1: Bulk read → destructive or exfiltration ──────────────────
    # Many reads in the window, now requesting exfil or destroy.
    # Classic pattern: enumerate data → extract → optionally cover tracks.
    if action_lower in _EXFIL_ACTIONS or action_lower in _DESTRUCTIVE_ACTIONS:
        reads_in_window = sum(1 for h in history if h["action"].lower() == "read")
        if reads_in_window >= BULK_READ_THRESHOLD:
            category = "EXFIL" if action_lower in _EXFIL_ACTIONS else "DESTROY"
            flags.append(
                f"KILL_CHAIN:BULK_READ_THEN_{category}"
                f":{reads_in_window}_reads_in_5min"
            )

    # ── Detector 2: Read → delete same resource ───────────────────────────────
    # Agent read a specific resource and now wants to delete it.
    # High-confidence data-theft + cover-tracks signal.
    if action_lower in _DESTRUCTIVE_ACTIONS:
        target = _normalize_path(resource)
        prior_reads = [
            h for h in history
            if h["action"].lower() == "read"
            and _normalize_path(h["resource"]) == target
        ]
        if prior_reads:
            flags.append(f"KILL_CHAIN:READ_THEN_DELETE:{resource}")

    # ── Detector 3: Sensitivity ramp to CRITICAL ──────────────────────────────
    # Agent accumulated LOW/MEDIUM requests, now hitting CRITICAL for the first time.
    # Indicates progressive boundary probing before a high-value target.
    if _sensitivity(resource, action) == ResourceSensitivity.CRITICAL:
        recent = history[:15]
        past = [_sensitivity(h["resource"], h["action"]) for h in recent]
        critical_before = sum(1 for s in past if s == ResourceSensitivity.CRITICAL)
        low_med_before = sum(
            1 for s in past
            if s in (ResourceSensitivity.LOW, ResourceSensitivity.MEDIUM)
        )
        if critical_before == 0 and low_med_before >= SENSITIVITY_RAMP_MIN_HISTORY:
            flags.append(
                f"KILL_CHAIN:SENSITIVITY_RAMP"
                f":{low_med_before}_low_med_before_first_critical"
            )

    # ── Detector 4: Directory sweep ───────────────────────────────────────────
    # Agent accessing many distinct top-level resource prefixes — broad reconnaissance.
    prefixes = {_top_prefix(h["resource"]) for h in history}
    prefixes.add(_top_prefix(resource))
    if len(prefixes) >= SWEEP_PREFIX_THRESHOLD:
        flags.append(f"KILL_CHAIN:DIRECTORY_SWEEP:{len(prefixes)}_prefixes")

    return flags
