"""
Detector 7 — KILL_CHAIN:RESOURCE_HAMMERING

Fires when an agent accesses the same specific resource path multiple times
within the 5-minute fast window. Complements:
  - BULK_READ_THEN_EXFIL  (breadth: distinct resources before exfil action)
  - DIRECTORY_SWEEP       (breadth: distinct top-level prefixes in fast window)
  - REPETITIVE_ACTION     (same action type, not same resource path)

This detector catches depth attacks — focus on one resource at high frequency:

  - Log-flooding before exfiltration: repeat-read the same file to bury the
    subsequent exfil attempt in a sea of individually-authorized entries.
  - Broken agent loop: stuck in a retry cycle (operational risk → ESCALATE;
    does not hard-DENY below HAMMERING_DENY_THRESHOLD).
  - Slow-polling exfil: frequency stays below RPM velocity thresholds but the
    per-resource access count over the window reveals the pattern.

Flags (fed to make_decision() via analyze_kill_chain() in kill_chain.py):
  KILL_CHAIN:RESOURCE_HAMMERING:{N}_in_5min:{resource}       → ESCALATE path
  KILL_CHAIN:RESOURCE_HAMMERING:HARD:{N}_in_5min:{resource}  → hard DENY
"""

import posixpath
import time
from urllib.parse import unquote

# Must match kill_chain._FAST_WINDOW so this detector applies the same time gate
# as every other fast-window detector.
_FAST_WINDOW_SECONDS = 300.0

# Number of total accesses (prior history + current request) to the same resource
# within _FAST_WINDOW_SECONDS that triggers the ESCALATE path.
# Rationale: legitimate caching/retry patterns rarely exceed 5-6 accesses in 5 min;
# 8 is a conservative threshold that minimises false positives.
HAMMERING_ESCALATE_THRESHOLD = 8

# Total accesses that trigger a hard DENY — clearly broken loop or deliberate attack.
# At 20 accesses in 5 min the pattern is anomalous regardless of context.
HAMMERING_DENY_THRESHOLD = 20


def _normalize(resource: str) -> str:
    """URL-decode then POSIX-normalize and lowercase — prevents bypass via percent-encoding or case."""
    return posixpath.normpath(unquote(resource)).lower()


def detect_resource_hammering(
    action: str, resource: str, history: list[dict]
) -> list[str]:
    """
    Return KILL_CHAIN:RESOURCE_HAMMERING:* flags if the agent is hammering a single resource.

    Parameters
    ----------
    action   : current (not-yet-executed) action string — unused in detection logic,
               present to match the interface of all other detector functions.
    resource : current resource path.
    history  : agent request history ordered most-recent first, as returned by
               audit.get_agent_request_history(window_seconds=KILL_CHAIN_WINDOW_SECONDS).
               Each entry is a dict with at least "resource" and "timestamp" keys.

    Returns at most one flag string; returns [] when below the escalate threshold.
    """
    now = time.time()
    target = _normalize(resource)

    prior = sum(
        1 for h in history
        if now - h["timestamp"] <= _FAST_WINDOW_SECONDS
        and _normalize(h.get("resource", "")) == target
    )

    # +1 for the current request, which is not yet in request_history at decision time.
    total = prior + 1

    if total >= HAMMERING_DENY_THRESHOLD:
        return [f"KILL_CHAIN:RESOURCE_HAMMERING:HARD:{total}_in_5min:{resource}"]
    if total >= HAMMERING_ESCALATE_THRESHOLD:
        return [f"KILL_CHAIN:RESOURCE_HAMMERING:{total}_in_5min:{resource}"]

    return []
