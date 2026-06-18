"""
Quarantine Mode — Layer 3 of AgentGate's defense model.

Sits above the trust score and behavioral contracts. When an agent triggers
hard attack patterns (kill chain, critical velocity) or accumulates soft
violations (CONSECUTIVE_DENY_THRESHOLD DENYs within DENY_WINDOW_SECONDS),
it is placed in quarantine:

  - All /authorize requests immediately return DENY with QUARANTINED flag.
  - Auto-expires after QUARANTINE_BASE_SECONDS (default 15 min).
  - Each new violation while quarantined extends by QUARANTINE_EXTENSION_SECONDS.
  - Hard ceiling: QUARANTINE_MAX_SECONDS (24 h).
  - Manual release via dashboard or DELETE /agents/{id}/quarantine.

Three operational states:
  active     → normal trust scoring
  quarantined → all actions denied, auto-expiring, human-releasable
  revoked    → permanent, requires re-registration
"""

import time
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, Deque, Optional

# ── Constants ──────────────────────────────────────────────────────────────────

QUARANTINE_BASE_SECONDS      = int(15 * 60)   # 15 min initial window
QUARANTINE_EXTENSION_SECONDS = int(15 * 60)   # 15 min added per new violation
QUARANTINE_MAX_SECONDS       = int(24 * 3600) # 24 h hard ceiling
CONSECUTIVE_DENY_THRESHOLD   = 5              # DENYs to trigger soft quarantine
DENY_WINDOW_SECONDS          = 60.0           # rolling window for accumulation

# Flags that trigger quarantine immediately, regardless of deny count.
HARD_QUARANTINE_FLAGS: frozenset = frozenset({
    "CRITICAL_VELOCITY",
    "KILL_CHAIN:BULK_READ_THEN_EXFIL",
    "KILL_CHAIN:BULK_READ_THEN_DESTROY",
    "KILL_CHAIN:READ_THEN_DELETE",
    "KILL_CHAIN:CROSS_SESSION:BULK_READ_THEN_EXFIL",
    "KILL_CHAIN:CROSS_SESSION:BULK_READ_THEN_DESTROY",
    "KILL_CHAIN:CROSS_SESSION:READ_THEN_DELETE",
    "KILL_CHAIN:LETHAL_TRIFECTA",
})


# ── Data model ─────────────────────────────────────────────────────────────────

@dataclass
class QuarantineRecord:
    agent_id:        str
    quarantined_at:  float
    expires_at:      float
    trigger:         str    # "KILL_CHAIN:BULK_READ_THEN_EXFIL", "CONSECUTIVE_DENY", etc.
    violation_count: int = 1
    extended_count:  int = 0

    def is_active(self) -> bool:
        return time.time() < self.expires_at

    def remaining_seconds(self) -> float:
        return max(0.0, self.expires_at - time.time())

    def to_dict(self) -> dict:
        return {
            "agent_id":        self.agent_id,
            "quarantined_at":  self.quarantined_at,
            "expires_at":      self.expires_at,
            "trigger":         self.trigger,
            "violation_count": self.violation_count,
            "extended_count":  self.extended_count,
            "remaining_seconds": round(self.remaining_seconds(), 1),
            "active":          self.is_active(),
        }


# ── In-memory state ────────────────────────────────────────────────────────────

_store: Dict[str, QuarantineRecord] = {}
_deny_windows: Dict[str, Deque] = {}
_lock = threading.Lock()


# ── Core operations ────────────────────────────────────────────────────────────

def quarantine(agent_id: str, trigger: str, permanent: bool = False) -> QuarantineRecord:
    """
    Place agent in quarantine. Idempotent: extends window if already quarantined.
    permanent=True pins expires_at at the 24-hour ceiling from now.
    """
    with _lock:
        now = time.time()
        existing = _store.get(agent_id)
        if existing and existing.is_active():
            new_expires = min(
                existing.expires_at + QUARANTINE_EXTENSION_SECONDS,
                now + QUARANTINE_MAX_SECONDS,
            )
            existing.expires_at = new_expires
            existing.violation_count += 1
            existing.extended_count += 1
            existing.trigger = trigger
            return existing

        duration = QUARANTINE_MAX_SECONDS if permanent else QUARANTINE_BASE_SECONDS
        record = QuarantineRecord(
            agent_id=agent_id,
            quarantined_at=now,
            expires_at=now + duration,
            trigger=trigger,
        )
        _store[agent_id] = record
        return record


def is_quarantined(agent_id: str) -> bool:
    """Fast path check. Evicts expired records on the way out."""
    record = _store.get(agent_id)
    if record is None:
        return False
    if record.is_active():
        return True
    with _lock:
        r = _store.get(agent_id)
        if r and not r.is_active():
            del _store[agent_id]
    return False


def get_record(agent_id: str) -> Optional[QuarantineRecord]:
    """Return the active quarantine record, or None if not quarantined / expired."""
    record = _store.get(agent_id)
    return record if (record and record.is_active()) else None


def release(agent_id: str) -> bool:
    """Manual release. Returns True if an active quarantine was removed."""
    with _lock:
        record = _store.pop(agent_id, None)
        _deny_windows.pop(agent_id, None)
        return record is not None


def get_all() -> list:
    """Return all active quarantine records, pruning expired ones first."""
    now = time.time()
    with _lock:
        expired = [aid for aid, r in _store.items() if now >= r.expires_at]
        for aid in expired:
            del _store[aid]
        return [r.to_dict() for r in _store.values()]


def record_deny(agent_id: str) -> Optional[str]:
    """
    Record a DENY for soft-trigger accumulation.
    Returns the trigger string if the threshold is crossed, else None.
    Clears the window after triggering so the agent gets a fresh slate once released.
    """
    with _lock:
        now = time.time()
        if agent_id not in _deny_windows:
            _deny_windows[agent_id] = deque()
        dq = _deny_windows[agent_id]
        dq.append(now)
        # Evict timestamps outside the rolling window
        while dq and now - dq[0] > DENY_WINDOW_SECONDS:
            dq.popleft()
        if len(dq) >= CONSECUTIVE_DENY_THRESHOLD:
            dq.clear()
            return "CONSECUTIVE_DENY"
        return None


def should_quarantine_on_flags(flags: list) -> Optional[str]:
    """Return the canonical hard-trigger flag matched (prefix), or None."""
    for flag in flags:
        for hf in HARD_QUARANTINE_FLAGS:
            if flag.startswith(hf):
                return hf
    return None


def load_from_persistence(records: list) -> None:
    """Restore active quarantines from SQLite on startup. Silently skips expired records."""
    now = time.time()
    with _lock:
        for r in records:
            if r.get("expires_at", 0) > now:
                _store[r["agent_id"]] = QuarantineRecord(
                    agent_id=r["agent_id"],
                    quarantined_at=r["quarantined_at"],
                    expires_at=r["expires_at"],
                    trigger=r["trigger"],
                    violation_count=r.get("violation_count", 1),
                    extended_count=r.get("extended_count", 0),
                )
