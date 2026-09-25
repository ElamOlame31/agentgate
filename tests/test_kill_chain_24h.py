"""
Tests for the 24-hour cross-session kill chain detectors.

Key invariant: request_history is SQLite-backed, so history from before
a server restart persists and can trigger cross-session patterns.

These tests simulate pre-session history by inserting records with past
timestamps directly via audit.log_request_history_at(), then verify that
analyze_kill_chain() correctly identifies the cross-session pattern.
"""

import time
import sqlite3
import uuid
import pytest
from unittest.mock import patch

from core.platform import audit
from core.detection.kill_chain import (
    analyze_kill_chain,
    BULK_READ_THRESHOLD,
    BULK_READ_THRESHOLD_24H,
    SWEEP_PREFIX_THRESHOLD,
    SENSITIVITY_RAMP_MIN_HISTORY,
    KILL_CHAIN_WINDOW_SECONDS,
    _FAST_WINDOW,
    _RAMP_WINDOW,
)
from core.detection import quarantine as q


# ── Helper: insert history with arbitrary timestamp ───────────────────────────

def _insert_history(agent_id: str, action: str, resource: str, age_seconds: float = 0.0):
    """Insert a request_history row with timestamp = now - age_seconds."""
    conn = sqlite3.connect(audit.DB_PATH)
    conn.execute(
        "INSERT INTO request_history VALUES (?,?,?,?,?)",
        (str(uuid.uuid4()), agent_id, action, resource, time.time() - age_seconds)
    )
    conn.commit()
    conn.close()


def _uid(prefix: str = "cs") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


# ── Cross-session bulk read → exfil ───────────────────────────────────────────

class TestCrossSessionBulkReadExfil:
    def test_fast_detector_still_fires_with_burst(self):
        """Fast (5-min) detector takes priority when burst threshold is met."""
        uid = _uid()
        for i in range(BULK_READ_THRESHOLD):
            _insert_history(uid, "read", f"/reports/r{i}.pdf", age_seconds=10)
        flags = analyze_kill_chain(uid, "export", "/dump.zip")
        assert any("KILL_CHAIN:BULK_READ_THEN_EXFIL" in f for f in flags)
        # Should NOT emit cross-session flag when fast already fired
        assert not any("CROSS_SESSION" in f for f in flags)

    def test_cross_session_fires_when_reads_span_hours(self):
        """30+ reads spread over 6 hours triggers the cross-session exfil detector."""
        uid = _uid()
        for i in range(BULK_READ_THRESHOLD_24H):
            # Spread reads evenly across 6 hours
            age = (i / BULK_READ_THRESHOLD_24H) * 21_600
            _insert_history(uid, "read", f"/data/file{i}.csv", age_seconds=age)
        flags = analyze_kill_chain(uid, "export", "/dump.zip")
        assert any("KILL_CHAIN:CROSS_SESSION:BULK_READ_THEN_EXFIL" in f for f in flags)

    def test_cross_session_fires_on_destroy_too(self):
        """Cross-session bulk read before a destructive action also triggers."""
        uid = _uid()
        for i in range(BULK_READ_THRESHOLD_24H):
            age = (i / BULK_READ_THRESHOLD_24H) * 14_400
            _insert_history(uid, "read", f"/hr/file{i}.csv", age_seconds=age)
        flags = analyze_kill_chain(uid, "delete", "/hr/all_records")
        assert any("KILL_CHAIN:CROSS_SESSION:BULK_READ_THEN_DESTROY" in f for f in flags)

    def test_below_threshold_does_not_fire(self):
        """29 reads over 24h is below threshold — no cross-session flag."""
        uid = _uid()
        for i in range(BULK_READ_THRESHOLD_24H - 1):
            age = (i / BULK_READ_THRESHOLD_24H) * 14_400
            _insert_history(uid, "read", f"/data/file{i}.csv", age_seconds=age)
        flags = analyze_kill_chain(uid, "export", "/dump.zip")
        assert not any("CROSS_SESSION:BULK_READ_THEN_EXFIL" in f for f in flags)

    def test_reads_older_than_24h_are_excluded(self):
        """Reads from 25 hours ago fall outside the 24h window and are ignored."""
        uid = _uid()
        for i in range(BULK_READ_THRESHOLD_24H + 10):
            _insert_history(uid, "read", f"/data/old{i}.csv", age_seconds=90_000)
        flags = analyze_kill_chain(uid, "export", "/dump.zip")
        assert not any("BULK_READ_THEN_EXFIL" in f for f in flags)


# ── Cross-session read → delete ───────────────────────────────────────────────

class TestCrossSessionReadThenDelete:
    def test_fast_detector_fires_within_5min(self):
        """Read then delete within 5 minutes fires the standard (non-cross-session) flag."""
        uid = _uid()
        _insert_history(uid, "read", "/confidential/salary.xlsx", age_seconds=30)
        flags = analyze_kill_chain(uid, "delete", "/confidential/salary.xlsx")
        assert any("KILL_CHAIN:READ_THEN_DELETE" in f for f in flags)
        assert not any("CROSS_SESSION" in f for f in flags)

    def test_cross_session_fires_when_read_was_hours_ago(self):
        """Read 8 hours ago + delete now = cross-session READ_THEN_DELETE."""
        uid = _uid()
        _insert_history(uid, "read", "/confidential/salary.xlsx", age_seconds=28_800)
        flags = analyze_kill_chain(uid, "delete", "/confidential/salary.xlsx")
        assert any("KILL_CHAIN:CROSS_SESSION:READ_THEN_DELETE" in f for f in flags)

    def test_cross_session_fires_on_url_encoded_path(self):
        """URL-encoded path variants are normalized and still match."""
        uid = _uid()
        _insert_history(uid, "read", "/confidential/salary%20sheet.xlsx", age_seconds=3_600)
        flags = analyze_kill_chain(uid, "delete", "/confidential/salary sheet.xlsx")
        assert any("READ_THEN_DELETE" in f for f in flags)

    def test_different_resource_does_not_fire(self):
        """Read /file-a, delete /file-b — no cross-session flag."""
        uid = _uid()
        _insert_history(uid, "read", "/confidential/file-a.xlsx", age_seconds=3_600)
        flags = analyze_kill_chain(uid, "delete", "/confidential/file-b.xlsx")
        assert not any("READ_THEN_DELETE" in f for f in flags)

    def test_cross_session_triggers_quarantine(self):
        """Cross-session READ_THEN_DELETE maps to a hard quarantine trigger."""
        flag = "KILL_CHAIN:CROSS_SESSION:READ_THEN_DELETE:/confidential/salary.xlsx"
        result = q.should_quarantine_on_flags([flag])
        assert result == "KILL_CHAIN:CROSS_SESSION:READ_THEN_DELETE"


# ── Cross-session sensitivity ramp ────────────────────────────────────────────

class TestCrossSessionSensitivityRamp:
    def test_fast_ramp_still_fires(self):
        """Standard 5-min ramp still fires when within the fast window."""
        uid = _uid()
        for i in range(SENSITIVITY_RAMP_MIN_HISTORY):
            _insert_history(uid, "read", "/reports/q1.pdf", age_seconds=60 + i * 10)
        flags = analyze_kill_chain(uid, "read", "/confidential/salary.xlsx")
        assert any("KILL_CHAIN:SENSITIVITY_RAMP" in f for f in flags)

    def test_cross_session_ramp_fires_over_4h(self):
        """10+ low/med reads over 4h before first CRITICAL triggers cross-session ramp."""
        uid = _uid()
        for i in range(SENSITIVITY_RAMP_MIN_HISTORY * 2):
            age = (i / (SENSITIVITY_RAMP_MIN_HISTORY * 2)) * 12_000  # within 3.3h
            _insert_history(uid, "read", "/reports/q1.pdf", age_seconds=age + 500)
        flags = analyze_kill_chain(uid, "read", "/confidential/salary.xlsx")
        assert any("SENSITIVITY_RAMP" in f for f in flags)


# ── quarantine: prefix matching for suffixed flags ────────────────────────────

class TestQuarantinePrefixMatching:
    def test_suffixed_fast_exfil_flag_triggers_quarantine(self):
        """Real kill chain flags carry a detail suffix — quarantine must prefix-match."""
        flag = "KILL_CHAIN:BULK_READ_THEN_EXFIL:12_reads_in_5min"
        assert q.should_quarantine_on_flags([flag]) == "KILL_CHAIN:BULK_READ_THEN_EXFIL"

    def test_suffixed_destroy_flag_triggers_quarantine(self):
        flag = "KILL_CHAIN:BULK_READ_THEN_DESTROY:15_reads_in_5min"
        assert q.should_quarantine_on_flags([flag]) == "KILL_CHAIN:BULK_READ_THEN_DESTROY"

    def test_suffixed_read_delete_flag_triggers_quarantine(self):
        flag = "KILL_CHAIN:READ_THEN_DELETE:/confidential/salary.xlsx"
        assert q.should_quarantine_on_flags([flag]) == "KILL_CHAIN:READ_THEN_DELETE"

    def test_cross_session_exfil_triggers_quarantine(self):
        flag = "KILL_CHAIN:CROSS_SESSION:BULK_READ_THEN_EXFIL:30_reads_in_24h"
        assert q.should_quarantine_on_flags([flag]) == "KILL_CHAIN:CROSS_SESSION:BULK_READ_THEN_EXFIL"

    def test_cross_session_destroy_triggers_quarantine(self):
        flag = "KILL_CHAIN:CROSS_SESSION:BULK_READ_THEN_DESTROY:35_reads_in_24h"
        assert q.should_quarantine_on_flags([flag]) == "KILL_CHAIN:CROSS_SESSION:BULK_READ_THEN_DESTROY"

    def test_cross_session_read_delete_triggers_quarantine(self):
        flag = "KILL_CHAIN:CROSS_SESSION:READ_THEN_DELETE:/sec/keys.json"
        assert q.should_quarantine_on_flags([flag]) == "KILL_CHAIN:CROSS_SESSION:READ_THEN_DELETE"

    def test_escalate_flags_do_not_trigger_quarantine(self):
        """SENSITIVITY_RAMP and DIRECTORY_SWEEP are ESCALATE, not hard quarantine triggers."""
        flags = [
            "KILL_CHAIN:SENSITIVITY_RAMP:5_low_med_before_first_critical",
            "KILL_CHAIN:DIRECTORY_SWEEP:7_prefixes",
            "KILL_CHAIN:CROSS_SESSION:SENSITIVITY_RAMP:10_low_med_in_4h",
        ]
        assert q.should_quarantine_on_flags(flags) is None


# ── audit cleanup ─────────────────────────────────────────────────────────────

class TestRequestHistoryCleanup:
    def test_cleanup_removes_old_entries(self):
        uid = _uid()
        # Insert one old, one recent
        _insert_history(uid, "read", "/old.pdf", age_seconds=90_000)  # 25h ago
        _insert_history(uid, "read", "/new.pdf", age_seconds=60)      # 1 min ago
        deleted = audit.cleanup_old_request_history(retention_seconds=86_400.0)
        assert deleted >= 1
        remaining = audit.get_agent_request_history(uid, window_seconds=KILL_CHAIN_WINDOW_SECONDS)
        resources = [r["resource"] for r in remaining]
        assert "/new.pdf" in resources
        assert "/old.pdf" not in resources

    def test_cleanup_leaves_recent_entries_intact(self):
        uid = _uid()
        for i in range(5):
            _insert_history(uid, "read", f"/recent{i}.pdf", age_seconds=300)
        audit.cleanup_old_request_history(retention_seconds=86_400.0)
        remaining = audit.get_agent_request_history(uid, window_seconds=KILL_CHAIN_WINDOW_SECONDS)
        assert len(remaining) == 5

    def test_cleanup_with_custom_retention(self):
        uid = _uid()
        _insert_history(uid, "read", "/two-hour-old.pdf", age_seconds=7_200)
        deleted = audit.cleanup_old_request_history(retention_seconds=3_600.0)  # 1h retention
        assert deleted >= 1
        remaining = audit.get_agent_request_history(uid, window_seconds=KILL_CHAIN_WINDOW_SECONDS)
        assert all(r["resource"] != "/two-hour-old.pdf" for r in remaining)
