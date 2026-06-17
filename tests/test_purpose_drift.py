"""
stdlib-only tests for core/purpose_drift.py.
No external dependencies — pydantic, fastapi, sentence-transformers not required.

Tests are grouped by concern:
  TestGetPurposeScoreHistory — raw DB query helper
  TestNoDriftDetected         — cases that must produce no flags
  TestGradualDrift            — GRADUAL flag logic
  TestSustainedLow            — SUSTAINED_LOW flag logic
  TestConstants               — module-level constant invariants
  TestAgentIsolation          — per-agent isolation (no cross-contamination)
"""
import sqlite3
import tempfile
import time
import uuid
import unittest
from pathlib import Path

from core.purpose_drift import (
    detect_purpose_drift,
    get_purpose_score_history,
    BASELINE_WINDOW,
    DRIFT_MAX_AGE_SECONDS,
    DRIFT_THRESHOLD_ABSOLUTE,
    DRIFT_THRESHOLD_GRADUAL,
    MIN_ENTRIES_FOR_DRIFT,
    RECENT_WINDOW,
)


# ── helpers ────────────────────────────────────────────────────────────────────

def _make_db(path: str) -> None:
    """Create a minimal audit_log table for testing."""
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE audit_log (
            id TEXT PRIMARY KEY,
            timestamp REAL,
            agent_id TEXT,
            action TEXT,
            resource TEXT,
            decision TEXT,
            trust_score REAL,
            purpose_score REAL,
            full_json TEXT,
            attack_flags TEXT
        )
    """)
    conn.commit()
    conn.close()


def _insert_scores(
    path: str,
    agent_id: str,
    scores: list,
    base_ts: float = None,
) -> None:
    """Insert purpose scores, evenly spaced 60 s apart, oldest first."""
    conn = sqlite3.connect(path)
    now = base_ts or time.time()
    for i, score in enumerate(scores):
        ts = now - (len(scores) - 1 - i) * 60
        conn.execute(
            """
            INSERT INTO audit_log
            (id, timestamp, agent_id, action, resource, decision,
             trust_score, purpose_score, full_json, attack_flags)
            VALUES (?, ?, ?, 'read', '/r', 'PERMIT', 80.0, ?, '{}', '[]')
            """,
            (str(uuid.uuid4()), ts, agent_id, score),
        )
    conn.commit()
    conn.close()


# ── test classes ───────────────────────────────────────────────────────────────

class TestGetPurposeScoreHistory(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db = self.tmp.name
        _make_db(self.db)

    def test_empty_db_returns_empty_list(self):
        self.assertEqual(get_purpose_score_history("agent1", db_path=self.db), [])

    def test_returns_scores_for_correct_agent(self):
        _insert_scores(self.db, "agent1", [70.0, 72.0, 68.0])
        _insert_scores(self.db, "agent2", [50.0, 55.0])
        self.assertEqual(len(get_purpose_score_history("agent1", db_path=self.db)), 3)

    def test_scores_are_floats(self):
        _insert_scores(self.db, "agent1", [60.0, 70.0])
        for s in get_purpose_score_history("agent1", db_path=self.db):
            self.assertIsInstance(s, float)

    def test_ordered_oldest_first(self):
        _insert_scores(self.db, "agent1", [40.0, 60.0, 80.0])
        scores = get_purpose_score_history("agent1", db_path=self.db)
        self.assertEqual(scores[0], 40.0)
        self.assertEqual(scores[-1], 80.0)

    def test_excludes_entries_older_than_max_age(self):
        old_ts = time.time() - DRIFT_MAX_AGE_SECONDS - 3600
        _insert_scores(self.db, "agent1", [90.0], base_ts=old_ts)
        _insert_scores(self.db, "agent1", [50.0, 50.0, 50.0])
        scores = get_purpose_score_history("agent1", db_path=self.db)
        self.assertEqual(len(scores), 3)

    def test_missing_table_returns_empty(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            empty = f.name
        scores = get_purpose_score_history("agent1", db_path=empty)
        self.assertEqual(scores, [])

    def test_accepts_path_object(self):
        _insert_scores(self.db, "agent1", [65.0])
        s1 = get_purpose_score_history("agent1", db_path=self.db)
        s2 = get_purpose_score_history("agent1", db_path=Path(self.db))
        self.assertEqual(s1, s2)

    def test_null_purpose_scores_excluded(self):
        conn = sqlite3.connect(self.db)
        conn.execute(
            "INSERT INTO audit_log (id, timestamp, agent_id, action, resource, "
            "decision, trust_score, purpose_score, full_json, attack_flags) "
            "VALUES (?, ?, ?, 'read', '/r', 'PERMIT', 80.0, NULL, '{}', '[]')",
            (str(uuid.uuid4()), time.time(), "agent1"),
        )
        conn.commit()
        conn.close()
        scores = get_purpose_score_history("agent1", db_path=self.db)
        self.assertEqual(scores, [])


class TestNoDriftDetected(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db = self.tmp.name
        _make_db(self.db)

    def test_empty_history_no_flags(self):
        self.assertEqual(detect_purpose_drift("agent1", db_path=self.db), [])

    def test_below_min_entries_no_flags(self):
        _insert_scores(self.db, "agent1", [30.0] * (MIN_ENTRIES_FOR_DRIFT - 1))
        self.assertEqual(detect_purpose_drift("agent1", db_path=self.db), [])

    def test_exactly_min_entries_activates_detection(self):
        # At exactly MIN_ENTRIES_FOR_DRIFT, detection activates but no drift if stable
        _insert_scores(self.db, "agent1", [70.0] * MIN_ENTRIES_FOR_DRIFT)
        flags = detect_purpose_drift("agent1", db_path=self.db)
        self.assertFalse(any("GRADUAL" in f for f in flags))
        self.assertFalse(any("SUSTAINED_LOW" in f for f in flags))

    def test_stable_high_scores_no_flags(self):
        _insert_scores(self.db, "agent1", [75.0] * (BASELINE_WINDOW + RECENT_WINDOW))
        self.assertEqual(detect_purpose_drift("agent1", db_path=self.db), [])

    def test_increasing_trend_no_gradual_flag(self):
        scores = [float(50 + i) for i in range(MIN_ENTRIES_FOR_DRIFT + 5)]
        _insert_scores(self.db, "agent1", scores)
        flags = detect_purpose_drift("agent1", db_path=self.db)
        self.assertFalse(any("GRADUAL" in f for f in flags))

    def test_drop_below_threshold_no_gradual_flag(self):
        baseline = [75.0] * BASELINE_WINDOW
        drop = DRIFT_THRESHOLD_GRADUAL - 1.0
        recent = [75.0 - drop] * RECENT_WINDOW
        _insert_scores(self.db, "agent1", baseline + recent)
        flags = detect_purpose_drift("agent1", db_path=self.db)
        self.assertFalse(any("GRADUAL" in f for f in flags))

    def test_recent_avg_at_absolute_floor_no_sustained_low(self):
        # recent_avg == DRIFT_THRESHOLD_ABSOLUTE should NOT fire (strictly less-than)
        score = DRIFT_THRESHOLD_ABSOLUTE
        _insert_scores(self.db, "agent1", [score] * (BASELINE_WINDOW + RECENT_WINDOW))
        flags = detect_purpose_drift("agent1", db_path=self.db)
        self.assertFalse(any("SUSTAINED_LOW" in f for f in flags))

    def test_mid_dip_followed_by_recovery_no_gradual(self):
        baseline = [75.0] * BASELINE_WINDOW
        middle_dip = [20.0] * 15
        recovery = [75.0] * RECENT_WINDOW
        _insert_scores(self.db, "agent1", baseline + middle_dip + recovery)
        flags = detect_purpose_drift("agent1", db_path=self.db)
        self.assertFalse(any("GRADUAL" in f for f in flags))


class TestGradualDrift(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db = self.tmp.name
        _make_db(self.db)

    def test_significant_drop_raises_gradual_flag(self):
        baseline = [80.0] * BASELINE_WINDOW
        recent = [80.0 - DRIFT_THRESHOLD_GRADUAL] * RECENT_WINDOW
        _insert_scores(self.db, "agent1", baseline + recent)
        flags = detect_purpose_drift("agent1", db_path=self.db)
        self.assertTrue(any("PURPOSE_DRIFT:GRADUAL" in f for f in flags))

    def test_flag_contains_delta(self):
        baseline = [80.0] * BASELINE_WINDOW
        recent = [50.0] * RECENT_WINDOW
        _insert_scores(self.db, "agent1", baseline + recent)
        gradual = [f for f in detect_purpose_drift("agent1", db_path=self.db)
                   if "GRADUAL" in f]
        self.assertEqual(len(gradual), 1)
        self.assertIn("30pts", gradual[0])

    def test_flag_contains_baseline_and_recent_avg(self):
        baseline = [80.0] * BASELINE_WINDOW
        recent = [50.0] * RECENT_WINDOW
        _insert_scores(self.db, "agent1", baseline + recent)
        gradual = [f for f in detect_purpose_drift("agent1", db_path=self.db)
                   if "GRADUAL" in f]
        self.assertIn("baseline=80", gradual[0])
        self.assertIn("recent=50", gradual[0])

    def test_large_drop_raises_gradual_flag(self):
        baseline = [90.0] * BASELINE_WINDOW
        recent = [25.0] * RECENT_WINDOW
        _insert_scores(self.db, "agent1", baseline + recent)
        self.assertTrue(any("GRADUAL" in f
                            for f in detect_purpose_drift("agent1", db_path=self.db)))

    def test_only_recent_window_used_for_comparison(self):
        # Recent window is high; only middle entries are low — no GRADUAL flag
        baseline = [75.0] * BASELINE_WINDOW
        middle = [20.0] * 20
        recent = [75.0] * RECENT_WINDOW
        _insert_scores(self.db, "agent1", baseline + middle + recent)
        flags = detect_purpose_drift("agent1", db_path=self.db)
        self.assertFalse(any("GRADUAL" in f for f in flags))

    def test_flag_starts_with_purpose_drift_prefix(self):
        baseline = [80.0] * BASELINE_WINDOW
        recent = [50.0] * RECENT_WINDOW
        _insert_scores(self.db, "agent1", baseline + recent)
        for f in detect_purpose_drift("agent1", db_path=self.db):
            self.assertTrue(f.startswith("PURPOSE_DRIFT:"))


class TestSustainedLow(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db = self.tmp.name
        _make_db(self.db)

    def test_recent_avg_below_absolute_raises_flag(self):
        low = DRIFT_THRESHOLD_ABSOLUTE - 5.0
        _insert_scores(self.db, "agent1", [low] * (BASELINE_WINDOW + RECENT_WINDOW))
        self.assertTrue(any("SUSTAINED_LOW" in f
                            for f in detect_purpose_drift("agent1", db_path=self.db)))

    def test_flag_contains_recent_avg(self):
        low = 25.0
        _insert_scores(self.db, "agent1", [low] * (BASELINE_WINDOW + RECENT_WINDOW))
        sustained = [f for f in detect_purpose_drift("agent1", db_path=self.db)
                     if "SUSTAINED_LOW" in f]
        self.assertEqual(len(sustained), 1)
        self.assertIn("recent_avg=25", sustained[0])

    def test_both_flags_fire_simultaneously(self):
        baseline = [80.0] * BASELINE_WINDOW
        recent = [20.0] * RECENT_WINDOW
        _insert_scores(self.db, "agent1", baseline + recent)
        flags = detect_purpose_drift("agent1", db_path=self.db)
        self.assertTrue(any("GRADUAL" in f for f in flags))
        self.assertTrue(any("SUSTAINED_LOW" in f for f in flags))

    def test_both_flags_exactly_two_items(self):
        baseline = [85.0] * BASELINE_WINDOW
        recent = [20.0] * RECENT_WINDOW
        _insert_scores(self.db, "agent1", baseline + recent)
        flags = detect_purpose_drift("agent1", db_path=self.db)
        self.assertEqual(len(flags), 2)

    def test_very_low_recent_avg_fires_both(self):
        baseline = [90.0] * BASELINE_WINDOW
        recent = [5.0] * RECENT_WINDOW
        _insert_scores(self.db, "agent1", baseline + recent)
        flags = detect_purpose_drift("agent1", db_path=self.db)
        self.assertEqual(sum(1 for f in flags if "GRADUAL" in f), 1)
        self.assertEqual(sum(1 for f in flags if "SUSTAINED_LOW" in f), 1)


class TestConstants(unittest.TestCase):

    def test_recent_window_positive(self):
        self.assertGreater(RECENT_WINDOW, 0)

    def test_baseline_window_larger_than_recent(self):
        self.assertGreater(BASELINE_WINDOW, RECENT_WINDOW)

    def test_min_entries_at_least_recent_window(self):
        self.assertGreaterEqual(MIN_ENTRIES_FOR_DRIFT, RECENT_WINDOW)

    def test_drift_threshold_gradual_positive(self):
        self.assertGreater(DRIFT_THRESHOLD_GRADUAL, 0.0)

    def test_drift_threshold_gradual_less_than_100(self):
        self.assertLess(DRIFT_THRESHOLD_GRADUAL, 100.0)

    def test_drift_threshold_absolute_between_0_and_100(self):
        self.assertGreater(DRIFT_THRESHOLD_ABSOLUTE, 0.0)
        self.assertLess(DRIFT_THRESHOLD_ABSOLUTE, 100.0)

    def test_drift_max_age_is_24h(self):
        self.assertEqual(DRIFT_MAX_AGE_SECONDS, 86_400.0)

    def test_gradual_threshold_larger_than_absolute_noise(self):
        # Gradual threshold should be meaningfully large relative to absolute threshold
        self.assertGreater(DRIFT_THRESHOLD_GRADUAL, 5.0)


class TestAgentIsolation(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db = self.tmp.name
        _make_db(self.db)

    def test_drifting_agent_does_not_affect_stable_agent(self):
        baseline = [80.0] * BASELINE_WINDOW
        recent = [20.0] * RECENT_WINDOW
        _insert_scores(self.db, "drifting_agent", baseline + recent)
        _insert_scores(self.db, "stable_agent", [75.0] * (BASELINE_WINDOW + RECENT_WINDOW))
        self.assertTrue(any("GRADUAL" in f
                            for f in detect_purpose_drift("drifting_agent", db_path=self.db)))
        self.assertEqual(detect_purpose_drift("stable_agent", db_path=self.db), [])

    def test_unknown_agent_returns_empty(self):
        _insert_scores(self.db, "other_agent", [70.0] * (BASELINE_WINDOW + RECENT_WINDOW))
        self.assertEqual(detect_purpose_drift("nonexistent", db_path=self.db), [])

    def test_two_agents_drifting_independently(self):
        baseline_a = [80.0] * BASELINE_WINDOW
        recent_a = [20.0] * RECENT_WINDOW
        _insert_scores(self.db, "agent_a", baseline_a + recent_a)

        baseline_b = [70.0] * BASELINE_WINDOW
        recent_b = [30.0] * RECENT_WINDOW
        _insert_scores(self.db, "agent_b", baseline_b + recent_b)

        flags_a = detect_purpose_drift("agent_a", db_path=self.db)
        flags_b = detect_purpose_drift("agent_b", db_path=self.db)

        self.assertTrue(any("GRADUAL" in f for f in flags_a))
        self.assertTrue(any("GRADUAL" in f for f in flags_b))


if __name__ == "__main__":
    unittest.main()
