"""
Stdlib-only tests for core/resource_hammering.py (Detector 7).

No pydantic, fastapi, or sentence-transformers required.
All timestamps are constructed relative to time.time() to ensure window-boundary
assertions are time-independent.
"""

import time
import unittest

from core.resource_hammering import (
    detect_resource_hammering,
    _normalize,
    HAMMERING_ESCALATE_THRESHOLD,
    HAMMERING_DENY_THRESHOLD,
    _FAST_WINDOW_SECONDS,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_history(resource: str, count: int, delta_seconds: float = 10.0) -> list[dict]:
    """Return `count` history entries for `resource`, each delta_seconds old."""
    now = time.time()
    return [
        {"action": "read", "resource": resource, "timestamp": now - delta_seconds}
        for _ in range(count)
    ]


def _make_entry(resource: str, delta_seconds: float, action: str = "read") -> dict:
    return {"action": action, "resource": resource, "timestamp": time.time() - delta_seconds}


# ── Test classes ──────────────────────────────────────────────────────────────

class TestNormalize(unittest.TestCase):
    """_normalize() must URL-decode, lowercase, and POSIX-normalize."""

    def test_simple_path_unchanged(self):
        self.assertEqual(_normalize("/reports/q3.pdf"), "/reports/q3.pdf")

    def test_uppercase_to_lower(self):
        self.assertEqual(_normalize("/Reports/Q3.PDF"), "/reports/q3.pdf")

    def test_percent_encoded_decoded(self):
        self.assertEqual(_normalize("/reports%2Fq3.pdf"), "/reports/q3.pdf")

    def test_space_encoded(self):
        self.assertEqual(_normalize("/my%20file.txt"), "/my file.txt")

    def test_trailing_slash_normalized(self):
        # posixpath.normpath strips trailing slash
        self.assertEqual(_normalize("/reports/"), "/reports")

    def test_dotdot_normalized(self):
        self.assertEqual(_normalize("/reports/../confidential"), "/confidential")

    def test_double_slash_normalized(self):
        self.assertEqual(_normalize("/reports//q3.pdf"), "/reports/q3.pdf")

    def test_mixed_case_and_encoding(self):
        self.assertEqual(_normalize("/Reports%2FQ3.PDF"), "/reports/q3.pdf")

    def test_root_path(self):
        self.assertEqual(_normalize("/"), "/")

    def test_no_leading_slash(self):
        result = _normalize("reports/q3.pdf")
        self.assertIn("reports", result)
        self.assertIn("q3.pdf", result)


class TestBelowThreshold(unittest.TestCase):
    """No flag when total accesses are below HAMMERING_ESCALATE_THRESHOLD."""

    def test_empty_history(self):
        # Total = 1 (just current request)
        result = detect_resource_hammering("read", "/reports/q3.pdf", [])
        self.assertEqual(result, [])

    def test_one_prior_access(self):
        # Total = 2
        history = _make_history("/reports/q3.pdf", 1)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertEqual(result, [])

    def test_five_prior_accesses(self):
        # Total = 6, below threshold of 8
        history = _make_history("/reports/q3.pdf", 5)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertEqual(result, [])

    def test_six_prior_accesses(self):
        # Total = 7, still below threshold of 8
        history = _make_history("/reports/q3.pdf", 6)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertEqual(result, [])

    def test_all_different_resources(self):
        # Many history entries, but all for different resources
        history = [_make_entry(f"/reports/q{i}.pdf", 10.0) for i in range(20)]
        result = detect_resource_hammering("read", "/reports/target.pdf", history)
        self.assertEqual(result, [])

    def test_old_accesses_dont_count(self):
        # 7 accesses but all outside the fast window → total = 1 → no flag
        history = _make_history("/reports/q3.pdf", 7, delta_seconds=400.0)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertEqual(result, [])

    def test_mixed_resources_each_below_threshold(self):
        # 4 accesses to resource A and 3 to resource B, neither reaches 8
        history = (
            _make_history("/reports/a.pdf", 4)
            + _make_history("/reports/b.pdf", 3)
        )
        result_a = detect_resource_hammering("read", "/reports/a.pdf", history)
        result_b = detect_resource_hammering("read", "/reports/b.pdf", history)
        self.assertEqual(result_a, [])
        self.assertEqual(result_b, [])

    def test_just_below_escalate_threshold_with_old_entries(self):
        # 3 in window + 100 outside window → total 4 → no flag
        history = (
            _make_history("/r.txt", 3, delta_seconds=10.0)
            + _make_history("/r.txt", 100, delta_seconds=400.0)
        )
        result = detect_resource_hammering("read", "/r.txt", history)
        self.assertEqual(result, [])


class TestEscalateLevel(unittest.TestCase):
    """ESCALATE flag (non-HARD) fires at HAMMERING_ESCALATE_THRESHOLD."""

    def test_exactly_at_escalate_threshold(self):
        # Total = THRESHOLD → ESCALATE flag
        prior = HAMMERING_ESCALATE_THRESHOLD - 1
        history = _make_history("/reports/q3.pdf", prior)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertEqual(len(result), 1)
        self.assertIn("KILL_CHAIN:RESOURCE_HAMMERING", result[0])
        self.assertNotIn("HARD", result[0])

    def test_one_above_escalate_threshold(self):
        prior = HAMMERING_ESCALATE_THRESHOLD
        history = _make_history("/reports/q3.pdf", prior)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertEqual(len(result), 1)
        self.assertNotIn("HARD", result[0])

    def test_escalate_flag_contains_resource(self):
        prior = HAMMERING_ESCALATE_THRESHOLD - 1
        resource = "/reports/q3.pdf"
        history = _make_history(resource, prior)
        result = detect_resource_hammering("read", resource, history)
        self.assertIn(resource, result[0])

    def test_escalate_flag_contains_count(self):
        prior = HAMMERING_ESCALATE_THRESHOLD - 1
        total = prior + 1
        history = _make_history("/reports/q3.pdf", prior)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertIn(str(total), result[0])

    def test_escalate_flag_contains_window_label(self):
        prior = HAMMERING_ESCALATE_THRESHOLD - 1
        history = _make_history("/reports/q3.pdf", prior)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertIn("5min", result[0])

    def test_escalate_flag_starts_with_kill_chain(self):
        prior = HAMMERING_ESCALATE_THRESHOLD - 1
        history = _make_history("/reports/q3.pdf", prior)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertTrue(result[0].startswith("KILL_CHAIN:RESOURCE_HAMMERING:"))

    def test_mid_range_escalate(self):
        # 14 prior → total 15 → still ESCALATE (below DENY threshold of 20)
        prior = 14
        self.assertGreater(prior + 1, HAMMERING_ESCALATE_THRESHOLD)
        self.assertLess(prior + 1, HAMMERING_DENY_THRESHOLD)
        history = _make_history("/reports/q3.pdf", prior)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertEqual(len(result), 1)
        self.assertNotIn("HARD", result[0])

    def test_just_below_deny_threshold(self):
        prior = HAMMERING_DENY_THRESHOLD - 2  # total = DENY_THRESHOLD - 1
        history = _make_history("/reports/q3.pdf", prior)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertEqual(len(result), 1)
        self.assertNotIn("HARD", result[0])


class TestDenyLevel(unittest.TestCase):
    """Hard DENY flag fires at HAMMERING_DENY_THRESHOLD."""

    def test_exactly_at_deny_threshold(self):
        prior = HAMMERING_DENY_THRESHOLD - 1
        history = _make_history("/reports/q3.pdf", prior)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertEqual(len(result), 1)
        self.assertIn("HARD", result[0])

    def test_one_above_deny_threshold(self):
        prior = HAMMERING_DENY_THRESHOLD
        history = _make_history("/reports/q3.pdf", prior)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertEqual(len(result), 1)
        self.assertIn("HARD", result[0])

    def test_deny_flag_starts_with_hard_prefix(self):
        prior = HAMMERING_DENY_THRESHOLD - 1
        history = _make_history("/reports/q3.pdf", prior)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertTrue(result[0].startswith("KILL_CHAIN:RESOURCE_HAMMERING:HARD:"))

    def test_deny_flag_contains_resource(self):
        prior = HAMMERING_DENY_THRESHOLD - 1
        resource = "/confidential/salary.xlsx"
        history = _make_history(resource, prior)
        result = detect_resource_hammering("read", resource, history)
        self.assertIn(resource, result[0])

    def test_deny_flag_contains_correct_count(self):
        prior = HAMMERING_DENY_THRESHOLD - 1
        total = prior + 1
        history = _make_history("/reports/q3.pdf", prior)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertIn(str(total), result[0])

    def test_extreme_count_still_hard(self):
        prior = 100
        history = _make_history("/reports/q3.pdf", prior)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertIn("HARD", result[0])

    def test_deny_flag_contains_window_label(self):
        prior = HAMMERING_DENY_THRESHOLD - 1
        history = _make_history("/reports/q3.pdf", prior)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertIn("5min", result[0])


class TestWindowFiltering(unittest.TestCase):
    """Only history within _FAST_WINDOW_SECONDS counts."""

    def test_entries_in_window_count(self):
        # 7 entries within window → total 8 → ESCALATE
        history = _make_history("/reports/q3.pdf", 7, delta_seconds=100.0)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertEqual(len(result), 1)

    def test_entries_outside_window_excluded(self):
        # 19 entries, all outside window → total 1 (only current) → no flag
        history = _make_history("/reports/q3.pdf", 19, delta_seconds=400.0)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertEqual(result, [])

    def test_mixed_window_partial_count(self):
        # 3 in window + 20 outside → total 4 → no flag
        in_window = _make_history("/reports/q3.pdf", 3, delta_seconds=60.0)
        out_window = _make_history("/reports/q3.pdf", 20, delta_seconds=400.0)
        result = detect_resource_hammering("read", "/reports/q3.pdf", in_window + out_window)
        self.assertEqual(result, [])

    def test_mixed_window_reaches_escalate(self):
        # 7 in window + 10 outside → total 8 → ESCALATE
        in_window = _make_history("/reports/q3.pdf", 7, delta_seconds=60.0)
        out_window = _make_history("/reports/q3.pdf", 10, delta_seconds=400.0)
        result = detect_resource_hammering("read", "/reports/q3.pdf", in_window + out_window)
        self.assertEqual(len(result), 1)

    def test_entry_well_within_window(self):
        history = _make_history("/reports/q3.pdf", 7, delta_seconds=1.0)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertEqual(len(result), 1)

    def test_deny_level_requires_in_window_entries(self):
        # 19 in window → total 20 → hard DENY
        history = _make_history("/reports/q3.pdf", 19, delta_seconds=60.0)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertIn("HARD", result[0])

    def test_deny_blocked_by_window(self):
        # 19 entries outside window → total 1 → no flag (hard DENY threshold not reached)
        history = _make_history("/reports/q3.pdf", 19, delta_seconds=350.0)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertEqual(result, [])

    def test_zero_second_old_entry_counted(self):
        # Entry with timestamp = now (0 seconds old) must be within window
        history = [_make_entry("/reports/q3.pdf", 0.0)]
        # Total = 2 → below threshold but entry should be counted
        resource = "/reports/q3.pdf"
        target = _normalize(resource)
        prior = sum(
            1 for h in history
            if time.time() - h["timestamp"] <= _FAST_WINDOW_SECONDS
            and _normalize(h.get("resource", "")) == target
        )
        self.assertEqual(prior, 1)


class TestResourceIsolation(unittest.TestCase):
    """Accesses to different resources do not interfere with each other."""

    def test_different_resource_not_counted(self):
        # 19 accesses to /other, current request is /target → no flag for /target
        history = _make_history("/other/file.txt", 19)
        result = detect_resource_hammering("read", "/target/file.txt", history)
        self.assertEqual(result, [])

    def test_similar_but_distinct_paths(self):
        # /reports/q3.pdf vs /reports/q3.pdf.bak — distinct paths
        history = _make_history("/reports/q3.pdf.bak", 19)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertEqual(result, [])

    def test_prefix_match_not_applied(self):
        # /reports/q3 should not match /reports/q3.pdf
        history = _make_history("/reports/q3", 19)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertEqual(result, [])

    def test_case_insensitive_matching(self):
        # History has uppercase, current is lowercase — should match after normalization
        history = _make_history("/Reports/Q3.PDF", 7)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertEqual(len(result), 1)

    def test_encoded_vs_decoded_match(self):
        # Percent-encoded path in history vs decoded in current request
        history = _make_history("/reports%2Fq3.pdf", 7)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertEqual(len(result), 1)

    def test_two_hammered_resources_independent(self):
        # Both /a.pdf and /b.pdf hammered — each request is evaluated independently
        history_a = _make_history("/a.pdf", 7)
        history_b = _make_history("/b.pdf", 7)
        combined = history_a + history_b

        result_a = detect_resource_hammering("read", "/a.pdf", combined)
        result_b = detect_resource_hammering("read", "/b.pdf", combined)

        self.assertEqual(len(result_a), 1)
        self.assertEqual(len(result_b), 1)


class TestActionVariance(unittest.TestCase):
    """Any action on the same resource counts, regardless of action type."""

    def test_all_reads_count(self):
        history = [_make_entry("/reports/q3.pdf", 10.0, action="read") for _ in range(7)]
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertEqual(len(result), 1)

    def test_all_writes_count(self):
        history = [_make_entry("/reports/q3.pdf", 10.0, action="write") for _ in range(7)]
        result = detect_resource_hammering("write", "/reports/q3.pdf", history)
        self.assertEqual(len(result), 1)

    def test_mixed_actions_count(self):
        # 3 reads + 4 writes on same resource → total 8 → ESCALATE
        reads = [_make_entry("/reports/q3.pdf", 10.0, action="read") for _ in range(3)]
        writes = [_make_entry("/reports/q3.pdf", 10.0, action="write") for _ in range(4)]
        result = detect_resource_hammering("read", "/reports/q3.pdf", reads + writes)
        self.assertEqual(len(result), 1)

    def test_current_action_type_irrelevant_to_count(self):
        # History has only reads; current action is delete — still escalates on same resource
        history = _make_history("/reports/q3.pdf", 7)
        result_delete = detect_resource_hammering("delete", "/reports/q3.pdf", history)
        result_read = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertEqual(len(result_delete), 1)
        self.assertEqual(len(result_read), 1)


class TestReturnType(unittest.TestCase):
    """Return value is always a list of strings."""

    def test_returns_list_when_clean(self):
        result = detect_resource_hammering("read", "/reports/q3.pdf", [])
        self.assertIsInstance(result, list)

    def test_returns_list_when_escalate(self):
        history = _make_history("/reports/q3.pdf", HAMMERING_ESCALATE_THRESHOLD - 1)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertIsInstance(result, list)

    def test_returns_list_when_deny(self):
        history = _make_history("/reports/q3.pdf", HAMMERING_DENY_THRESHOLD - 1)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertIsInstance(result, list)

    def test_never_returns_none(self):
        self.assertIsNotNone(detect_resource_hammering("read", "/x", []))

    def test_at_most_one_flag(self):
        # Escalate and deny are mutually exclusive; result is at most one flag
        history = _make_history("/reports/q3.pdf", HAMMERING_DENY_THRESHOLD - 1)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertLessEqual(len(result), 1)

    def test_all_elements_are_strings(self):
        history = _make_history("/reports/q3.pdf", HAMMERING_ESCALATE_THRESHOLD - 1)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        for flag in result:
            self.assertIsInstance(flag, str)


class TestFlagFormat(unittest.TestCase):
    """Flag strings follow the KILL_CHAIN:RESOURCE_HAMMERING[:HARD]:{N}_in_5min:{resource} convention."""

    def test_escalate_flag_prefix(self):
        prior = HAMMERING_ESCALATE_THRESHOLD - 1
        history = _make_history("/reports/q3.pdf", prior)
        flag = detect_resource_hammering("read", "/reports/q3.pdf", history)[0]
        self.assertTrue(flag.startswith("KILL_CHAIN:RESOURCE_HAMMERING:"))

    def test_deny_flag_prefix(self):
        prior = HAMMERING_DENY_THRESHOLD - 1
        history = _make_history("/reports/q3.pdf", prior)
        flag = detect_resource_hammering("read", "/reports/q3.pdf", history)[0]
        self.assertTrue(flag.startswith("KILL_CHAIN:RESOURCE_HAMMERING:HARD:"))

    def test_count_in_escalate_flag_is_accurate(self):
        prior = HAMMERING_ESCALATE_THRESHOLD - 1
        expected_total = prior + 1
        history = _make_history("/reports/q3.pdf", prior)
        flag = detect_resource_hammering("read", "/reports/q3.pdf", history)[0]
        self.assertIn(f"{expected_total}_in_5min", flag)

    def test_count_in_deny_flag_is_accurate(self):
        prior = HAMMERING_DENY_THRESHOLD - 1
        expected_total = prior + 1
        history = _make_history("/reports/q3.pdf", prior)
        flag = detect_resource_hammering("read", "/reports/q3.pdf", history)[0]
        self.assertIn(f"{expected_total}_in_5min", flag)

    def test_original_resource_preserved_in_flag(self):
        # The flag should contain the original resource, not the normalized form
        resource = "/Reports/Q3.PDF"
        history = _make_history(resource, HAMMERING_ESCALATE_THRESHOLD - 1)
        flag = detect_resource_hammering("read", resource, history)[0]
        self.assertIn(resource, flag)

    def test_deny_flag_contains_in_5min(self):
        prior = HAMMERING_DENY_THRESHOLD - 1
        history = _make_history("/reports/q3.pdf", prior)
        flag = detect_resource_hammering("read", "/reports/q3.pdf", history)[0]
        self.assertIn("_in_5min:", flag)


class TestConstants(unittest.TestCase):
    """Module constants are within sensible operational ranges."""

    def test_escalate_threshold_is_positive_integer(self):
        self.assertIsInstance(HAMMERING_ESCALATE_THRESHOLD, int)
        self.assertGreater(HAMMERING_ESCALATE_THRESHOLD, 0)

    def test_deny_threshold_is_positive_integer(self):
        self.assertIsInstance(HAMMERING_DENY_THRESHOLD, int)
        self.assertGreater(HAMMERING_DENY_THRESHOLD, 0)

    def test_deny_threshold_greater_than_escalate(self):
        self.assertGreater(HAMMERING_DENY_THRESHOLD, HAMMERING_ESCALATE_THRESHOLD)

    def test_fast_window_is_positive(self):
        self.assertGreater(_FAST_WINDOW_SECONDS, 0)

    def test_escalate_threshold_in_reasonable_range(self):
        self.assertGreater(HAMMERING_ESCALATE_THRESHOLD, 2)
        self.assertLess(HAMMERING_ESCALATE_THRESHOLD, 50)

    def test_deny_threshold_in_reasonable_range(self):
        self.assertGreater(HAMMERING_DENY_THRESHOLD, 10)
        self.assertLess(HAMMERING_DENY_THRESHOLD, 100)

    def test_fast_window_matches_5_minutes(self):
        self.assertEqual(_FAST_WINDOW_SECONDS, 300.0)

    def test_deny_at_least_double_escalate(self):
        # Deny threshold should be meaningfully above escalate to avoid conflation
        self.assertGreaterEqual(HAMMERING_DENY_THRESHOLD, HAMMERING_ESCALATE_THRESHOLD * 2)


class TestEdgeCases(unittest.TestCase):
    """Edge cases and robustness."""

    def test_resource_with_encoded_slash(self):
        # %2F in resource — normalized forms should match
        history = _make_history("/reports%2Fq3.pdf", 7)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertEqual(len(result), 1)

    def test_root_resource(self):
        # Resource "/" — hammer detection should still work
        history = _make_history("/", 7)
        result = detect_resource_hammering("read", "/", history)
        self.assertEqual(len(result), 1)

    def test_very_long_resource_path(self):
        resource = "/a/" * 200 + "file.txt"
        history = _make_history(resource, 7)
        result = detect_resource_hammering("read", resource, history)
        self.assertEqual(len(result), 1)

    def test_resource_with_spaces(self):
        resource = "/my documents/q3 report.pdf"
        history = _make_history(resource, 7)
        result = detect_resource_hammering("read", resource, history)
        self.assertEqual(len(result), 1)

    def test_history_missing_resource_key(self):
        # Entries without 'resource' key should not crash
        history = [{"action": "read", "timestamp": time.time() - 10.0}]
        try:
            result = detect_resource_hammering("read", "/reports/q3.pdf", history)
            self.assertIsInstance(result, list)
        except (KeyError, AttributeError):
            self.fail("detect_resource_hammering raised on missing 'resource' key")

    def test_empty_string_resource_in_history(self):
        # Empty resource in history entry should not match a real resource
        history = [{"action": "read", "resource": "", "timestamp": time.time() - 10.0}]
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertEqual(result, [])

    def test_large_history_performance(self):
        # 5000 entries — must complete without error
        history = _make_history("/reports/q3.pdf", 5000)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertEqual(len(result), 1)
        self.assertIn("HARD", result[0])

    def test_current_request_always_adds_one(self):
        # With zero history, count is 1 (current request only) → below threshold
        result = detect_resource_hammering("read", "/reports/q3.pdf", [])
        self.assertEqual(result, [])


class TestCurrentRequestCounted(unittest.TestCase):
    """The current (not-yet-executed) request must be included in the total count."""

    def test_prior_count_plus_one_reaches_escalate(self):
        # ESCALATE_THRESHOLD - 1 prior entries → total exactly at threshold → ESCALATE
        prior = HAMMERING_ESCALATE_THRESHOLD - 1
        history = _make_history("/reports/q3.pdf", prior)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertEqual(len(result), 1)

    def test_prior_count_one_short_no_flag(self):
        # ESCALATE_THRESHOLD - 2 prior entries → total one below threshold → no flag
        prior = HAMMERING_ESCALATE_THRESHOLD - 2
        history = _make_history("/reports/q3.pdf", prior)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertEqual(result, [])

    def test_prior_count_reaches_deny(self):
        prior = HAMMERING_DENY_THRESHOLD - 1
        history = _make_history("/reports/q3.pdf", prior)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertIn("HARD", result[0])

    def test_prior_count_one_short_of_deny(self):
        # total = DENY_THRESHOLD - 1 → ESCALATE, not DENY
        prior = HAMMERING_DENY_THRESHOLD - 2
        history = _make_history("/reports/q3.pdf", prior)
        result = detect_resource_hammering("read", "/reports/q3.pdf", history)
        self.assertEqual(len(result), 1)
        self.assertNotIn("HARD", result[0])


if __name__ == "__main__":
    unittest.main()
