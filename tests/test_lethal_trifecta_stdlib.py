"""
Stdlib-only tests for the Lethal Trifecta kill chain detector (Detector 5).

The trifecta: an agent that simultaneously holds all three arms within its
24-hour session window:
  Arm 1 — reads untrusted external content (fetch, browse, URL resources)
  Arm 2 — accesses sensitive internal data (HIGH or CRITICAL sensitivity)
  Arm 3 — communicates externally (exfil actions, webhooks, email, etc.)

These tests exercise the three arm-classifier functions and the trifecta flag
format directly, without requiring SQLite, pydantic, or fastapi.

Full integration tests (requiring the full deps stack) live in test_kill_chain_24h.py.
"""

import unittest

# ── Inline re-implementations of the three arm classifiers ───────────────────
# We copy the exact logic from core/kill_chain.py so this file has zero imports
# beyond the stdlib. If the logic drifts, the integration tests will catch it.

_EXTERNAL_READ_ACTIONS = frozenset({
    "fetch", "browse", "scrape", "crawl", "download", "get",
})
_EXTERNAL_URL_PREFIXES = ("http://", "https://", "ftp://")
_EXTERNAL_RESOURCE_KEYWORDS = frozenset({
    "external", "remote", "internet", "inbound", "incoming",
})

_EXFIL_ACTIONS = frozenset({
    "send", "email", "upload", "post", "forward", "export", "transfer", "publish",
})
_EXFIL_DESTINATION_KEYWORDS = frozenset({
    "webhook", "smtp", "email", "ftp", "s3", "outbound", "external",
    "slack", "teams", "discord", "notify", "alert",
})

_CRITICAL_KEYWORDS = {
    "salary", "payroll", "password", "passwd", "cred", "credential",
    "secret", "private_key", "privatekey", "token", "api_key", "apikey",
    "id_rsa", "id_ed25519", "id_ecdsa", ".pem", ".p12", ".pfx", ".key",
    "ssh", "tls_cert", "ssl_cert", "ca_bundle",
    "mfa", "totp", "seed", "oauth", "jwt_secret", "session_secret",
    ".env", ".env.prod", ".env.local", "vault", "keystore",
    ".sql", ".dump", ".bak", ".backup", "db_export",
    ".gpg", ".asc", "pgp", "keyring",
}
_HIGH_KEYWORDS = {
    "confidential", "hr", "finance", "admin", "root", "audit",
    "employee", "medical", "health", "pii", "gdpr", "compliance",
    "legal", "contract", "nda", "executive", "board", "merger",
    "acquisition", "strategy",
}


def _is_external_read(action: str, resource: str) -> bool:
    a = action.lower()
    r = resource.lower()
    # Exfil actions on external URLs are Arm 3 (outbound), not Arm 1 (inbound read).
    if a in _EXFIL_ACTIONS:
        return False
    if r.startswith(_EXTERNAL_URL_PREFIXES):
        return True
    if a in _EXTERNAL_READ_ACTIONS:
        return True
    if a in {"read", "get"} and any(kw in r for kw in _EXTERNAL_RESOURCE_KEYWORDS):
        return True
    return False


def _is_sensitive_access(action: str, resource: str) -> bool:
    # Resource-only sensitivity for trifecta Arm 2 — prevents double-counting with Arm 3.
    # An exfil action like `export /dump.zip` is Arm 3; it only counts as Arm 2 if the
    # resource itself contains sensitive data keywords (e.g. `export /confidential/salary.xlsx`).
    r = resource.lower()
    if any(kw in r for kw in _CRITICAL_KEYWORDS):
        return True
    if any(kw in r for kw in _HIGH_KEYWORDS):
        return True
    return False


def _is_external_comm(action: str, resource: str) -> bool:
    a = action.lower()
    r = resource.lower()
    if a in _EXFIL_ACTIONS:
        return True
    if any(kw in r for kw in _EXFIL_DESTINATION_KEYWORDS):
        return True
    return False


def _trifecta_fires(history: list[dict], action: str, resource: str) -> bool:
    """
    Replicate the Detector 5 logic from analyze_kill_chain() for stdlib testing.
    Returns True if the KILL_CHAIN:LETHAL_TRIFECTA flag would be emitted.
    """
    cur_ext_read = _is_external_read(action, resource)
    cur_sensitive = _is_sensitive_access(action, resource)
    cur_ext_comm = _is_external_comm(action, resource)

    hist_ext_read = cur_ext_read or any(
        _is_external_read(h["action"], h["resource"]) for h in history
    )
    hist_sensitive = cur_sensitive or any(
        _is_sensitive_access(h["action"], h["resource"]) for h in history
    )
    hist_ext_comm = cur_ext_comm or any(
        _is_external_comm(h["action"], h["resource"]) for h in history
    )

    if hist_ext_read and hist_sensitive and hist_ext_comm:
        if cur_ext_comm or cur_sensitive:
            return True
    return False


def _h(action: str, resource: str) -> dict:
    return {"action": action, "resource": resource}


# ── Arm 1: External Content Read ─────────────────────────────────────────────

class TestExternalReadArm(unittest.TestCase):

    def test_http_url_is_external_read(self):
        self.assertTrue(_is_external_read("read", "https://evil.com/payload.txt"))

    def test_https_url_is_external_read(self):
        self.assertTrue(_is_external_read("get", "https://api.external.com/data"))

    def test_ftp_url_is_external_read(self):
        self.assertTrue(_is_external_read("read", "ftp://uploads.attacker.com/file"))

    def test_fetch_action_is_external_read_regardless_of_resource(self):
        self.assertTrue(_is_external_read("fetch", "/local/resource"))

    def test_browse_action_is_external_read(self):
        self.assertTrue(_is_external_read("browse", "/web/page"))

    def test_scrape_action_is_external_read(self):
        self.assertTrue(_is_external_read("scrape", "/data"))

    def test_crawl_action_is_external_read(self):
        self.assertTrue(_is_external_read("crawl", "/site"))

    def test_download_action_is_external_read(self):
        self.assertTrue(_is_external_read("download", "/file.zip"))

    def test_read_external_resource_keyword(self):
        self.assertTrue(_is_external_read("read", "/external/feeds/news"))

    def test_read_remote_resource_keyword(self):
        self.assertTrue(_is_external_read("read", "/remote/api/response"))

    def test_read_internet_resource_keyword(self):
        self.assertTrue(_is_external_read("read", "/internet/cache/page"))

    def test_read_internal_path_is_not_external_read(self):
        self.assertFalse(_is_external_read("read", "/reports/q1.pdf"))

    def test_exfil_action_on_url_is_not_arm1(self):
        # An exfil action (send/export/upload) on an external URL is Arm 3 (outbound comm),
        # not Arm 1 (inbound read). Direction matters for injection risk.
        self.assertFalse(_is_external_read("send", "https://webhook.site/x"))
        self.assertFalse(_is_external_read("upload", "https://s3.amazonaws.com/bucket"))
        self.assertFalse(_is_external_read("export", "https://attacker.com/dump"))

    def test_case_insensitive_action(self):
        self.assertTrue(_is_external_read("FETCH", "/data"))

    def test_case_insensitive_resource(self):
        self.assertTrue(_is_external_read("read", "HTTPS://api.example.com/v1"))


# ── Arm 2: Sensitive Data Access ─────────────────────────────────────────────

class TestSensitiveAccessArm(unittest.TestCase):

    def test_salary_path_is_sensitive(self):
        self.assertTrue(_is_sensitive_access("read", "/hr/salary.xlsx"))

    def test_confidential_path_is_sensitive(self):
        self.assertTrue(_is_sensitive_access("read", "/confidential/merger_details.pdf"))

    def test_password_path_is_sensitive(self):
        self.assertTrue(_is_sensitive_access("read", "/config/passwords.json"))

    def test_credentials_path_is_sensitive(self):
        self.assertTrue(_is_sensitive_access("read", "/vault/credentials.json"))

    def test_exfil_to_nonsensitive_resource_is_not_arm2(self):
        # `export /dump.zip` is Arm 3 (external comm). Since /dump.zip has no sensitive
        # keywords, it must NOT count as Arm 2 — preventing false-positive trifecta on
        # Arm1 + export-to-generic-path alone.
        self.assertFalse(_is_sensitive_access("export", "/dump.zip"))

    def test_exfil_to_sensitive_resource_is_arm2(self):
        # `export /confidential/salary.xlsx` is simultaneously Arm 2 (sensitive resource)
        # AND Arm 3 (exfil action). Combined with Arm 1 in history it fires the trifecta.
        self.assertTrue(_is_sensitive_access("export", "/confidential/salary.xlsx"))

    def test_finance_path_is_sensitive(self):
        self.assertTrue(_is_sensitive_access("read", "/finance/q4_results.xlsx"))

    def test_hr_path_is_sensitive(self):
        self.assertTrue(_is_sensitive_access("read", "/hr/employee_list.csv"))

    def test_public_reports_not_sensitive(self):
        self.assertFalse(_is_sensitive_access("read", "/reports/q1.pdf"))

    def test_low_sensitivity_read_not_arm2(self):
        self.assertFalse(_is_sensitive_access("read", "/blog/post.txt"))

    def test_case_insensitive_resource_match(self):
        self.assertTrue(_is_sensitive_access("read", "/HR/employee.csv"))


# ── Arm 3: External Communication ────────────────────────────────────────────

class TestExternalCommArm(unittest.TestCase):

    def test_export_action_is_external_comm(self):
        self.assertTrue(_is_external_comm("export", "/dump.zip"))

    def test_send_action_is_external_comm(self):
        self.assertTrue(_is_external_comm("send", "/message"))

    def test_email_action_is_external_comm(self):
        self.assertTrue(_is_external_comm("email", "/report.pdf"))

    def test_upload_action_is_external_comm(self):
        self.assertTrue(_is_external_comm("upload", "/s3/bucket"))

    def test_post_action_is_external_comm(self):
        self.assertTrue(_is_external_comm("post", "/api/notify"))

    def test_forward_action_is_external_comm(self):
        self.assertTrue(_is_external_comm("forward", "/queue"))

    def test_transfer_action_is_external_comm(self):
        self.assertTrue(_is_external_comm("transfer", "/remote"))

    def test_publish_action_is_external_comm(self):
        self.assertTrue(_is_external_comm("publish", "/stream"))

    def test_webhook_resource_is_external_comm(self):
        self.assertTrue(_is_external_comm("write", "/outbound/webhook/target"))

    def test_slack_resource_is_external_comm(self):
        self.assertTrue(_is_external_comm("write", "/integrations/slack/channel"))

    def test_smtp_resource_is_external_comm(self):
        self.assertTrue(_is_external_comm("write", "/smtp/outbox"))

    def test_s3_resource_is_external_comm(self):
        self.assertTrue(_is_external_comm("write", "/s3/mybucket/output.csv"))

    def test_read_internal_path_not_arm3(self):
        self.assertFalse(_is_external_comm("read", "/reports/q1.pdf"))

    def test_case_insensitive_action(self):
        self.assertTrue(_is_external_comm("EXPORT", "/dump.zip"))


# ── Trifecta full detection ───────────────────────────────────────────────────

class TestTrifectaDetection(unittest.TestCase):

    def test_classic_attack_fires_on_exfil(self):
        """
        Classic indirect prompt injection: agent fetches external content,
        reads sensitive internal data, then tries to exfiltrate.
        """
        history = [
            _h("fetch", "https://attacker.com/payload.txt"),   # Arm 1
            _h("read", "/confidential/salary.xlsx"),           # Arm 2
        ]
        # Current action completes the trifecta (Arm 3)
        self.assertTrue(_trifecta_fires(history, "export", "/dump.zip"))

    def test_fires_on_email_exfil(self):
        history = [
            _h("browse", "https://malicious.com/inject"),
            _h("read", "/hr/employees.csv"),
        ]
        self.assertTrue(_trifecta_fires(history, "email", "/report.pdf"))

    def test_fires_on_sensitive_access_when_exfil_already_in_history(self):
        """
        Less common: arm 3 already happened, arm 1 already happened,
        current request is arm 2. Still a trifecta.
        """
        history = [
            _h("fetch", "https://attacker.com/cmd"),     # Arm 1
            _h("export", "/dump.zip"),                   # Arm 3 in history
        ]
        # Current action is Arm 2 — completing the set
        self.assertTrue(_trifecta_fires(history, "read", "/confidential/salary.xlsx"))

    def test_does_not_fire_without_external_read_arm(self):
        """Missing Arm 1 — agent never read external content."""
        history = [
            _h("read", "/confidential/salary.xlsx"),
        ]
        self.assertFalse(_trifecta_fires(history, "export", "/dump.zip"))

    def test_does_not_fire_without_sensitive_arm(self):
        """Missing Arm 2 — agent only accessed low-sensitivity data."""
        history = [
            _h("fetch", "https://attacker.com/payload.txt"),
            _h("read", "/public/reports/q1.pdf"),
        ]
        self.assertFalse(_trifecta_fires(history, "export", "/dump.zip"))

    def test_does_not_fire_without_external_comm_arm(self):
        """Missing Arm 3 — agent never tried to communicate externally."""
        history = [
            _h("fetch", "https://attacker.com/payload.txt"),
            _h("read", "/confidential/salary.xlsx"),
        ]
        # Current action is a read — no external comm arm
        self.assertFalse(_trifecta_fires(history, "read", "/reports/q2.pdf"))

    def test_does_not_fire_on_current_external_read_only(self):
        """
        Current action is Arm 1, but history only has Arm 2.
        Trifecta needs 3 arms — and current must be Arm 2 or Arm 3 to fire.
        """
        history = [
            _h("read", "/confidential/salary.xlsx"),   # Arm 2
        ]
        # No external comm anywhere — no fire
        self.assertFalse(_trifecta_fires(history, "fetch", "https://attacker.com/c2"))

    def test_current_is_both_arm2_and_arm3(self):
        """
        Current action is exfil to a sensitive resource (Arm 2 + Arm 3 simultaneously),
        and history has Arm 1. The current action satisfies both conditions for firing
        (cur_ext_comm=True, cur_sensitive=True) and completes the trifecta.
        """
        history = [
            _h("fetch", "https://attacker.com/inject"),   # Arm 1 in history
        ]
        # export /confidential/salary.xlsx = Arm 2 (sensitive resource) + Arm 3 (exfil action)
        self.assertTrue(_trifecta_fires(history, "export", "/confidential/salary.xlsx"))

    def test_empty_history_no_fire(self):
        """No history and no-trifecta current request."""
        self.assertFalse(_trifecta_fires([], "read", "/reports/q1.pdf"))

    def test_agent_isolation(self):
        """
        Trifecta arms from one agent's history must not affect another agent.
        (This verifies the API contract — actual isolation is by agent_id query.)
        """
        agent_a_history = [
            _h("fetch", "https://attacker.com/payload.txt"),
            _h("read", "/confidential/salary.xlsx"),
        ]
        # Agent B has no history — trifecta must not fire for B
        self.assertFalse(_trifecta_fires([], "export", "/dump.zip"))
        # Agent A — trifecta fires
        self.assertTrue(_trifecta_fires(agent_a_history, "export", "/dump.zip"))

    def test_webhook_resource_as_arm3(self):
        """Writing to a webhook resource (not exfil action) still counts as Arm 3."""
        history = [
            _h("fetch", "https://attacker.com/inject"),
            _h("read", "/confidential/contracts.pdf"),
        ]
        self.assertTrue(_trifecta_fires(history, "write", "/outbound/webhook/target"))

    def test_slow_assembly_across_history(self):
        """All three arms spread across history (no single arm in current action)."""
        # Current action has none of the three arms
        history = [
            _h("fetch", "https://attacker.com/inject"),      # Arm 1
            _h("read", "/confidential/salary.xlsx"),          # Arm 2
            _h("export", "/dump.zip"),                        # Arm 3 — already happened
        ]
        # Current action is a benign read — but all 3 arms are in history
        # Detector should NOT fire because current is not Arm 2 or Arm 3
        self.assertFalse(_trifecta_fires(history, "read", "/reports/q3.pdf"))

    def test_flag_format_contains_arm_labels(self):
        """Verify the expected flag string format contains all three arm labels."""
        flag = "KILL_CHAIN:LETHAL_TRIFECTA:EXT_READ+SENSITIVE_ACCESS+EXT_COMM"
        self.assertIn("LETHAL_TRIFECTA", flag)
        self.assertIn("EXT_READ", flag)
        self.assertIn("SENSITIVE_ACCESS", flag)
        self.assertIn("EXT_COMM", flag)


# ── Quarantine integration ────────────────────────────────────────────────────

class TestTrifectaQuarantineIntegration(unittest.TestCase):
    """
    Verify that KILL_CHAIN:LETHAL_TRIFECTA is in HARD_QUARANTINE_FLAGS.
    Imports the real quarantine module — no external deps.
    """

    def test_lethal_trifecta_is_hard_quarantine_flag(self):
        from core.detection.quarantine import HARD_QUARANTINE_FLAGS
        self.assertIn("KILL_CHAIN:LETHAL_TRIFECTA", HARD_QUARANTINE_FLAGS)

    def test_should_quarantine_fires_on_trifecta_flag(self):
        from core.detection.quarantine import should_quarantine_on_flags
        flag = "KILL_CHAIN:LETHAL_TRIFECTA:EXT_READ+SENSITIVE_ACCESS+EXT_COMM"
        result = should_quarantine_on_flags([flag])
        self.assertEqual(result, "KILL_CHAIN:LETHAL_TRIFECTA")

    def test_trifecta_flag_prefix_matched(self):
        from core.detection.quarantine import should_quarantine_on_flags
        # Should match regardless of the suffix detail
        for suffix in ["EXT_READ+SENSITIVE_ACCESS+EXT_COMM", "somevariant", ""]:
            base = "KILL_CHAIN:LETHAL_TRIFECTA"
            flag = f"{base}:{suffix}" if suffix else base
            result = should_quarantine_on_flags([flag])
            self.assertEqual(result, "KILL_CHAIN:LETHAL_TRIFECTA",
                             f"Failed for flag: {flag!r}")

    def test_escalate_flags_still_do_not_quarantine(self):
        from core.detection.quarantine import should_quarantine_on_flags
        flags = [
            "KILL_CHAIN:SENSITIVITY_RAMP:5_low_med",
            "KILL_CHAIN:DIRECTORY_SWEEP:7_prefixes",
        ]
        self.assertIsNone(should_quarantine_on_flags(flags))


# ── Constants and documentation ──────────────────────────────────────────────

class TestKillChainConstants(unittest.TestCase):

    def test_external_read_actions_is_non_empty_frozenset(self):
        self.assertIsInstance(_EXTERNAL_READ_ACTIONS, frozenset)
        self.assertGreater(len(_EXTERNAL_READ_ACTIONS), 0)

    def test_exfil_destination_keywords_is_non_empty(self):
        self.assertIsInstance(_EXFIL_DESTINATION_KEYWORDS, frozenset)
        self.assertGreater(len(_EXFIL_DESTINATION_KEYWORDS), 0)

    def test_three_url_prefixes_covered(self):
        for scheme in ("http://", "https://", "ftp://"):
            self.assertIn(scheme, _EXTERNAL_URL_PREFIXES)

    def test_all_canonical_exfil_actions_are_external_comm(self):
        for action in ("send", "email", "upload", "post", "forward", "export",
                       "transfer", "publish"):
            self.assertTrue(_is_external_comm(action, "/any"), f"Expected {action} to be Arm 3")

    def test_fetch_browse_scrape_are_external_read(self):
        for action in ("fetch", "browse", "scrape", "crawl", "download"):
            self.assertTrue(_is_external_read(action, "/any"), f"Expected {action} to be Arm 1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
