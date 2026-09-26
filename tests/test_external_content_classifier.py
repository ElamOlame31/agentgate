"""
Stdlib-only tests for core/external_content_classifier.py.

Covers:
  - Hostname-based classification (exact + suffix)
  - Path-based classification for each source type
  - Negative cases (internal paths that must NOT be flagged)
  - Encoding bypass prevention (URL-encoding, double-encoding, NFKC fullwidth)
  - is_external_content_source() convenience wrapper
  - Module constants integrity

No external dependencies — runs in environments without pydantic/fastapi.
Full injection integration tests (should_scan wiring into /authorize) require
the full dependency stack and live in tests/test_comprehensive.py.

Motivation: April 2026 demonstrated that agents reading GitHub PR titles
are vulnerable to indirect prompt injection. This detector auto-enables
injection scanning for known external-content resources without requiring
the explicit processes_external_content=True registration flag.
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.detection.external_content_classifier import (
    classify_external_source,
    is_external_content_source,
    GITHUB, JIRA, CHAT, EMAIL, WEBHOOK, WIKI, SUPPORT, UPLOAD, NONE,
    _parse_resource,
)


class TestConstants(unittest.TestCase):
    """Module-level constants are correctly defined."""

    def test_all_constants_are_strings(self):
        for const in (GITHUB, JIRA, CHAT, EMAIL, WEBHOOK, WIKI, SUPPORT, UPLOAD, NONE):
            self.assertIsInstance(const, str)

    def test_all_constants_nonempty(self):
        for const in (GITHUB, JIRA, CHAT, EMAIL, WEBHOOK, WIKI, SUPPORT, UPLOAD, NONE):
            self.assertTrue(len(const) > 0)

    def test_all_constants_are_distinct(self):
        consts = [GITHUB, JIRA, CHAT, EMAIL, WEBHOOK, WIKI, SUPPORT, UPLOAD, NONE]
        self.assertEqual(len(consts), len(set(consts)))

    def test_none_is_none(self):
        self.assertEqual(NONE, "NONE")

    def test_github_is_github(self):
        self.assertEqual(GITHUB, "GITHUB")

    def test_jira_is_jira(self):
        self.assertEqual(JIRA, "JIRA")

    def test_chat_is_chat(self):
        self.assertEqual(CHAT, "CHAT")

    def test_email_is_email(self):
        self.assertEqual(EMAIL, "EMAIL")

    def test_webhook_is_webhook(self):
        self.assertEqual(WEBHOOK, "WEBHOOK")

    def test_wiki_is_wiki(self):
        self.assertEqual(WIKI, "WIKI")

    def test_support_is_support(self):
        self.assertEqual(SUPPORT, "SUPPORT")


class TestParseResource(unittest.TestCase):
    """Internal _parse_resource helper correctly normalizes inputs."""

    def test_plain_path_no_host(self):
        host, path = _parse_resource("/repos/owner/repo/pulls/1")
        self.assertEqual(host, "")
        self.assertTrue(path.startswith("/repos"))

    def test_url_extracts_host(self):
        host, path = _parse_resource("https://github.com/owner/repo/pull/1")
        self.assertEqual(host, "github.com")
        self.assertIn("pull", path)

    def test_url_strips_port(self):
        host, _ = _parse_resource("https://github.com:443/owner/repo/pull/1")
        self.assertEqual(host, "github.com")

    def test_url_decoded(self):
        _, path = _parse_resource("%2Frepos%2Fowner%2Frepo%2Fpulls%2F1")
        self.assertIn("repos", path)

    def test_double_url_decoded(self):
        _, path = _parse_resource("%252Frepos%252Fowner%252Frepo%252Fpulls%252F1")
        self.assertIn("repos", path)

    def test_lowercased(self):
        host, path = _parse_resource("https://GitHub.COM/Owner/Repo/PULL/1")
        self.assertEqual(host, "github.com")
        self.assertNotIn("G", path)
        self.assertNotIn("P", path)

    def test_nfkc_fullwidth(self):
        # Fullwidth Latin characters (ｇｉｔｈｕｂ → github)
        _, path = _parse_resource("/ｇｉｔｈｕｂ/pulls/1")
        self.assertIn("github", path)

    def test_path_without_leading_slash(self):
        _, path = _parse_resource("repos/owner/repo/pulls/1")
        self.assertTrue(path.startswith("/"))

    def test_empty_string(self):
        host, path = _parse_resource("")
        self.assertEqual(host, "")


class TestHostClassificationExact(unittest.TestCase):
    """Hostname-exact matches return the correct source type."""

    def test_github_com(self):
        source, is_ext = classify_external_source("https://github.com/owner/repo/pull/1")
        self.assertEqual(source, GITHUB)
        self.assertTrue(is_ext)

    def test_api_github_com(self):
        source, is_ext = classify_external_source("https://api.github.com/repos/owner/repo/pulls/1")
        self.assertEqual(source, GITHUB)
        self.assertTrue(is_ext)

    def test_raw_githubusercontent_com(self):
        source, is_ext = classify_external_source("https://raw.githubusercontent.com/owner/repo/main/file.txt")
        self.assertEqual(source, GITHUB)
        self.assertTrue(is_ext)

    def test_slack_com(self):
        source, is_ext = classify_external_source("https://slack.com/archives/C123/p456")
        self.assertEqual(source, CHAT)
        self.assertTrue(is_ext)

    def test_hooks_slack_com(self):
        source, is_ext = classify_external_source("https://hooks.slack.com/services/T123/B456/xxx")
        self.assertEqual(source, CHAT)
        self.assertTrue(is_ext)

    def test_teams_microsoft_com(self):
        source, is_ext = classify_external_source("https://teams.microsoft.com/l/channel/123/messages")
        self.assertEqual(source, CHAT)
        self.assertTrue(is_ext)

    def test_notion_so(self):
        source, is_ext = classify_external_source("https://notion.so/Page-Title-abc123")
        self.assertEqual(source, WIKI)
        self.assertTrue(is_ext)

    def test_notion_site(self):
        source, is_ext = classify_external_source("https://notion.site/abc123")
        self.assertEqual(source, WIKI)
        self.assertTrue(is_ext)

    def test_intercom_io(self):
        source, is_ext = classify_external_source("https://intercom.io/conversations/123")
        self.assertEqual(source, SUPPORT)
        self.assertTrue(is_ext)

    def test_discord_com(self):
        source, is_ext = classify_external_source("https://discord.com/channels/123/456/789")
        self.assertEqual(source, CHAT)
        self.assertTrue(is_ext)


class TestHostClassificationSuffix(unittest.TestCase):
    """Hostname suffix matches return the correct source type."""

    def test_atlassian_net(self):
        source, is_ext = classify_external_source("https://mycompany.atlassian.net/browse/PROJ-123")
        self.assertEqual(source, JIRA)
        self.assertTrue(is_ext)

    def test_zendesk_com(self):
        source, is_ext = classify_external_source("https://mycompany.zendesk.com/tickets/123")
        self.assertEqual(source, SUPPORT)
        self.assertTrue(is_ext)

    def test_freshdesk_com(self):
        source, is_ext = classify_external_source("https://mycompany.freshdesk.com/support/tickets/456")
        self.assertEqual(source, SUPPORT)
        self.assertTrue(is_ext)

    def test_freshservice_com(self):
        source, is_ext = classify_external_source("https://mycompany.freshservice.com/requests/789")
        self.assertEqual(source, SUPPORT)
        self.assertTrue(is_ext)

    def test_slack_subdomain(self):
        source, is_ext = classify_external_source("https://myteam.slack.com/messages/channel")
        self.assertEqual(source, CHAT)
        self.assertTrue(is_ext)

    def test_unknown_host_not_external(self):
        source, is_ext = classify_external_source("https://internal.corp.example.com/documents/report.pdf")
        self.assertEqual(source, NONE)
        self.assertFalse(is_ext)

    def test_github_url_no_path(self):
        source, is_ext = classify_external_source("https://github.com")
        self.assertEqual(source, GITHUB)
        self.assertTrue(is_ext)


class TestPathClassificationGitHub(unittest.TestCase):
    """Path-based GitHub classification."""

    def test_repos_pulls(self):
        source, is_ext = classify_external_source("/repos/owner/repo/pulls/123")
        self.assertEqual(source, GITHUB)
        self.assertTrue(is_ext)

    def test_repos_issues(self):
        source, is_ext = classify_external_source("/repos/owner/repo/issues/456")
        self.assertEqual(source, GITHUB)
        self.assertTrue(is_ext)

    def test_repos_discussions(self):
        source, is_ext = classify_external_source("/repos/owner/repo/discussions/789")
        self.assertEqual(source, GITHUB)
        self.assertTrue(is_ext)

    def test_repos_comments(self):
        source, is_ext = classify_external_source("/repos/owner/repo/comments/101")
        self.assertEqual(source, GITHUB)
        self.assertTrue(is_ext)

    def test_repos_reviews(self):
        source, is_ext = classify_external_source("/repos/owner/repo/reviews/202")
        self.assertEqual(source, GITHUB)
        self.assertTrue(is_ext)

    def test_github_prefix(self):
        source, is_ext = classify_external_source("/github/pulls/1")
        self.assertEqual(source, GITHUB)
        self.assertTrue(is_ext)

    def test_gh_prefix(self):
        source, is_ext = classify_external_source("/gh/repos/owner/repo/pull/1")
        self.assertEqual(source, GITHUB)
        self.assertTrue(is_ext)

    def test_pull_request_component(self):
        source, is_ext = classify_external_source("/pull_request/event_payload")
        self.assertEqual(source, GITHUB)
        self.assertTrue(is_ext)

    def test_pullrequest_component(self):
        source, is_ext = classify_external_source("/pullrequest/opened")
        self.assertEqual(source, GITHUB)
        self.assertTrue(is_ext)

    def test_internal_report_not_github(self):
        source, is_ext = classify_external_source("/reports/q3-annual.pdf")
        self.assertEqual(source, NONE)
        self.assertFalse(is_ext)

    def test_internal_hr_not_github(self):
        source, is_ext = classify_external_source("/hr/employee/review-2025.pdf")
        self.assertEqual(source, NONE)
        self.assertFalse(is_ext)


class TestPathClassificationJira(unittest.TestCase):
    """Path-based Jira classification."""

    def test_jira_prefix(self):
        source, is_ext = classify_external_source("/jira/issues/PROJ-123")
        self.assertEqual(source, JIRA)
        self.assertTrue(is_ext)

    def test_atlassian_prefix(self):
        source, is_ext = classify_external_source("/atlassian/servicedesk/tickets")
        self.assertEqual(source, JIRA)
        self.assertTrue(is_ext)

    def test_servicedesk_prefix(self):
        source, is_ext = classify_external_source("/servicedesk/requests/456")
        self.assertEqual(source, JIRA)
        self.assertTrue(is_ext)

    def test_browse_issue_key(self):
        source, is_ext = classify_external_source("/browse/PROJ-123")
        self.assertEqual(source, JIRA)
        self.assertTrue(is_ext)

    def test_browse_two_letter_project(self):
        source, is_ext = classify_external_source("/browse/AB-999")
        self.assertEqual(source, JIRA)
        self.assertTrue(is_ext)

    def test_jira_rest_api(self):
        source, is_ext = classify_external_source("/rest/api/2/issue/PROJ-456")
        self.assertEqual(source, JIRA)
        self.assertTrue(is_ext)

    def test_jira_rest_api_v3(self):
        source, is_ext = classify_external_source("/rest/api/3/issue/AB-1")
        self.assertEqual(source, JIRA)
        self.assertTrue(is_ext)

    def test_browse_with_lowercase_key_matches_jira(self):
        # After normalization all paths are lowercased, so /browse/proj-123
        # (the lowercased form of /browse/PROJ-123) still classifies as JIRA.
        source, is_ext = classify_external_source("/browse/proj-123")
        self.assertEqual(source, JIRA)
        self.assertTrue(is_ext)


class TestPathClassificationChat(unittest.TestCase):
    """Path-based chat platform classification."""

    def test_slack_prefix(self):
        source, is_ext = classify_external_source("/slack/channels/C123/messages")
        self.assertEqual(source, CHAT)
        self.assertTrue(is_ext)

    def test_discord_prefix(self):
        source, is_ext = classify_external_source("/discord/channels/guild/channel")
        self.assertEqual(source, CHAT)
        self.assertTrue(is_ext)

    def test_mattermost_prefix(self):
        source, is_ext = classify_external_source("/mattermost/teams/general/messages")
        self.assertEqual(source, CHAT)
        self.assertTrue(is_ext)

    def test_internal_teamwork_not_chat(self):
        # /teams/ alone is too generic — not classified as CHAT without hostname
        source, is_ext = classify_external_source("/internal/teams/marketing/docs")
        self.assertEqual(source, NONE)
        self.assertFalse(is_ext)


class TestPathClassificationEmail(unittest.TestCase):
    """Path-based email classification."""

    def test_email_prefix(self):
        source, is_ext = classify_external_source("/email/inbox/message-123")
        self.assertEqual(source, EMAIL)
        self.assertTrue(is_ext)

    def test_emails_plural(self):
        source, is_ext = classify_external_source("/emails/received/456")
        self.assertEqual(source, EMAIL)
        self.assertTrue(is_ext)

    def test_inbox_prefix(self):
        source, is_ext = classify_external_source("/inbox/messages/789")
        self.assertEqual(source, EMAIL)
        self.assertTrue(is_ext)

    def test_mailbox_prefix(self):
        source, is_ext = classify_external_source("/mailbox/folder/message")
        self.assertEqual(source, EMAIL)
        self.assertTrue(is_ext)

    def test_smtp_prefix(self):
        source, is_ext = classify_external_source("/smtp/queue/pending")
        self.assertEqual(source, EMAIL)
        self.assertTrue(is_ext)

    def test_imap_prefix(self):
        source, is_ext = classify_external_source("/imap/INBOX/1")
        self.assertEqual(source, EMAIL)
        self.assertTrue(is_ext)

    def test_internal_mail_not_classified(self):
        # /mail/ is intentionally excluded (too ambiguous — could be /mailroom/ or /mail-system/)
        # Test that a clearly internal mail-system path is NOT mis-classified
        source, _ = classify_external_source("/internal/mailroom/logs")
        self.assertEqual(source, NONE)


class TestPathClassificationWebhook(unittest.TestCase):
    """Path-based webhook classification."""

    def test_webhook_singular(self):
        source, is_ext = classify_external_source("/webhook/payload")
        self.assertEqual(source, WEBHOOK)
        self.assertTrue(is_ext)

    def test_webhooks_plural(self):
        # Note: /webhooks/github/push contains /github/ so it classifies as
        # GITHUB (a webhook from GitHub is still GitHub external content). Use
        # a non-GitHub service to test the pure WEBHOOK path rule.
        source, is_ext = classify_external_source("/webhooks/stripe/payment-complete")
        self.assertEqual(source, WEBHOOK)
        self.assertTrue(is_ext)

    def test_callback_singular(self):
        source, is_ext = classify_external_source("/callback/oauth/stripe")
        self.assertEqual(source, WEBHOOK)
        self.assertTrue(is_ext)

    def test_callbacks_plural(self):
        source, is_ext = classify_external_source("/callbacks/stripe/payment")
        self.assertEqual(source, WEBHOOK)
        self.assertTrue(is_ext)

    def test_event_payload(self):
        source, is_ext = classify_external_source("/event_payload/push")
        self.assertEqual(source, WEBHOOK)
        self.assertTrue(is_ext)

    def test_event_payloads_plural(self):
        source, is_ext = classify_external_source("/event-payloads/123")
        self.assertEqual(source, WEBHOOK)
        self.assertTrue(is_ext)


class TestPathClassificationWiki(unittest.TestCase):
    """Path-based wiki classification."""

    def test_confluence(self):
        source, is_ext = classify_external_source("/confluence/pages/12345")
        self.assertEqual(source, WIKI)
        self.assertTrue(is_ext)

    def test_wiki(self):
        source, is_ext = classify_external_source("/wiki/articles/agent-security")
        self.assertEqual(source, WIKI)
        self.assertTrue(is_ext)

    def test_notion(self):
        source, is_ext = classify_external_source("/notion/pages/abc123")
        self.assertEqual(source, WIKI)
        self.assertTrue(is_ext)

    def test_knowledge_base_hyphen(self):
        source, is_ext = classify_external_source("/knowledge-base/articles/123")
        self.assertEqual(source, WIKI)
        self.assertTrue(is_ext)

    def test_knowledge_base_underscore(self):
        source, is_ext = classify_external_source("/knowledge_base/articles/123")
        self.assertEqual(source, WIKI)
        self.assertTrue(is_ext)


class TestPathClassificationSupport(unittest.TestCase):
    """Path-based support ticket classification."""

    def test_zendesk(self):
        source, is_ext = classify_external_source("/zendesk/tickets/123")
        self.assertEqual(source, SUPPORT)
        self.assertTrue(is_ext)

    def test_freshdesk(self):
        source, is_ext = classify_external_source("/freshdesk/tickets/456")
        self.assertEqual(source, SUPPORT)
        self.assertTrue(is_ext)

    def test_freshservice(self):
        source, is_ext = classify_external_source("/freshservice/requests/789")
        self.assertEqual(source, SUPPORT)
        self.assertTrue(is_ext)

    def test_intercom(self):
        source, is_ext = classify_external_source("/intercom/conversations/101")
        self.assertEqual(source, SUPPORT)
        self.assertTrue(is_ext)

    def test_support_tickets_two_level(self):
        source, is_ext = classify_external_source("/support/tickets/202")
        self.assertEqual(source, SUPPORT)
        self.assertTrue(is_ext)

    def test_support_alone_not_classified(self):
        # /support/ alone without /tickets/ does NOT match SUPPORT — too generic
        source, is_ext = classify_external_source("/support/documentation/guide.pdf")
        self.assertEqual(source, NONE)
        self.assertFalse(is_ext)


class TestPathClassificationUpload(unittest.TestCase):
    """Path-based user-upload classification."""

    def test_user_uploads_hyphen(self):
        source, is_ext = classify_external_source("/user-uploads/documents/file.pdf")
        self.assertEqual(source, UPLOAD)
        self.assertTrue(is_ext)

    def test_user_uploads_underscore(self):
        source, is_ext = classify_external_source("/user_uploads/images/photo.jpg")
        self.assertEqual(source, UPLOAD)
        self.assertTrue(is_ext)

    def test_user_content(self):
        source, is_ext = classify_external_source("/user-content/profile/avatar.png")
        self.assertEqual(source, UPLOAD)
        self.assertTrue(is_ext)

    def test_user_input(self):
        source, is_ext = classify_external_source("/user-input/form-response")
        self.assertEqual(source, UPLOAD)
        self.assertTrue(is_ext)

    def test_form_submissions(self):
        source, is_ext = classify_external_source("/form-submissions/2026/june/123")
        self.assertEqual(source, UPLOAD)
        self.assertTrue(is_ext)

    def test_feedback(self):
        source, is_ext = classify_external_source("/feedback/product/suggestion-456")
        self.assertEqual(source, UPLOAD)
        self.assertTrue(is_ext)


class TestNegativeClassification(unittest.TestCase):
    """Internal paths must NOT be flagged as external content sources."""

    def test_internal_reports(self):
        self.assertFalse(is_external_content_source("/reports/annual.pdf"))

    def test_internal_documents(self):
        self.assertFalse(is_external_content_source("/documents/contract.docx"))

    def test_internal_hr_data(self):
        self.assertFalse(is_external_content_source("/hr/payroll/salary.xlsx"))

    def test_internal_api_users(self):
        self.assertFalse(is_external_content_source("/api/v1/users/123"))

    def test_internal_logs(self):
        self.assertFalse(is_external_content_source("/data/logs/server.log"))

    def test_internal_config(self):
        self.assertFalse(is_external_content_source("/config/settings.json"))

    def test_root_path(self):
        self.assertFalse(is_external_content_source("/"))

    def test_empty_string(self):
        self.assertFalse(is_external_content_source(""))

    def test_whitespace_only(self):
        self.assertFalse(is_external_content_source("   "))

    def test_random_internal_path(self):
        self.assertFalse(is_external_content_source("/data/analytics/2026/june/report.csv"))

    def test_internal_confidence_not_flagged(self):
        # /confidential/ alone is not a known external source
        self.assertFalse(is_external_content_source("/confidential/executive/strategy.pptx"))

    def test_internal_templates(self):
        # /templates/html/ has no external-content signals — distinct from /email/ inbox path
        self.assertFalse(is_external_content_source("/templates/html/welcome.html"))


class TestEncodingBypassPrevention(unittest.TestCase):
    """Encoding and Unicode bypass attempts are correctly handled."""

    def test_url_encoded_github_path(self):
        # %2F = /
        source, is_ext = classify_external_source("%2Frepos%2Fowner%2Frepo%2Fpulls%2F1")
        self.assertEqual(source, GITHUB)
        self.assertTrue(is_ext)

    def test_double_url_encoded_github_path(self):
        # %252F = %2F (double-encoded)
        source, is_ext = classify_external_source("%252Frepos%252Fowner%252Frepo%252Fpulls%252F1")
        self.assertEqual(source, GITHUB)
        self.assertTrue(is_ext)

    def test_partial_url_encoded(self):
        # Only some chars encoded
        source, is_ext = classify_external_source("/repos/owner/repo/p%75lls/1")
        self.assertEqual(source, GITHUB)
        self.assertTrue(is_ext)

    def test_fullwidth_github_path(self):
        # Fullwidth Latin: ｇｉｔｈｕｂ should normalize to github via NFKC
        source, is_ext = classify_external_source("/ｇｉｔｈｕｂ/pulls/1")
        self.assertEqual(source, GITHUB)
        self.assertTrue(is_ext)

    def test_uppercase_path_lowercased(self):
        source, is_ext = classify_external_source("/GITHUB/PULLS/1")
        self.assertEqual(source, GITHUB)
        self.assertTrue(is_ext)

    def test_mixed_case_path(self):
        source, is_ext = classify_external_source("/GitHub/Pulls/1")
        self.assertEqual(source, GITHUB)
        self.assertTrue(is_ext)

    def test_url_encoded_jira_browse(self):
        source, is_ext = classify_external_source("/browse/PROJ%2D123")
        self.assertEqual(source, JIRA)
        self.assertTrue(is_ext)

    def test_url_with_encoded_host(self):
        # https://github.com encoded path components
        source, is_ext = classify_external_source("https://github.com/owner/repo/pulls%2F123")
        self.assertEqual(source, GITHUB)
        self.assertTrue(is_ext)


class TestIsExternalContentSource(unittest.TestCase):
    """is_external_content_source() convenience wrapper."""

    def test_github_url_returns_true(self):
        self.assertTrue(is_external_content_source("https://github.com/owner/repo/pull/1"))

    def test_jira_path_returns_true(self):
        self.assertTrue(is_external_content_source("/jira/issues/PROJ-1"))

    def test_internal_returns_false(self):
        self.assertFalse(is_external_content_source("/internal/docs/guide.pdf"))

    def test_empty_returns_false(self):
        self.assertFalse(is_external_content_source(""))

    def test_webhook_returns_true(self):
        self.assertTrue(is_external_content_source("/webhook/payload"))

    def test_atlassian_url_returns_true(self):
        self.assertTrue(is_external_content_source("https://acme.atlassian.net/browse/DEV-42"))

    def test_random_string_returns_false(self):
        self.assertFalse(is_external_content_source("just a random string with no path"))


class TestClassifyReturnShape(unittest.TestCase):
    """classify_external_source() always returns a 2-tuple of (str, bool)."""

    def test_external_returns_str_bool_true(self):
        result = classify_external_source("/github/pulls/1")
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        self.assertIsInstance(result[0], str)
        self.assertIsInstance(result[1], bool)
        self.assertTrue(result[1])

    def test_internal_returns_str_bool_false(self):
        result = classify_external_source("/internal/docs")
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], NONE)
        self.assertFalse(result[1])

    def test_empty_returns_none_false(self):
        result = classify_external_source("")
        self.assertEqual(result, (NONE, False))

    def test_classified_source_type_is_known_constant(self):
        known = {GITHUB, JIRA, CHAT, EMAIL, WEBHOOK, WIKI, SUPPORT, UPLOAD, NONE}
        for resource in ["/github/pr/1", "/jira/issues/A-1", "/slack/msgs", ""]:
            source, _ = classify_external_source(resource)
            self.assertIn(source, known, f"Unknown source type '{source}' for resource '{resource}'")


class TestHostnamePrecedence(unittest.TestCase):
    """Hostname classification takes precedence over path classification."""

    def test_github_host_beats_non_github_path(self):
        # Host is github.com, path looks like something else
        source, is_ext = classify_external_source("https://github.com/random/path")
        self.assertEqual(source, GITHUB)
        self.assertTrue(is_ext)

    def test_atlassian_host_beats_non_jira_path(self):
        source, is_ext = classify_external_source("https://acme.atlassian.net/wiki/spaces/TEAM/pages/123")
        # atlassian.net suffix → JIRA (not WIKI path prefix — host wins)
        self.assertEqual(source, JIRA)
        self.assertTrue(is_ext)

    def test_zendesk_host_beats_generic_path(self):
        source, is_ext = classify_external_source("https://acme.zendesk.com/api/v2/search")
        self.assertEqual(source, SUPPORT)
        self.assertTrue(is_ext)


class TestRealWorldAttackPaths(unittest.TestCase):
    """Real-world paths from known indirect injection attacks."""

    def test_april_2026_github_pr_title(self):
        # April 2026: agents hijacked via GitHub PR titles
        source, is_ext = classify_external_source(
            "https://api.github.com/repos/target-org/target-repo/pulls/123"
        )
        self.assertEqual(source, GITHUB)
        self.assertTrue(is_ext)

    def test_github_pr_body_via_rest_api(self):
        source, is_ext = classify_external_source("/repos/org/repo/pulls/456")
        self.assertEqual(source, GITHUB)
        self.assertTrue(is_ext)

    def test_jira_ticket_description(self):
        source, is_ext = classify_external_source(
            "https://mycompany.atlassian.net/browse/SEC-101"
        )
        self.assertEqual(source, JIRA)
        self.assertTrue(is_ext)

    def test_slack_message_with_injected_content(self):
        source, is_ext = classify_external_source("/slack/channels/C123ABC/messages/1234567890.123456")
        self.assertEqual(source, CHAT)
        self.assertTrue(is_ext)

    def test_webhook_payload_from_external_service(self):
        source, is_ext = classify_external_source("/webhooks/stripe/payment-complete")
        self.assertEqual(source, WEBHOOK)
        self.assertTrue(is_ext)

    def test_user_submitted_form_data(self):
        source, is_ext = classify_external_source("/user-input/support-form/submission-789")
        self.assertEqual(source, UPLOAD)
        self.assertTrue(is_ext)


if __name__ == "__main__":
    unittest.main()
