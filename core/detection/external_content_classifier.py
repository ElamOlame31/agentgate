"""
External Content Source Classifier — identifies resource paths that point to
user-generated content that may carry indirect prompt injection.

Indirect prompt injection uses legitimate content channels (GitHub PR bodies,
Jira ticket descriptions, Slack messages) as the injection vector. Unlike
direct injection — where the attacker sends malicious content to the agent
directly — indirect injection embeds instructions inside data the agent is
expected to read as part of its job.

April 2026 demonstrated this concretely: researchers injected instructions
into GitHub PR titles to hijack Claude Code, Gemini CLI, and GitHub Copilot,
exfiltrating GitHub Actions secrets via PR comments. The agents trusted
GitHub as a source, so no existing guardrail fired.

This module provides:
  classify_external_source(resource) -> (source_type, is_external)
  is_external_content_source(resource) -> bool

When is_external is True, AgentGate enables injection scanning for the
request regardless of whether the agent was registered with
processes_external_content=True — closing the gap for agents that read
from trusted-but-user-controlled channels without the explicit flag.

Classification is two-tiered:
  1. Hostname-based (most reliable): matches known external service domains
     from URL-form resources (e.g. https://github.com/owner/repo/pull/123).
  2. Path-based: matches well-known path structures for external services
     (e.g. /repos/owner/repo/pulls/123 for the GitHub REST API).

All input is NFKC-normalized and URL-decoded before matching, preventing
homoglyph substitution and encoding-bypass attacks.

Zero external dependencies.
"""

import posixpath
import re
import unicodedata
from urllib.parse import unquote, urlparse


# ── Source type constants ──────────────────────────────────────────────────────

GITHUB  = "GITHUB"   # GitHub pull requests, issues, discussions, comments, reviews
JIRA    = "JIRA"     # Jira / Atlassian tickets, epics, stories, service-desk requests
CHAT    = "CHAT"     # Slack, Discord, Mattermost channel messages and threads
EMAIL   = "EMAIL"    # Email inboxes, mailboxes, SMTP/IMAP paths
WEBHOOK = "WEBHOOK"  # Webhook payloads, event callbacks, delivery endpoints
WIKI    = "WIKI"     # Confluence, Notion, MediaWiki pages and knowledge-base articles
SUPPORT = "SUPPORT"  # Zendesk, Freshdesk, Intercom support tickets
UPLOAD  = "UPLOAD"   # User-uploaded files, form submissions, user-generated input
NONE    = "NONE"     # Not a known external content source


# ── Hostname-based classification ──────────────────────────────────────────────

# Exact hostname → source_type
_HOST_EXACT: dict[str, str] = {
    "github.com":              GITHUB,
    "api.github.com":          GITHUB,
    "raw.githubusercontent.com": GITHUB,
    "gist.github.com":         GITHUB,
    "slack.com":               CHAT,
    "hooks.slack.com":         CHAT,
    "teams.microsoft.com":     CHAT,
    "discord.com":             CHAT,
    "discordapp.com":          CHAT,
    "mattermost.com":          CHAT,
    "confluence.atlassian.com": WIKI,
    "notion.so":               WIKI,
    "notion.site":             WIKI,
    "intercom.io":             SUPPORT,
    "helpscout.net":           SUPPORT,
    "helpscout.com":           SUPPORT,
}

# Hostname suffix → source_type  (checked with str.endswith)
_HOST_SUFFIX: list[tuple[str, str]] = [
    (".atlassian.net",    JIRA),     # company.atlassian.net
    (".jira.com",         JIRA),
    (".zendesk.com",      SUPPORT),
    (".freshdesk.com",    SUPPORT),
    (".freshservice.com", SUPPORT),
    (".intercom.io",      SUPPORT),
    (".slack.com",        CHAT),
    (".mattermost.com",   CHAT),
]


# ── Path-based classification ──────────────────────────────────────────────────

# Applied to the normalized (lowercased, NFKC, URL-decoded, POSIX-normed) path.
# Order matters: first match wins.  More specific patterns come first.
_PATH_RULES: list[tuple[re.Pattern, str]] = [
    # ── GitHub ────────────────────────────────────────────────────────────────
    # GitHub REST API repo paths (unambiguous structure)
    (re.compile(r"/repos/[^/]+/[^/]+/(?:pulls|issues|discussions|comments|reviews)(?:/|$)"),
     GITHUB),
    # Service name prefix: /github/ or /gh/
    (re.compile(r"(?:^|/)github(?:/|$)"),  GITHUB),
    (re.compile(r"(?:^|/)gh(?:/|$)"),      GITHUB),
    # Explicit PR/issue event paths
    (re.compile(r"(?:^|/)pull[_-]?request(?:/|$)"), GITHUB),
    (re.compile(r"(?:^|/)pullrequest(?:/|$)"),       GITHUB),

    # ── Jira / Atlassian ─────────────────────────────────────────────────────
    # Jira browse URL pattern (/browse/PROJ-123) — lowercased after normalization
    (re.compile(r"/browse/[a-z][a-z0-9]*-\d+"), JIRA),
    # Jira REST API
    (re.compile(r"(?:^|/)rest/api/\d+/issue(?:/|$)"), JIRA),
    # Service name prefixes
    (re.compile(r"(?:^|/)jira(?:/|$)"),        JIRA),
    (re.compile(r"(?:^|/)atlassian(?:/|$)"),   JIRA),
    (re.compile(r"(?:^|/)servicedesk(?:/|$)"), JIRA),

    # ── Chat platforms ────────────────────────────────────────────────────────
    (re.compile(r"(?:^|/)slack(?:/|$)"),       CHAT),
    (re.compile(r"(?:^|/)discord(?:/|$)"),     CHAT),
    (re.compile(r"(?:^|/)mattermost(?:/|$)"),  CHAT),

    # ── Email ─────────────────────────────────────────────────────────────────
    (re.compile(r"(?:^|/)emails?(?:/|$)"),  EMAIL),
    (re.compile(r"(?:^|/)inbox(?:/|$)"),    EMAIL),
    (re.compile(r"(?:^|/)mailbox(?:/|$)"),  EMAIL),
    (re.compile(r"(?:^|/)smtp(?:/|$)"),     EMAIL),
    (re.compile(r"(?:^|/)imap(?:/|$)"),     EMAIL),

    # ── Webhook / callbacks ───────────────────────────────────────────────────
    (re.compile(r"(?:^|/)webhooks?(?:/|$)"),           WEBHOOK),
    (re.compile(r"(?:^|/)callbacks?(?:/|$)"),          WEBHOOK),
    (re.compile(r"(?:^|/)event[_-]?payloads?(?:/|$)"), WEBHOOK),

    # ── Wiki / knowledge base ─────────────────────────────────────────────────
    (re.compile(r"(?:^|/)confluence(?:/|$)"),                 WIKI),
    (re.compile(r"(?:^|/)wiki(?:/|$)"),                       WIKI),
    (re.compile(r"(?:^|/)notion(?:/|$)"),                     WIKI),
    (re.compile(r"(?:^|/)knowledge[_-]base(?:/|$)"),          WIKI),

    # ── Support ticket systems ────────────────────────────────────────────────
    (re.compile(r"(?:^|/)zendesk(?:/|$)"),     SUPPORT),
    (re.compile(r"(?:^|/)freshdesk(?:/|$)"),   SUPPORT),
    (re.compile(r"(?:^|/)freshservice(?:/|$)"), SUPPORT),
    (re.compile(r"(?:^|/)intercom(?:/|$)"),    SUPPORT),
    # /support/tickets/ — require two-level path to avoid over-matching /support/*
    (re.compile(r"/support/tickets?(?:/|$)"),  SUPPORT),

    # ── User-generated uploads and input ─────────────────────────────────────
    (re.compile(r"(?:^|/)user[_-]?uploads?(?:/|$)"),     UPLOAD),
    (re.compile(r"(?:^|/)user[_-]?content(?:/|$)"),      UPLOAD),
    (re.compile(r"(?:^|/)user[_-]?input(?:/|$)"),        UPLOAD),
    (re.compile(r"(?:^|/)form[_-]?submissions?(?:/|$)"), UPLOAD),
    (re.compile(r"(?:^|/)feedback(?:/|$)"),               UPLOAD),
]


# ── Core functions ─────────────────────────────────────────────────────────────

def _parse_resource(resource: str) -> tuple[str, str]:
    """
    Returns (host, normalized_path).

    Handles both URL form (https://github.com/...) and plain path form
    (/repos/owner/repo/pulls/123).  Applies double URL-decode, NFKC
    normalization, lowercase, and POSIX normpath so bypass attempts via
    encoding or Unicode lookalikes are caught.
    """
    # Double URL-decode to catch percent-percent-encoded bypass attempts
    decoded = unquote(unquote(resource))
    # NFKC: fullwidth Latin ｇｉｔｈｕｂ → github; compatibility decompositions
    decoded = unicodedata.normalize("NFKC", decoded)
    decoded = decoded.lower().strip()

    host = ""
    path = decoded

    if decoded.startswith(("http://", "https://", "ftp://")):
        try:
            parsed = urlparse(decoded)
            host = parsed.netloc or ""
            # Strip port from host (github.com:443 → github.com)
            if ":" in host:
                host = host.split(":")[0]
            path = parsed.path or "/"
        except Exception:
            host = ""
            path = decoded

    # Ensure absolute path for normpath
    if not path.startswith("/"):
        path = "/" + path

    path = posixpath.normpath(path)
    return host, path


def classify_external_source(resource: str) -> tuple[str, bool]:
    """
    Classify a resource as an external user-generated content source.

    Returns (source_type, is_external_content) where source_type is one
    of the module-level constants (GITHUB, JIRA, CHAT, …, NONE) and
    is_external_content is True when injection scanning should be enabled
    for this resource.

    Classification priority:
      1. Hostname-based (exact then suffix) — highest confidence
      2. Path-based (first matching rule wins) — moderate confidence
    """
    if not resource or not resource.strip():
        return NONE, False

    host, path = _parse_resource(resource)

    # 1. Hostname-based (most reliable — no path ambiguity)
    if host:
        if host in _HOST_EXACT:
            return _HOST_EXACT[host], True
        for suffix, source_type in _HOST_SUFFIX:
            if host.endswith(suffix):
                return source_type, True

    # 2. Path-based rules (first match wins)
    for pattern, source_type in _PATH_RULES:
        if pattern.search(path):
            return source_type, True

    return NONE, False


def is_external_content_source(resource: str) -> bool:
    """
    Returns True when the resource points to user-generated external content
    that should trigger injection scanning even without processes_external_content=True.
    """
    _, is_ext = classify_external_source(resource)
    return is_ext
