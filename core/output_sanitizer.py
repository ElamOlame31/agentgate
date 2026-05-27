"""
Output Sanitizer — guards what an agent PRODUCES before it passes downstream.

Unlike /scan (which guards agent INPUTS from prompt injection), this module
guards agent OUTPUTS from leaking sensitive material or carrying injected
instructions that could redirect the next agent in the pipeline.

Five threat categories:
  CREDENTIAL_LEAK   (critical) — API keys, tokens, private keys embedded in output
  PII               (high)     — email, SSN, phone, credit card numbers
  INSTRUCTION_TAG   (medium)   — LLM control tags that could hijack downstream agents
  IMPERATIVE_INJECT (medium)   — command phrases that redirect downstream behavior
  EXFIL_URL         (high)     — webhook domains, ngrok, data URIs, raw IP addresses

Redaction format: [REDACTED:CATEGORY:SUBCATEGORY]
"""

import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field

# Reuse injection patterns from the input scanner — same lexicon, output context
from core.injection_detector import INJECTION_PATTERNS


# ── Severity ordering ──────────────────────────────────────────────────────────

_SEV_ORDER = {"clean": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# ── Category 1: Credential leaks (critical) ────────────────────────────────────
# Extend the trust_engine patterns with output-specific credentials.

_CREDENTIAL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"sk-[A-Za-z0-9]{20,}", re.IGNORECASE),                          "OPENAI_KEY"),
    (re.compile(r"AKIA[0-9A-Z]{16}"),                                             "AWS_ACCESS_KEY"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"),                                          "GITHUB_PAT"),
    (re.compile(r"glpat-[A-Za-z0-9_-]{20,}"),                                     "GITLAB_PAT"),
    (re.compile(r"xox[bpoa]-[0-9A-Za-z-]{10,}", re.IGNORECASE),                  "SLACK_TOKEN"),
    (re.compile(r"AIza[0-9A-Za-z_-]{35}"),                                        "GOOGLE_API_KEY"),
    (re.compile(r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE KEY"),         "PRIVATE_KEY_HEADER"),
    (re.compile(r"password\s*[=:]\s*\S{8,}", re.IGNORECASE),                      "PASSWORD"),
    (re.compile(r"(?<!\w)secret\s*[=:]\s*\S{8,}", re.IGNORECASE),                "SECRET"),
    (re.compile(r"api[_-]?key\s*[=:]\s*\S{8,}", re.IGNORECASE),                  "API_KEY"),
    (re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]{20,}=*"),                           "BEARER_TOKEN"),
    # JWT: three base64url segments separated by dots
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "JWT"),
    # Database connection strings
    (re.compile(r"(?:postgres|mysql|mongodb|redis)://[^\s]{8,}", re.IGNORECASE),  "DB_CONN_STRING"),
    # Generic high-entropy token: 32+ hex chars that look like secrets
    (re.compile(r"\b[0-9a-f]{32,64}\b"),                                          "HEX_SECRET"),
]


# ── Category 2: PII (high) ─────────────────────────────────────────────────────

_PII_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Email address
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "EMAIL"),
    # US Social Security Number (XXX-XX-XXXX or XXX XX XXXX)
    (re.compile(r"\b\d{3}[-\s]\d{2}[-\s]\d{4}\b"), "SSN"),
    # North American phone: (NXX) NXX-XXXX or NXX-NXX-XXXX (N=2-9, not 0/1)
    (re.compile(r"\b(?:\+1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]\d{4}\b"), "PHONE_NANP"),
    # International phone: +CC followed by 2-5 digit groups (handles +33 6 12 34 56 78, etc.)
    (re.compile(r"\+[1-9]\d{1,3}(?:[-.\s]\d{1,5}){2,5}"), "PHONE_INTL"),
    # Credit card: XXXX[-space]XXXX[-space]XXXX[-space]XXXX (all separators must match)
    (re.compile(r"\b\d{4}([-\s])(?:\d{4}\1){2}\d{4}\b"), "CREDIT_CARD"),
    # IBAN: 2-letter country code + 2 check digits + up to 30 alphanumeric chars
    (re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b"), "IBAN"),
]


# ── Category 3: Instruction tags (medium) ─────────────────────────────────────
# XML/markdown control structures used by LLMs as delimiters.
# Presence in output strongly suggests the agent is parroting injected content.

_INSTRUCTION_TAG_PATTERNS: list[re.Pattern] = [
    # HTML/XML-style LLM control tags
    re.compile(
        r"<\s*(?:system|instructions?|prompt|assistant|human|user|ai|context|task|goal|directive)"
        r"\s*[^>]{0,80}>",
        re.IGNORECASE,
    ),
    # Llama-2 / Mistral delimiters
    re.compile(r"\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>", re.IGNORECASE),
    # ChatML format (used by GPT-4, Mistral, etc.)
    re.compile(r"<\|(?:im_start|im_end|system|user|assistant)\|>", re.IGNORECASE),
    # Markdown heading used as role separator
    re.compile(r"###\s*(?:System|Instructions?|Prompt|Human|Assistant)\s*:", re.IGNORECASE),
    # Code-fence with LLM-specific language tag
    re.compile(r"```\s*(?:system|instructions?|prompt)\b", re.IGNORECASE),
    # Anthropic Human/Assistant turns (if leaked into output)
    re.compile(r"\n(?:Human|Assistant):\s", re.IGNORECASE),
]


# ── Category 4: Imperative injection (medium) ────────────────────────────────
# Inject patterns reused from input scanner — if these appear in OUTPUT the
# agent has likely been compromised and is amplifying injected commands.

_IMPERATIVE_INJECT_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS
]


# ── Category 5: Exfiltration URLs (high) ─────────────────────────────────────

# Well-known webhook / request-capture services frequently abused for exfil
_EXFIL_DOMAINS: frozenset[str] = frozenset({
    "ngrok.io", "ngrok-free.app", "ngrok.app",
    "webhook.site", "webhooks.site",
    "requestbin.com", "requestbin.net",
    "pipedream.net", "pipedream.com",
    "hookdeck.com", "beeceptor.com", "postb.in",
    "requestcatcher.com", "mocky.io", "httpbin.org",
    "smee.io", "canarytokens.com", "interactsh.com",
    "oast.me", "oast.pro", "oast.live",          # OAST interaction servers
    "burpcollaborator.net", "interact.sh",
    "discord.com/api/webhooks",                   # Discord webhook path
    "hooks.slack.com",                            # Slack webhook path
})

# Patterns that indicate exfiltration regardless of domain
_EXFIL_URL_PATTERNS: list[tuple[re.Pattern, str]] = [
    # data: URIs carrying base64-encoded payloads
    (re.compile(r"data:[a-z+/]+;base64,[A-Za-z0-9+/=]{20,}", re.IGNORECASE), "DATA_URI"),
    # Raw IP address URLs (bypasses DNS logging)
    (re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?:[:/\s]|$)", re.IGNORECASE), "RAW_IP_URL"),
]

# General URL extractor for domain matching
_URL_RE = re.compile(r"https?://[^\s\"'<>]{4,}", re.IGNORECASE)


def _extract_domain(url: str) -> str:
    try:
        netloc = urllib.parse.urlparse(url).netloc.lower()
        return netloc.split(":")[0]  # strip port
    except Exception:
        return ""


def _url_is_exfil(url: str) -> bool:
    domain = _extract_domain(url)
    if not domain:
        return False
    # Exact match or subdomain match
    return any(
        domain == ed or domain.endswith("." + ed) or ("/" in ed and ed in url.lower())
        for ed in _EXFIL_DOMAINS
    )


# ── Data model ─────────────────────────────────────────────────────────────────

@dataclass
class ThreatFinding:
    category:    str   # CREDENTIAL_LEAK | PII | INSTRUCTION_TAG | IMPERATIVE_INJECT | EXFIL_URL
    subcategory: str   # EMAIL, SSN, OPENAI_KEY, etc. (empty string if N/A)
    severity:    str   # critical | high | medium | low
    start:       int   # byte offset in normalized content
    end:         int
    excerpt:     str   # first 60 chars of match, for display (never the full secret)


@dataclass
class SanitizeResult:
    original_length:    int
    sanitized:          str
    threats:            list = field(default_factory=list)   # list[ThreatFinding]
    threat_count:       int = 0
    highest_severity:   str = "clean"
    categories_detected: list = field(default_factory=list) # list[str], deduplicated


# ── Internal match collection ─────────────────────────────────────────────────

def _collect_raw_matches(content: str) -> list[tuple]:
    """Return (start, end, category, subcategory, severity) for every regex hit."""
    hits: list[tuple] = []

    for pat, sub in _CREDENTIAL_PATTERNS:
        for m in pat.finditer(content):
            hits.append((m.start(), m.end(), "CREDENTIAL_LEAK", sub, "critical"))

    for pat, sub in _PII_PATTERNS:
        for m in pat.finditer(content):
            hits.append((m.start(), m.end(), "PII", sub, "high"))

    for pat in _INSTRUCTION_TAG_PATTERNS:
        for m in pat.finditer(content):
            hits.append((m.start(), m.end(), "INSTRUCTION_TAG", "", "medium"))

    for pat in _IMPERATIVE_INJECT_PATTERNS:
        for m in pat.finditer(content):
            hits.append((m.start(), m.end(), "IMPERATIVE_INJECT", "", "medium"))

    for pat, sub in _EXFIL_URL_PATTERNS:
        for m in pat.finditer(content):
            hits.append((m.start(), m.end(), "EXFIL_URL", sub, "high"))

    for m in _URL_RE.finditer(content):
        if _url_is_exfil(m.group(0)):
            hits.append((m.start(), m.end(), "EXFIL_URL", "WEBHOOK_DOMAIN", "high"))

    return hits


def _resolve_overlaps(matches: list[tuple]) -> list[tuple]:
    """
    Remove overlapping matches. Sort by start; when two ranges overlap keep the
    one with higher severity. Ties: keep the first (longer match usually wins
    because it was emitted by the more specific pattern).
    """
    if not matches:
        return []
    sorted_m = sorted(matches, key=lambda x: x[0])
    result = [sorted_m[0]]
    for curr in sorted_m[1:]:
        prev = result[-1]
        if curr[0] >= prev[1]:
            # No overlap
            result.append(curr)
        elif _SEV_ORDER[curr[4]] > _SEV_ORDER[prev[4]]:
            # Overlaps but higher severity — replace, extend end if needed
            result[-1] = (prev[0], max(prev[1], curr[1]), curr[2], curr[3], curr[4])
        # else: same or lower severity — skip
    return result


# ── Public API ─────────────────────────────────────────────────────────────────

def sanitize(content: str) -> SanitizeResult:
    """
    Scan agent output for all 5 threat categories.
    Returns sanitized text with threats redacted + full threat report.
    """
    if not content:
        return SanitizeResult(original_length=0, sanitized="")

    # NFKC normalization — catches homoglyph substitutions (full-width chars, etc.)
    normalized = unicodedata.normalize("NFKC", content)

    raw = _collect_raw_matches(normalized)
    resolved = _resolve_overlaps(raw)

    threats = [
        ThreatFinding(
            category=cat,
            subcategory=sub,
            severity=sev,
            start=start,
            end=end,
            excerpt=normalized[start : start + 60],
        )
        for start, end, cat, sub, sev in resolved
    ]

    # Apply redactions right-to-left so earlier offsets stay valid
    sanitized = normalized
    for start, end, cat, sub, sev in reversed(resolved):
        label = f"REDACTED:{cat}" + (f":{sub}" if sub else "")
        sanitized = sanitized[:start] + f"[{label}]" + sanitized[end:]

    highest = max(
        (_SEV_ORDER[t.severity] for t in threats),
        default=0,
    )
    highest_str = next(k for k, v in _SEV_ORDER.items() if v == highest) if threats else "clean"

    # Deduplicated category list, preserving encounter order
    seen: set[str] = set()
    categories: list[str] = []
    for t in threats:
        if t.category not in seen:
            seen.add(t.category)
            categories.append(t.category)

    return SanitizeResult(
        original_length=len(content),
        sanitized=sanitized,
        threats=threats,
        threat_count=len(threats),
        highest_severity=highest_str,
        categories_detected=categories,
    )
