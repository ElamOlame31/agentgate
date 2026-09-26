"""
MCP Tool Argument Scanner — guards what the agent sends INTO upstream tools.

Scans the params.arguments of a tools/call request for injection patterns
BEFORE the request is forwarded to the upstream MCP server.  Complements
the output_sanitizer (which guards what comes BACK from tools).

Five threat categories, ordered by severity:
  SHELL_INJECTION   (critical) — shell metacharacters, command substitution,
                                  command chaining; present in ~43% of 2026 MCP CVEs
  CODE_INJECTION    (high)     — eval/exec/os.system/subprocess calls embedded
                                  in argument values
  SSRF              (high)     — arguments that direct the tool to fetch internal
                                  network addresses or cloud metadata endpoints
  PATH_TRAVERSAL    (high)     — directory traversal sequences that could escape
                                  the tool's intended file-system scope
  NULL_BYTE         (medium)   — null-byte injection used to truncate strings or
                                  bypass suffix validation in C-based tools

Severity → proxy action:
  critical  → request BLOCKED (JSON-RPC error -32010, never forwarded)
  high      → request BLOCKED (JSON-RPC error -32010)
  medium    → forwarded with X-AgentGate-ArgWarning header

Public API:
  scan_arguments(arguments, tool_name="") → ArgScanResult
  ArgScanResult.blocked      True when any critical/high finding was detected
  ArgScanResult.findings     list[ArgFinding] — all detections, sorted severity-desc
  ArgScanResult.highest_severity  "clean"|"medium"|"high"|"critical"
"""

import re
import unicodedata
from dataclasses import dataclass, field


# ── Severity ordering ──────────────────────────────────────────────────────────

_SEV_ORDER = {"clean": 0, "medium": 1, "high": 2, "critical": 3}

# Maximum length of a string value to scan; values longer than this are
# truncated to avoid regex catastrophic backtracking on multi-MB payloads.
MAX_VALUE_LENGTH = 4096

# Maximum recursion depth for nested argument dicts.
MAX_DEPTH = 6


# ── Shell command words that confirm injection intent ─────────────────────────
# A semicolon or pipe followed by one of these words in an argument value
# is a strong signal of shell injection — not a coincidence.

_SHELL_CMDS = frozenset({
    "ls", "cat", "rm", "mv", "cp", "chmod", "chown", "wget", "curl", "nc",
    "netcat", "bash", "sh", "zsh", "fish", "python", "python3", "perl",
    "ruby", "node", "php", "env", "export", "echo", "printf", "sed", "awk",
    "grep", "find", "xargs", "tar", "gzip", "base64", "id", "whoami",
    "uname", "ps", "kill", "pkill", "sudo", "su", "dd", "tee", "head",
    "tail", "cut", "sort", "touch", "mkdir", "rmdir", "ln", "sleep",
    "ping", "ifconfig", "ip", "nmap", "ssh", "scp", "rsync", "git",
    "svn", "cmd", "powershell", "pwsh", "open", "start", "exec",
    "read", "write", "stat", "file", "which", "type", "source",
})

# Shell chain operator followed by whitespace + known command
_CHAIN_RE = re.compile(
    r"(?:[;&|]{1,2}|&&|\|\|)\s+(" + "|".join(re.escape(c) for c in _SHELL_CMDS) + r")\b",
    re.IGNORECASE,
)

# Command substitution: $(cmd) or `cmd` — almost never legitimate in tool args
_CMD_SUBST_RE = re.compile(r"\$\([^)]{1,200}\)|`[^`]{1,200}`")

# Backtick in isolation (even short forms)
_BACKTICK_RE = re.compile(r"`[^`]{2,}`")

# Variable expansion that might leak env secrets or inject: ${VAR}, ${VAR:-default}
_VAR_EXPAND_RE = re.compile(r"\$\{[^}]{1,100}\}")

# Background execution attempt: & followed by shell command (not &&)
_BACKGROUND_RE = re.compile(
    r"(?<![&])[&](?![&])\s+(" + "|".join(re.escape(c) for c in _SHELL_CMDS) + r")\b",
    re.IGNORECASE,
)

# Newline followed by a shell command word (multiline shell injection)
_NEWLINE_CMD_RE = re.compile(
    r"[\n\r]\s*(" + "|".join(re.escape(c) for c in _SHELL_CMDS) + r")\s",
    re.IGNORECASE,
)

_SHELL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (_CMD_SUBST_RE,     "CMD_SUBSTITUTION"),
    (_BACKTICK_RE,      "BACKTICK_SUBSTITUTION"),
    (_VAR_EXPAND_RE,    "VAR_EXPANSION"),
    (_CHAIN_RE,         "CMD_CHAIN"),
    (_BACKGROUND_RE,    "BACKGROUND_EXEC"),
    (_NEWLINE_CMD_RE,   "NEWLINE_INJECT"),
]


# ── Code injection (high) ─────────────────────────────────────────────────────

_CODE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\beval\s*\("),                                                   "EVAL"),
    (re.compile(r"\bexec\s*\("),                                                   "EXEC"),
    (re.compile(r"\bos\s*\.\s*(?:system|popen|execvp?|execle?|spawn\w*)\s*\(",
                re.IGNORECASE),                                                    "OS_EXEC"),
    (re.compile(r"\bsubprocess\s*\.\s*(?:run|call|Popen|check_output|"
                r"check_call|getoutput)\s*\(",   re.IGNORECASE),                   "SUBPROCESS"),
    (re.compile(r"__import__\s*\("),                                               "IMPORT_INJECT"),
    (re.compile(r"\bgetattr\s*\(\s*\w+\s*,\s*['\"](?:system|popen|exec)",
                re.IGNORECASE),                                                    "GETATTR_EXEC"),
]


# ── SSRF (high) ───────────────────────────────────────────────────────────────
# Arguments directing the tool to internal endpoints.  A file-reader or
# search tool should never receive these addresses as input.

_SSRF_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Cloud instance metadata services
    (re.compile(r"169\.254\.169\.254"),                             "AWS_GCP_IMDS"),
    (re.compile(r"metadata\.google\.internal", re.IGNORECASE),     "GCP_METADATA"),
    (re.compile(r"100\.100\.100\.200"),                            "ALIBABA_IMDS"),
    (re.compile(r"169\.254\.170\.2"),                              "ECS_METADATA"),
    # localhost variants in URL form
    (re.compile(r"https?://(?:localhost|127\.\d+\.\d+\.\d+|::1)",
                re.IGNORECASE),                                     "LOCALHOST_URL"),
    # RFC 1918 private ranges in URL form
    (re.compile(
        r"https?://(?:10\.\d+\.\d+\.\d+|"
        r"172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|"
        r"192\.168\.\d+\.\d+)",
        re.IGNORECASE),                                            "INTERNAL_IP_URL"),
]


# ── Path traversal (high) ─────────────────────────────────────────────────────

_PATH_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Classic Unix and Windows traversal
    (re.compile(r"\.\.[/\\]"),                                              "DOT_DOT"),
    # URL/double-encoded: %2e%2e%2f or %252e%252e etc.
    (re.compile(r"(?:%2e){2}(?:%2f|%5c)", re.IGNORECASE),                  "ENCODED_TRAVERSAL"),
    # Absolute paths targeting known-sensitive Unix locations
    (re.compile(r"/etc/(?:passwd|shadow|hosts|sudoers|ssh|crontab|cron)",
                re.IGNORECASE),                                             "SENSITIVE_UNIX_PATH"),
    # Windows system directories
    (re.compile(r"C:\\(?:Windows|System32|Users\\\w+\\AppData)", re.IGNORECASE), "SENSITIVE_WIN_PATH"),
]


# ── Null byte (medium) ────────────────────────────────────────────────────────

_NULL_BYTE_RE = re.compile(r"\x00")


# ── Data model ─────────────────────────────────────────────────────────────────

@dataclass
class ArgFinding:
    category:    str    # SHELL_INJECTION | CODE_INJECTION | SSRF | PATH_TRAVERSAL | NULL_BYTE
    subcategory: str    # CMD_CHAIN, DOT_DOT, AWS_GCP_IMDS, etc.
    severity:    str    # critical | high | medium
    arg_path:    str    # dotted key path within arguments dict, e.g. "query" or "opts.file"
    excerpt:     str    # first 80 chars of the matched segment (never the full value)


@dataclass
class ArgScanResult:
    tool_name:        str
    findings:         list = field(default_factory=list)   # list[ArgFinding]
    highest_severity: str = "clean"
    blocked:          bool = False                          # True on critical or high


# ── Recursive value extractor ─────────────────────────────────────────────────

def _extract_string_values(obj: object, path: str, results: list, depth: int) -> None:
    """Recursively extract (value, path) for every string leaf in obj."""
    if depth <= 0:
        return
    if isinstance(obj, str):
        results.append((obj, path))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            child_path = f"{path}.{k}" if path else str(k)
            _extract_string_values(v, child_path, results, depth - 1)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _extract_string_values(v, f"{path}[{i}]", results, depth - 1)


# ── Per-value scanner ─────────────────────────────────────────────────────────

def _scan_value(value: str, arg_path: str) -> list[ArgFinding]:
    """Return all ArgFinding instances detected in a single string value."""
    # Normalize and truncate to prevent ReDoS on massive payloads
    normalized = unicodedata.normalize("NFKC", value[:MAX_VALUE_LENGTH])
    findings: list[ArgFinding] = []

    for pat, sub in _SHELL_PATTERNS:
        m = pat.search(normalized)
        if m:
            findings.append(ArgFinding(
                category="SHELL_INJECTION",
                subcategory=sub,
                severity="critical",
                arg_path=arg_path,
                excerpt=normalized[max(0, m.start() - 10): m.start() + 70],
            ))

    for pat, sub in _CODE_PATTERNS:
        m = pat.search(normalized)
        if m:
            findings.append(ArgFinding(
                category="CODE_INJECTION",
                subcategory=sub,
                severity="high",
                arg_path=arg_path,
                excerpt=normalized[m.start(): m.start() + 80],
            ))

    for pat, sub in _SSRF_PATTERNS:
        m = pat.search(normalized)
        if m:
            findings.append(ArgFinding(
                category="SSRF",
                subcategory=sub,
                severity="high",
                arg_path=arg_path,
                excerpt=normalized[m.start(): m.start() + 80],
            ))

    for pat, sub in _PATH_PATTERNS:
        m = pat.search(normalized)
        if m:
            findings.append(ArgFinding(
                category="PATH_TRAVERSAL",
                subcategory=sub,
                severity="high",
                arg_path=arg_path,
                excerpt=normalized[m.start(): m.start() + 80],
            ))

    m = _NULL_BYTE_RE.search(normalized)
    if m:
        findings.append(ArgFinding(
            category="NULL_BYTE",
            subcategory="NUL",
            severity="medium",
            arg_path=arg_path,
            excerpt=repr(normalized[max(0, m.start() - 5): m.start() + 10]),
        ))

    return findings


# ── Public API ─────────────────────────────────────────────────────────────────

def scan_arguments(arguments: object, tool_name: str = "") -> ArgScanResult:
    """
    Scan tool call arguments for injection patterns.

    arguments  — the params.arguments value from a tools/call JSON-RPC body.
                 May be a dict, list, or any JSON-serialisable type.  Non-string
                 leaf values (int, bool, None) are skipped silently.
    tool_name  — included in the result for logging; does not affect scoring.

    Returns ArgScanResult.  Result.blocked is True when highest_severity is
    'critical' or 'high' — the proxy should refuse to forward the request.
    """
    result = ArgScanResult(tool_name=tool_name)

    if not arguments:
        return result

    pairs: list[tuple[str, str]] = []
    _extract_string_values(arguments, "", pairs, MAX_DEPTH)

    all_findings: list[ArgFinding] = []
    for value, path in pairs:
        all_findings.extend(_scan_value(value, path))

    if not all_findings:
        return result

    # Sort: highest severity first, then by arg_path for stability
    all_findings.sort(
        key=lambda f: (-_SEV_ORDER[f.severity], f.arg_path)
    )

    result.findings = all_findings
    result.highest_severity = all_findings[0].severity
    result.blocked = _SEV_ORDER[result.highest_severity] >= _SEV_ORDER["high"]

    return result
