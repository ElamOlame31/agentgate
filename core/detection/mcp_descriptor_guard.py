"""
MCP Descriptor Guard — detects descriptor poisoning and rug-pull attacks in
MCP tools/list responses before descriptions reach the LLM's context window.

Two attack patterns:

1. Descriptor Poisoning: injection directives embedded in tool description or
   inputSchema property descriptions on first sight. Caught via 20 keyword regex
   patterns with NFKC normalization to block homoglyph substitution bypasses.

2. Rug-Pull / Tool Description Mutation: tool descriptions that change after
   initial registration. Tracked via SHA-256 hash of each tool's combined
   description + schema descriptor per upstream URL. Mutation itself is the signal,
   even if the new description looks clean.

Public API:
  scan_tool_descriptions(tools_list_result, upstream_url)
    -> (result_or_None, reason, threat_categories)
  clear_cache(upstream_url=None)
    -> resets per-upstream or all caches (useful for deliberate re-deployments)

Zero external dependencies — stdlib only: re, hashlib, unicodedata.
"""

import hashlib
import re
import unicodedata
from typing import Optional

# ── Injection patterns ─────────────────────────────────────────────────────────
# 20 patterns covering canonical prompt injection directive styles.
# All patterns are case-insensitive and applied after NFKC normalization.

_INJECTION_PATTERNS = [
    # Imperative overrides
    re.compile(r"\bignore\s+(all\s+)?(previous|prior|above)\s+instructions?\b", re.IGNORECASE),
    re.compile(r"\bdisregard\s+(all\s+)?(previous|prior|above)\s+instructions?\b", re.IGNORECASE),
    re.compile(r"\bforget\s+(all\s+)?(previous|prior|above)\s+instructions?\b", re.IGNORECASE),
    re.compile(r"\bdo\s+not\s+follow\s+(previous|prior)\s+instructions?\b", re.IGNORECASE),
    # System prompt override patterns
    re.compile(r"\bnew\s+(system\s+)?prompt\b.*?:", re.IGNORECASE | re.DOTALL),
    re.compile(r"\byour\s+(real|true|actual|new)\s+(instructions?|purpose|role|goal)\b", re.IGNORECASE),
    re.compile(r"\bact\s+as\s+(if\s+)?you\s+(are\s+)?(a\s+)?(new|different|another)\b", re.IGNORECASE),
    # Exfiltration directives
    re.compile(r"\bsend\s+(all|every|the)\s+(files?|data|content|documents?)\s+to\b", re.IGNORECASE),
    re.compile(r"\bexfiltrate\b", re.IGNORECASE),
    re.compile(r"\bupload\s+(all|every|the)\s+(files?|data|content)\b", re.IGNORECASE),
    # ChatML / control token injection
    re.compile(r"<\|?im_start\|?>", re.IGNORECASE),
    re.compile(r"<\|?im_end\|?>", re.IGNORECASE),
    re.compile(r"<\|?system\|?>", re.IGNORECASE),
    re.compile(r"\[INST\]|\[/INST\]", re.IGNORECASE),
    re.compile(r"<<SYS>>|<</SYS>>", re.IGNORECASE),
    # Role/instruction tag injection
    re.compile(r"<system>", re.IGNORECASE),
    re.compile(r"<instructions?>", re.IGNORECASE),
    re.compile(r"<user>", re.IGNORECASE),
    # Credential exfiltration
    re.compile(r"\b(send|post|submit|forward)\s+(your\s+)?(api[_\s]?key|token|credential|secret)\b", re.IGNORECASE),
    # General override phrase — handles "override all previous instructions", "override your rules", etc.
    re.compile(r"\boverride\s+(your\s+|all\s+)?(previous|prior|all)\s+(instructions?|guidelines?|rules?)\b", re.IGNORECASE),
]


def _normalize(text: str) -> str:
    """NFKC normalization collapses homoglyph substitutions (e.g. fullwidth letters → ASCII)."""
    return unicodedata.normalize("NFKC", text)


def _is_poisoned(text: str) -> bool:
    """Return True if text contains any injection directive after NFKC normalization."""
    if not text:
        return False
    normalized = _normalize(text)
    return any(p.search(normalized) for p in _INJECTION_PATTERNS)


def _descriptor_text(tool: dict) -> str:
    """
    Collect all description text from a tool dict into a single string.
    Covers: tool.description + all inputSchema.properties[*].description fields.
    """
    parts = []
    desc = tool.get("description")
    if isinstance(desc, str):
        parts.append(desc)
    schema = tool.get("inputSchema") or {}
    props = schema.get("properties") or {}
    for prop in props.values():
        if isinstance(prop, dict):
            pdesc = prop.get("description")
            if isinstance(pdesc, str):
                parts.append(pdesc)
    return "\n".join(parts)


def _tool_hash(tool: dict) -> str:
    """SHA-256 of all descriptor text for a tool (stable identity across calls)."""
    text = _descriptor_text(tool)
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


# ── Per-upstream descriptor hash cache ─────────────────────────────────────────
# Structure: {upstream_url: {tool_name: hash}}
# Module-level so it persists across requests within a single process.
_descriptor_cache: dict[str, dict[str, str]] = {}


def clear_cache(upstream_url: Optional[str] = None) -> None:
    """
    Reset the descriptor hash cache.
    upstream_url=None clears all upstreams (e.g. on deliberate server re-deployment).
    upstream_url=<url> clears only that upstream's cache.
    """
    global _descriptor_cache
    if upstream_url is None:
        _descriptor_cache.clear()
    else:
        _descriptor_cache.pop(upstream_url, None)


def scan_tool_descriptions(
    tools_list_result: dict,
    upstream_url: str,
) -> tuple[Optional[dict], str, list[str]]:
    """
    Scan a tools/list MCP response for descriptor poisoning and rug-pull attacks.

    Parameters:
      tools_list_result: the MCP JSON-RPC result object (must contain a "tools" list)
      upstream_url:      identifies which MCP server sent this (per-server cache key)

    Returns:
      (result_or_None, reason, threat_categories)
        - result_or_None: None if a threat was detected (caller must block);
                          tools_list_result (unchanged) if clean
        - reason: human-readable description of the threat, or "" if clean
        - threat_categories: ["TOOL_DESCRIPTION_MUTATION"] | ["DESCRIPTOR_POISONING"]
                             | ["GUARD_ERROR"] | []

    Fail-closed: any internal exception returns (None, reason, ["GUARD_ERROR"]) so
    that a guard crash never silently passes poisoned descriptors to the LLM.
    """
    try:
        tools = tools_list_result.get("tools")
        if not isinstance(tools, list):
            return tools_list_result, "", []

        known = _descriptor_cache.setdefault(upstream_url, {})

        mutation_tools: list[str] = []
        poisoned_tools: list[str] = []

        for tool in tools:
            if not isinstance(tool, dict):
                continue
            name = tool.get("name") or ""
            current_hash = _tool_hash(tool)

            if name in known:
                # Tool previously registered — check for rug-pull (description changed)
                if known[name] != current_hash:
                    mutation_tools.append(name)
                    known[name] = current_hash  # track from new baseline
            else:
                # First time seeing this tool — scan for initial poisoning
                known[name] = current_hash
                if _is_poisoned(_descriptor_text(tool)):
                    poisoned_tools.append(name)

        # Mutation takes precedence: a clean-to-dirty change IS a rug-pull, not just poisoning
        if mutation_tools:
            reason = (
                f"TOOL_DESCRIPTION_MUTATION: tool descriptor(s) changed after initial "
                f"registration — possible rug-pull attack. "
                f"Affected tools: {', '.join(mutation_tools)}"
            )
            return None, reason, ["TOOL_DESCRIPTION_MUTATION"]

        if poisoned_tools:
            reason = (
                f"DESCRIPTOR_POISONING: injection directive detected in tool description(s). "
                f"Affected tools: {', '.join(poisoned_tools)}"
            )
            return None, reason, ["DESCRIPTOR_POISONING"]

        return tools_list_result, "", []

    except Exception as exc:
        # Fail closed: internal guard error must not silently pass descriptors through.
        reason = f"DESCRIPTOR_GUARD_ERROR: internal error during scan — failing closed: {exc}"
        return None, reason, ["GUARD_ERROR"]
