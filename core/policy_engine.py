"""
Natural Language Policy Engine.

Admin writes plain English: "Agents must never delete files in /confidential"
Claude converts it to a structured, enforceable policy rule.
Policies are checked BEFORE trust scoring — a matching DENY policy is a hard block.
"""

import os
import json
import sqlite3
import uuid
import time
import fnmatch
from pathlib import Path
from pydantic import BaseModel
from typing import Optional
import anthropic

DB_PATH = Path(__file__).parent.parent / "agentgate_audit.db"


class Policy(BaseModel):
    id: str
    description: str          # original plain-English text
    effect: str               # DENY or ESCALATE
    action_pattern: str       # "delete", "write", "*" etc.
    resource_pattern: str     # "/confidential/*", "*" etc.
    agent_pattern: str        # "*" = all agents, or specific agent_id
    created_at: float


class PolicyMatch(BaseModel):
    matched: bool
    policy: Optional[Policy] = None
    reason: str = ""


def init_policy_table():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS policies (
            id TEXT PRIMARY KEY,
            description TEXT,
            effect TEXT,
            action_pattern TEXT,
            resource_pattern TEXT,
            agent_pattern TEXT,
            created_at REAL
        )
    """)
    conn.commit()
    conn.close()


def _parse_policy_with_claude(plain_text: str) -> dict:
    """Ask Claude to convert plain English to a structured policy."""
    prompt = f"""Convert this plain-English security policy into a JSON object.

Policy text: "{plain_text}"

Return ONLY a JSON object with these exact fields:
{{
  "effect": "DENY" or "ESCALATE",
  "action_pattern": the action to restrict (e.g. "delete", "write", "read", "*" for any),
  "resource_pattern": the resource path pattern (e.g. "/confidential/*", "/hr/*", "*" for any),
  "agent_pattern": "*" unless a specific agent is mentioned
}}

Examples:
- "agents must never delete files" → {{"effect":"DENY","action_pattern":"delete","resource_pattern":"*","agent_pattern":"*"}}
- "no agent should read password files" → {{"effect":"DENY","action_pattern":"read","resource_pattern":"*password*","agent_pattern":"*"}}
- "flag any access to /hr folder" → {{"effect":"ESCALATE","action_pattern":"*","resource_pattern":"/hr/*","agent_pattern":"*"}}

Return only valid JSON, no explanation."""

    try:
        client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        message = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=150,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = message.content[0].text.strip()
        # Strip markdown code blocks if present
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        return json.loads(raw.strip())
    except Exception:
        return _parse_policy_fallback(plain_text)


def _parse_policy_fallback(plain_text: str) -> dict:
    """Rule-based fallback when Claude API is unavailable."""
    text = plain_text.lower()
    effect = "ESCALATE"
    if any(w in text for w in ["never", "must not", "cannot", "deny", "block", "forbid", "prohibit"]):
        effect = "DENY"

    action = "*"
    for a in ["delete", "write", "read", "admin", "execute", "list"]:
        if a in text:
            action = a
            break

    resource = "*"
    for kw in ["confidential", "hr", "salary", "password", "admin", "secret", "private"]:
        if kw in text:
            resource = f"*{kw}*"
            break

    return {"effect": effect, "action_pattern": action, "resource_pattern": resource, "agent_pattern": "*"}


def create_policy(plain_text: str) -> Policy:
    """Convert plain English to a policy and persist it."""
    init_policy_table()
    parsed = _parse_policy_with_claude(plain_text)
    policy = Policy(
        id=str(uuid.uuid4())[:8],
        description=plain_text,
        effect=parsed.get("effect", "DENY"),
        action_pattern=parsed.get("action_pattern", "*"),
        resource_pattern=parsed.get("resource_pattern", "*"),
        agent_pattern=parsed.get("agent_pattern", "*"),
        created_at=time.time(),
    )
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO policies VALUES (?,?,?,?,?,?,?)",
        (policy.id, policy.description, policy.effect,
         policy.action_pattern, policy.resource_pattern,
         policy.agent_pattern, policy.created_at)
    )
    conn.commit()
    conn.close()
    return policy


def get_all_policies() -> list[Policy]:
    init_policy_table()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM policies ORDER BY created_at DESC").fetchall()
    conn.close()
    return [Policy(**dict(r)) for r in rows]


def delete_policy(policy_id: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute("DELETE FROM policies WHERE id=?", (policy_id,))
    conn.commit()
    conn.close()
    return cur.rowcount > 0


def check_policies(agent_id: str, action: str, resource: str) -> PolicyMatch:
    """
    Check all active policies against this request.
    Returns the first matching policy (most restrictive wins).
    """
    policies = get_all_policies()
    deny_match = None
    escalate_match = None

    for policy in policies:
        agent_ok = policy.agent_pattern == "*" or fnmatch.fnmatch(agent_id, policy.agent_pattern)
        action_ok = policy.action_pattern == "*" or fnmatch.fnmatch(action.lower(), policy.action_pattern.lower())
        resource_ok = fnmatch.fnmatch(resource.lower(), policy.resource_pattern.lower())

        if agent_ok and action_ok and resource_ok:
            if policy.effect == "DENY":
                deny_match = policy
                break  # DENY wins immediately
            elif policy.effect == "ESCALATE" and escalate_match is None:
                escalate_match = policy

    if deny_match:
        return PolicyMatch(
            matched=True,
            policy=deny_match,
            reason=f"Policy '{deny_match.description}' explicitly denies this action."
        )
    if escalate_match:
        return PolicyMatch(
            matched=True,
            policy=escalate_match,
            reason=f"Policy '{escalate_match.description}' requires escalation for this action."
        )
    return PolicyMatch(matched=False, reason="No policy matched.")
