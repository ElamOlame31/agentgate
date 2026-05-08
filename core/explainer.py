import os
import anthropic
from core.models import TrustBreakdown, Decision

_client: anthropic.Anthropic | None = None


def _explainer_enabled() -> bool:
    """Set AGENTGATE_EXPLAINER_ENABLED=false to use local fallback only (data residency)."""
    return os.getenv("AGENTGATE_EXPLAINER_ENABLED", "true").lower() != "false"


def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        _client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    return _client


def _sanitize(value: str, max_len: int = 200) -> str:
    """Strip newlines and control chars so agent-controlled data can't inject prompt instructions."""
    sanitized = value.replace("\n", " ").replace("\r", " ").replace("\t", " ")
    return sanitized[:max_len]


def generate_explanation(
    agent_name: str,
    action: str,
    resource: str,
    breakdown: TrustBreakdown,
    decision: Decision,
    flags: list[str],
) -> str:
    if not _explainer_enabled():
        raise Exception("Cloud explainer disabled via AGENTGATE_EXPLAINER_ENABLED=false")

    safe_name = _sanitize(agent_name, 128)
    safe_action = _sanitize(action, 128)
    safe_resource = _sanitize(resource, 256)

    prompt = f"""You are an AI security auditor. Generate a ONE sentence explanation (max 25 words) for this authorization decision.

Agent: {safe_name}
Requested: {safe_action} on {safe_resource}
Decision: {decision.value}
Trust Score: {breakdown.final_score}/100 (threshold: {breakdown.threshold_required})
Score breakdown:
  - Identity: {breakdown.identity_score}/100
  - Delegation chain: {breakdown.delegation_score}/100
  - Purpose alignment: {breakdown.purpose_alignment_score}/100
  - Behavioral: {breakdown.behavioral_score}/100
Resource sensitivity: {breakdown.resource_sensitivity.value}
Attack flags: {flags if flags else "none"}

Write one crisp sentence explaining WHY this decision was made. Be specific about the lowest score."""

    try:
        client = _get_client()
        message = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=80,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text.strip()
    except Exception:
        # Fallback explanation without API
        if decision == Decision.DENY:
            weakest = _weakest_score(breakdown, flags)
            return f"Access denied: {weakest}."
        elif decision == Decision.ESCALATE:
            if flags:
                reason = _humanize_flag(flags[0])
                return f"Flagged for review: {reason} (trust score {breakdown.final_score}/100)."
            else:
                weakest = _weakest_score(breakdown, [])
                return f"Flagged for review: trust score {breakdown.final_score}/100 is below the required {breakdown.threshold_required} — {weakest}."
        else:
            return f"Access granted: agent identity, purpose, and behavior all check out (score {breakdown.final_score}/100)."


def _humanize_flag(flag: str) -> str:
    """Convert a raw internal flag into a human-readable explanation."""
    if flag.startswith("RESOURCE_OUT_OF_SCOPE:"):
        resource = flag.split(":", 1)[1]
        return f"the requested resource '{resource}' is outside this agent's authorized scope"
    if flag.startswith("UNAUTHORIZED_ACTION:"):
        action = flag.split(":", 1)[1]
        return f"the action '{action}' is not in this agent's authorized actions"
    if flag.startswith("CRITICAL_VELOCITY:"):
        return "the agent is making requests far above its normal rate — possible exfiltration attempt"
    if flag.startswith("HIGH_VELOCITY:"):
        return "the agent's request rate is unusually high"
    if "CHAIN_SCOPE_VIOLATION" in flag:
        return "the request exceeds the scope granted in the agent's delegation chain"
    if "TOKEN_MISMATCH" in flag:
        return "the agent token does not match — possible identity spoofing"
    if "SCOPE_ESCALATION" in flag:
        return "the delegated agent is attempting to exceed its parent's permissions"
    if "REPETITIVE_ACTION" in flag:
        return "the agent is repeating the same action in a tight loop — suspicious pattern"
    return flag.lower().replace("_", " ")


def _weakest_score(breakdown: TrustBreakdown, flags: list[str]) -> str:
    if flags:
        return _humanize_flag(flags[0])
    scores = {
        "identity": breakdown.identity_score,
        "delegation": breakdown.delegation_score,
        "purpose alignment": breakdown.purpose_alignment_score,
        "behavioral": breakdown.behavioral_score,
    }
    weakest_key = min(scores, key=lambda k: scores[k])
    return f"{weakest_key} score was {scores[weakest_key]}/100"
