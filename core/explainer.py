import os
import anthropic
from core.models import TrustBreakdown, Decision

_client: anthropic.Anthropic | None = None


def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        _client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    return _client


def generate_explanation(
    agent_name: str,
    action: str,
    resource: str,
    breakdown: TrustBreakdown,
    decision: Decision,
    flags: list[str],
) -> str:
    prompt = f"""You are an AI security auditor. Generate a ONE sentence explanation (max 25 words) for this authorization decision.

Agent: {agent_name}
Requested: {action} on {resource}
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
            return f"Denied: {weakest}"
        elif decision == Decision.ESCALATE:
            if flags and breakdown.final_score >= breakdown.threshold_required:
                return f"Escalated: score {breakdown.final_score}/100 is sufficient but suspicious flags detected — {flags[0]}."
            elif flags:
                return f"Escalated: score {breakdown.final_score}/100 below required {breakdown.threshold_required} and flag raised — {flags[0]}."
            else:
                weakest = _weakest_score(breakdown, [])
                return f"Escalated: score {breakdown.final_score}/100 below required threshold {breakdown.threshold_required} — {weakest}."
        else:
            return f"Permitted: trust score {breakdown.final_score}/100 meets threshold {breakdown.threshold_required}."


def _weakest_score(breakdown: TrustBreakdown, flags: list[str]) -> str:
    if flags:
        return f"critical flag raised: {flags[0]}"
    scores = {
        "identity": breakdown.identity_score,
        "delegation": breakdown.delegation_score,
        "purpose alignment": breakdown.purpose_alignment_score,
        "behavioral": breakdown.behavioral_score,
    }
    weakest_key = min(scores, key=lambda k: scores[k])
    return f"{weakest_key} score was {scores[weakest_key]}/100"
