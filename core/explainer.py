import os
import anthropic
from core.models import TrustBreakdown, Decision

_client: anthropic.Anthropic | None = None

# Applies to the on-demand prose path only. Nothing on the authorization path
# waits on this.
EXPLAINER_TIMEOUT_SECONDS: float = float(
    os.getenv("AGENTGATE_EXPLAINER_TIMEOUT", "8")
)


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


def local_explanation(
    breakdown: TrustBreakdown,
    decision: Decision,
    flags: list[str],
) -> str:
    """Explain a decision from the decision itself — no network, no model.

    This is what /authorize returns. It is derived entirely from the scores and
    flags that produced the verdict, so it is available the instant the verdict
    is, it cannot fail, and it says the same thing every time for the same
    inputs — which is what an auditor comparing two records needs.
    """
    if decision == Decision.DENY:
        return f"Access denied: {_weakest_score(breakdown, flags)}."
    if decision == Decision.ESCALATE:
        if flags:
            return f"Flagged for review: {_humanize_flag(flags[0])} (trust score {breakdown.final_score}/100)."
        return (
            f"Flagged for review: trust score {breakdown.final_score}/100 is below "
            f"the required {breakdown.threshold_required} — {_weakest_score(breakdown, [])}."
        )
    return (
        f"Access granted: agent identity, purpose, and behavior all check out "
        f"(score {breakdown.final_score}/100)."
    )


def generate_explanation(
    agent_name: str,
    action: str,
    resource: str,
    breakdown: TrustBreakdown,
    decision: Decision,
    flags: list[str],
) -> str:
    """Prose explanation, on demand only.

    This reaches a third-party model over the network, so it must never sit on
    the authorization path: a slow or unreachable provider would delay every
    agent action, and a fail-closed gate would block them. Call it when someone
    is reading a decision — a dashboard, an audit review — not when one is made.
    """
    if not _explainer_enabled():
        return local_explanation(breakdown, decision, flags)

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
            # Bounded on purpose. The SDK's default allows several minutes,
            # which is indistinguishable from a hang to whoever is waiting.
            timeout=EXPLAINER_TIMEOUT_SECONDS,
        )
        return message.content[0].text.strip()
    except Exception:
        return local_explanation(breakdown, decision, flags)


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
