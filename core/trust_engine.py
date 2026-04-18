import time
import fnmatch
from core.models import (
    AgentRegistration, AuthorizationRequest,
    TrustBreakdown, ResourceSensitivity, Decision
)
from core.purpose_engine import compute_purpose_score
from core import audit

# Sensitivity thresholds: minimum trust score required to PERMIT
SENSITIVITY_THRESHOLDS = {
    ResourceSensitivity.LOW: 40.0,
    ResourceSensitivity.MEDIUM: 60.0,
    ResourceSensitivity.HIGH: 75.0,
    ResourceSensitivity.CRITICAL: 90.0,
}

# Score weights
W_IDENTITY = 0.25
W_DELEGATION = 0.25
W_PURPOSE = 0.30
W_BEHAVIORAL = 0.20

# Velocity: max requests per minute before behavioral score degrades
MAX_RPM = 20


def classify_resource_sensitivity(resource: str) -> ResourceSensitivity:
    r = resource.lower()
    if any(kw in r for kw in ["salary", "payroll", "password", "cred", "secret", "private_key", "token"]):
        return ResourceSensitivity.CRITICAL
    if any(kw in r for kw in ["confidential", "hr", "finance", "admin", "root", "audit"]):
        return ResourceSensitivity.HIGH
    if any(kw in r for kw in ["internal", "personal", "user", "config"]):
        return ResourceSensitivity.MEDIUM
    return ResourceSensitivity.LOW


def score_identity(agent: AgentRegistration, request: AuthorizationRequest) -> tuple[float, list[str]]:
    flags = []
    score = 100.0

    if agent.token and request.token != agent.token:
        flags.append("TOKEN_MISMATCH")
        score -= 60.0

    # Check if action is in authorized actions
    if request.action.lower() not in [a.lower() for a in agent.authorized_actions]:
        flags.append(f"UNAUTHORIZED_ACTION:{request.action}")
        score -= 40.0

    # Check if resource matches any authorized pattern.
    # Also match the directory itself when pattern ends with /*
    # e.g. "/documents" should match "/documents/*"
    def _matches(resource: str, pattern: str) -> bool:
        if fnmatch.fnmatch(resource, pattern):
            return True
        if pattern.endswith("/*"):
            parent = pattern[:-2]
            if resource == parent or resource == parent + "/":
                return True
        return False

    resource_allowed = any(
        _matches(request.resource, pattern)
        for pattern in agent.authorized_resources
    )
    if not resource_allowed:
        flags.append(f"RESOURCE_OUT_OF_SCOPE:{request.resource}")
        score -= 35.0

    return max(0.0, score), flags


def score_delegation(agent: AgentRegistration) -> tuple[float, list[str]]:
    flags = []
    score = 100.0

    # Penalize deep delegation chains
    depth = agent.delegation_depth
    if depth > 0:
        score -= depth * 15.0

    # Check scope attenuation: delegated scope should be narrower
    if agent.delegated_by and agent.scope_at_delegation:
        current_scope = set(agent.authorized_actions)
        parent_scope = set(agent.scope_at_delegation)
        if not current_scope.issubset(parent_scope):
            flags.append("SCOPE_ESCALATION_AT_DELEGATION")
            score -= 50.0

    if depth > 3:
        flags.append(f"EXCESSIVE_DELEGATION_DEPTH:{depth}")
        score -= 20.0

    return max(0.0, score), flags


def score_behavioral(agent_id: str, action: str) -> tuple[float, list[str]]:
    flags = []
    score = 100.0

    history = audit.get_agent_request_history(agent_id, window_seconds=60.0)
    rpm = len(history)

    if rpm > MAX_RPM:
        excess = rpm - MAX_RPM
        penalty = min(90.0, excess * 5.0)
        score -= penalty
        if rpm > MAX_RPM * 2:
            flags.append(f"CRITICAL_VELOCITY:{rpm}_RPM")
        else:
            flags.append(f"HIGH_VELOCITY:{rpm}_RPM")

    # Check for repeated identical actions (replay-style behavior)
    recent_actions = [h["action"] for h in history[:10]]
    if recent_actions.count(action) > 5:
        flags.append(f"REPETITIVE_ACTION:{action}")
        score -= 25.0

    return max(0.0, score), flags


def compute_trust(
    agent: AgentRegistration,
    request: AuthorizationRequest
) -> tuple[TrustBreakdown, list[str]]:
    all_flags = []

    id_score, id_flags = score_identity(agent, request)
    all_flags.extend(id_flags)

    del_score, del_flags = score_delegation(agent)
    all_flags.extend(del_flags)

    purpose_score = compute_purpose_score(
        agent.declared_purpose,
        request.action,
        request.resource,
        request.justification or ""
    )

    beh_score, beh_flags = score_behavioral(agent.agent_id, request.action)
    all_flags.extend(beh_flags)

    sensitivity = classify_resource_sensitivity(request.resource)
    threshold = SENSITIVITY_THRESHOLDS[sensitivity]

    final = (
        id_score * W_IDENTITY +
        del_score * W_DELEGATION +
        purpose_score * W_PURPOSE +
        beh_score * W_BEHAVIORAL
    )
    final = round(final, 2)

    breakdown = TrustBreakdown(
        identity_score=round(id_score, 2),
        delegation_score=round(del_score, 2),
        purpose_alignment_score=round(purpose_score, 2),
        behavioral_score=round(beh_score, 2),
        resource_sensitivity=sensitivity,
        final_score=final,
        threshold_required=threshold,
    )

    return breakdown, all_flags


def make_decision(breakdown: TrustBreakdown, flags: list[str]) -> Decision:
    score = breakdown.final_score
    threshold = breakdown.threshold_required

    # Hard deny on critical velocity
    if any("CRITICAL_VELOCITY" in f for f in flags):
        return Decision.DENY

    # Hard deny on critical security flags regardless of score
    critical_flags = [f for f in flags if any(kw in f for kw in [
        "TOKEN_MISMATCH", "SCOPE_ESCALATION", "UNAUTHORIZED_ACTION"
    ])]
    if critical_flags and breakdown.resource_sensitivity in (
        ResourceSensitivity.HIGH, ResourceSensitivity.CRITICAL
    ):
        return Decision.DENY

    if score >= threshold:
        if flags:
            return Decision.ESCALATE
        return Decision.PERMIT
    elif score >= threshold * 0.6:
        return Decision.ESCALATE
    else:
        return Decision.DENY
