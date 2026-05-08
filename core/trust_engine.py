import fnmatch
import posixpath
import time
import urllib.parse
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

# Velocity: global fallback threshold for agents with no baseline yet
GLOBAL_MAX_RPM = 20
# Minimum requests before we trust the baseline over the global threshold
BASELINE_MIN_REQUESTS = 10
# How many standard deviations above baseline before we flag HIGH_VELOCITY
BASELINE_SPIKE_MULTIPLIER = 2.5


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
    def _normalize(path: str) -> str:
        decoded = urllib.parse.unquote(urllib.parse.unquote(path))
        decoded = decoded.replace("\x00", "")
        normalized = posixpath.normpath(decoded)
        return normalized if normalized.startswith("/") else "/" + normalized

    def _matches(resource: str, pattern: str) -> bool:
        resource = _normalize(resource)
        pattern = _normalize(pattern)
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


def score_delegation(
    agent: AgentRegistration,
    request: "AuthorizationRequest",
    agents: dict,
) -> tuple[float, list[str]]:
    from core.delegation import (
        check_chain_scope, compute_chain_trust_multiplier, MAX_DELEGATION_DEPTH
    )
    flags = []
    score = 100.0
    depth = agent.delegation_depth

    # Penalize deep delegation chains
    if depth > 0:
        score -= depth * 15.0

    # Walk full chain — block if request exceeds any ancestor's scope
    if depth > 0:
        chain_ok, chain_error = check_chain_scope(
            agent.agent_id, request.action, request.resource, agents
        )
        if not chain_ok:
            flags.append("CHAIN_SCOPE_VIOLATION")
            flags.append(f"VIOLATION_DETAIL:{chain_error[:80]}")
            score = 0.0  # hard zero — cannot proceed

    # Legacy single-level scope check
    if agent.delegated_by and agent.scope_at_delegation:
        current_scope = set(agent.authorized_actions)
        parent_scope = set(agent.scope_at_delegation)
        if not current_scope.issubset(parent_scope):
            flags.append("SCOPE_ESCALATION_AT_DELEGATION")
            score -= 50.0

    if depth > MAX_DELEGATION_DEPTH:
        flags.append(f"EXCESSIVE_DELEGATION_DEPTH:{depth}")
        score = 0.0

    # Apply chain trust decay
    multiplier = compute_chain_trust_multiplier(depth)
    score = score * multiplier

    return max(0.0, score), flags


def score_behavioral(agent_id: str, action: str) -> tuple[float, list[str]]:
    flags = []
    score = 100.0

    history = audit.get_agent_request_history(agent_id, window_seconds=60.0)
    rpm = len(history)

    # Use per-agent baseline if the agent has enough history; fall back to global threshold
    baseline = audit.get_agent_baseline(agent_id)
    if baseline and baseline["total_requests"] >= BASELINE_MIN_REQUESTS:
        agent_avg_rpm = baseline["avg_rpm"]
        # Effective ceiling: agent's own average * spike multiplier, floor at GLOBAL_MAX_RPM
        effective_max = max(GLOBAL_MAX_RPM, agent_avg_rpm * BASELINE_SPIKE_MULTIPLIER)
        anomaly_ratio = rpm / max(agent_avg_rpm, 0.1)

        if rpm > effective_max:
            excess_ratio = rpm / effective_max
            penalty = min(90.0, (excess_ratio - 1.0) * 45.0)
            score -= penalty
            if anomaly_ratio > 5.0:
                flags.append(f"CRITICAL_VELOCITY:{rpm}_RPM|BASELINE:{round(agent_avg_rpm,1)}")
            else:
                flags.append(f"HIGH_VELOCITY:{rpm}_RPM|BASELINE:{round(agent_avg_rpm,1)}")
    else:
        # Cold start: use global threshold
        if rpm > GLOBAL_MAX_RPM:
            excess = rpm - GLOBAL_MAX_RPM
            penalty = min(90.0, excess * 5.0)
            score -= penalty
            if rpm > GLOBAL_MAX_RPM * 2:
                flags.append(f"CRITICAL_VELOCITY:{rpm}_RPM")
            else:
                flags.append(f"HIGH_VELOCITY:{rpm}_RPM")

    # Check for repeated identical actions (replay-style behavior)
    recent_actions = [h["action"] for h in history[:10]]
    if recent_actions.count(action) > 5:
        flags.append(f"REPETITIVE_ACTION:{action}")
        score -= 25.0

    # Only update baseline with clean observations — prevents gradual baseline poisoning
    if not any("VELOCITY" in f for f in flags):
        audit.update_agent_baseline(agent_id, float(rpm))

    return max(0.0, score), flags


def compute_trust(
    agent: AgentRegistration,
    request: AuthorizationRequest,
    agents: dict = None,
) -> tuple[TrustBreakdown, list[str]]:
    all_flags = []

    id_score, id_flags = score_identity(agent, request)
    all_flags.extend(id_flags)

    del_score, del_flags = score_delegation(agent, request, agents or {})
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

    # Hard deny on delegation chain violations — always, regardless of sensitivity
    if any("CHAIN_SCOPE_VIOLATION" in f for f in flags):
        return Decision.DENY

    # Hard deny when delegation depth exceeds the configured maximum
    if any("EXCESSIVE_DELEGATION_DEPTH" in f for f in flags):
        return Decision.DENY

    # Hard deny on unauthorized action — agent doing something outside its contract
    if any("UNAUTHORIZED_ACTION" in f for f in flags):
        return Decision.DENY

    # Hard deny when agent accesses resources outside its declared scope
    if any("RESOURCE_OUT_OF_SCOPE" in f for f in flags):
        return Decision.DENY

    # Hard deny on critical security flags for sensitive resources
    critical_flags = [f for f in flags if any(kw in f for kw in [
        "TOKEN_MISMATCH", "SCOPE_ESCALATION"
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
