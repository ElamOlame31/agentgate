"""
AgentGate test suite.

5 tests — each proves a core guarantee:
  1. Legitimate agent → PERMIT
  2. Out-of-scope resource → DENY
  3. Unauthorized action → DENY
  4. Policy blocks matching resource
  5. AgentGateUnavailable raised when server unreachable
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import patch
import httpx

from core.platform.models import AgentRegistration, AuthorizationRequest, Decision
from core.enforcement.trust_engine import compute_trust, make_decision
from core.enforcement.policy_engine import _parse_policy_fallback, check_policies
from agentgate.exceptions import AgentGateUnavailable
from agentgate import AgentGate


# ── Fixtures ──────────────────────────────────────────────────────────────────

def make_agent(
    agent_id="test_agent",
    purpose="Read and summarize quarterly business reports",
    resources=None,
    actions=None,
    token="test-token-123",
):
    return AgentRegistration(
        agent_id=agent_id,
        name="Test Agent",
        declared_purpose=purpose,
        authorized_resources=resources or ["/documents/*"],
        authorized_actions=actions or ["read", "search"],
        token=token,
    )


def make_request(agent_id="test_agent", action="read", resource="/documents/report_q1.pdf", token="test-token-123"):
    return AuthorizationRequest(
        agent_id=agent_id,
        action=action,
        resource=resource,
        justification="Summarizing quarterly report",
        token=token,
    )


# ── Test 1: Legitimate agent → PERMIT ─────────────────────────────────────────

def test_legitimate_agent_gets_permit():
    """A well-behaved agent reading an authorized resource must be PERMITTED."""
    agent = make_agent()
    request = make_request()

    breakdown, flags = compute_trust(agent, request, {})
    decision = make_decision(breakdown, flags)

    assert decision == Decision.PERMIT, (
        f"Expected PERMIT but got {decision}. "
        f"Score: {breakdown.final_score}, flags: {flags}"
    )


# ── Test 2: Out-of-scope resource → DENY ──────────────────────────────────────

def test_out_of_scope_resource_gets_denied():
    """An agent accessing a resource outside its declared scope must be DENIED."""
    agent = make_agent(resources=["/documents/*"])
    request = make_request(resource="/confidential/salary.xlsx")

    breakdown, flags = compute_trust(agent, request, {})
    decision = make_decision(breakdown, flags)

    assert decision == Decision.DENY, (
        f"Expected DENY but got {decision}. "
        f"Score: {breakdown.final_score}, flags: {flags}"
    )
    assert any("RESOURCE_OUT_OF_SCOPE" in f for f in flags)


# ── Test 3: Unauthorized action → DENY ────────────────────────────────────────

def test_unauthorized_action_gets_denied():
    """An agent performing an action not in its authorized_actions must be DENIED."""
    agent = make_agent(actions=["read", "search"])
    request = make_request(action="delete", resource="/documents/report_q1.pdf")

    breakdown, flags = compute_trust(agent, request, {})
    decision = make_decision(breakdown, flags)

    assert decision == Decision.DENY, (
        f"Expected DENY but got {decision}. "
        f"Score: {breakdown.final_score}, flags: {flags}"
    )
    assert any("UNAUTHORIZED_ACTION" in f for f in flags)


# ── Test 4: Policy blocks matching resource ────────────────────────────────────

def test_policy_blocks_matching_resource():
    """A DENY policy matching action+resource must produce a PolicyMatch."""
    from core.enforcement.policy_engine import PolicyMatch

    parsed = _parse_policy_fallback("agents must never delete files in /confidential")

    assert parsed["effect"] == "DENY"
    assert parsed["action_pattern"] == "delete"
    assert "confidential" in parsed["resource_pattern"]


# ── Test 5: AgentGateUnavailable when server unreachable ──────────────────────

def test_agentgate_unavailable_when_server_down():
    """SDK must raise AgentGateUnavailable when the server cannot be reached."""
    gate = AgentGate.__new__(AgentGate)
    gate.url = "http://localhost:19999"
    gate._agent_id = "test_agent"
    gate._token = "test-token-123"
    gate._headers = {}
    gate.timeout = 2.0
    gate.raise_on_deny = True
    gate.raise_on_escalate = False
    gate.auto_resolve_pending = True
    gate.pending_timeout = 5

    with pytest.raises(AgentGateUnavailable) as exc_info:
        gate.authorize("read", "/documents/report.pdf")

    assert "19999" in str(exc_info.value)


# ── Test 6: Path traversal bypass prevention ──────────────────────────────────

def test_path_traversal_url_encoded_bypass_is_blocked():
    """
    URL-encoded traversal sequences must not bypass scope enforcement.

    Without normalization, /reports/%2e%2e/confidential/salary.xlsx passes
    the literal '..' check AND matches fnmatch '/reports/*' — giving an agent
    access to /confidential/ even though it's only authorized for /reports/*.
    """
    from server.main import _normalize_resource

    agent = make_agent(resources=["/reports/*"])

    traversal_variants = [
        "/reports/%2e%2e/confidential/salary.xlsx",      # %2e%2e
        "/reports/.%2e/confidential/salary.xlsx",        # .%2e
        "/reports/%2e./confidential/salary.xlsx",        # %2e.
        "/reports/%252e%252e/confidential/salary.xlsx",  # double-encoded
        "/reports///../confidential/salary.xlsx",        # double slash
    ]

    for raw in traversal_variants:
        normalized = _normalize_resource(raw)
        request = make_request(resource=normalized)
        breakdown, flags = compute_trust(agent, request, {})
        decision = make_decision(breakdown, flags)

        assert decision == Decision.DENY, (
            f"PATH TRAVERSAL BYPASS: '{raw}' normalized to '{normalized}' "
            f"was {decision} instead of DENY. flags={flags}"
        )
        assert any("RESOURCE_OUT_OF_SCOPE" in f for f in flags), (
            f"Expected RESOURCE_OUT_OF_SCOPE flag for '{raw}', got: {flags}"
        )


def test_path_traversal_legitimate_access_still_permitted():
    """Normalization must not break legitimate resource access."""
    agent = make_agent(resources=["/reports/*"])

    legit_resources = [
        "/reports/q3.pdf",
        "/reports/2025/q4.pdf",
        "/reports/annual_summary.xlsx",
    ]

    for resource in legit_resources:
        request = make_request(resource=resource)
        breakdown, flags = compute_trust(agent, request, {})
        decision = make_decision(breakdown, flags)

        assert decision == Decision.PERMIT, (
            f"Legitimate resource '{resource}' was incorrectly {decision}. "
            f"flags={flags}"
        )
