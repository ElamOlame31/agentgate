"""
Tests for trust contagion (core/contagion.py + integration via /authorize).

Contagion rules:
  - When agent B is quarantined:
      * B's parent (if any) gets a -15 penalty on its next trust score.
      * Each of B's children gets a -30 penalty on their next trust score.
  - Penalty is additive, capped at 60, has a 1-hour TTL.
  - Released quarantine clears contagion propagated FROM that agent.
  - CONTAGION:FROM_PARENT / CONTAGION:FROM_CHILD flags appear in attack_flags.
"""

import time
import pytest
from unittest.mock import patch

import core.contagion as contagion
from core.models import AgentRegistration


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_agent(agent_id: str, delegated_by: str = None, depth: int = 0) -> AgentRegistration:
    return AgentRegistration(
        agent_id=agent_id,
        name=agent_id,
        declared_purpose="testing",
        authorized_resources=["/*"],
        authorized_actions=["read"],
        delegated_by=delegated_by,
        delegation_depth=depth,
    )


@pytest.fixture(autouse=True)
def clear_store():
    """Reset contagion store before each test."""
    contagion._store.clear()
    yield
    contagion._store.clear()


# ── Unit: propagate_quarantine ─────────────────────────────────────────────────

class TestPropagateQuarantine:
    def test_child_quarantined_penalises_parent(self):
        agents = {
            "parent": _make_agent("parent"),
            "child": _make_agent("child", delegated_by="parent", depth=1),
        }
        affected = contagion.propagate_quarantine("child", agents)
        assert "parent" in affected
        penalty, flags = contagion.get_contagion_penalty("parent")
        assert penalty == 15.0
        assert any("FROM_CHILD" in f for f in flags)
        assert any("child" in f for f in flags)

    def test_parent_quarantined_penalises_all_children(self):
        agents = {
            "parent": _make_agent("parent"),
            "child1": _make_agent("child1", delegated_by="parent", depth=1),
            "child2": _make_agent("child2", delegated_by="parent", depth=1),
        }
        affected = contagion.propagate_quarantine("parent", agents)
        assert "child1" in affected
        assert "child2" in affected
        assert "parent" not in affected  # parent is source, not affected

        p1, f1 = contagion.get_contagion_penalty("child1")
        p2, f2 = contagion.get_contagion_penalty("child2")
        assert p1 == 30.0
        assert p2 == 30.0
        assert any("FROM_PARENT" in f for f in f1)
        assert any("FROM_PARENT" in f for f in f2)

    def test_root_agent_no_parent_to_penalise(self):
        agents = {"root": _make_agent("root")}
        affected = contagion.propagate_quarantine("root", agents)
        assert affected == []
        penalty, flags = contagion.get_contagion_penalty("root")
        assert penalty == 0.0

    def test_unknown_agent_returns_empty(self):
        affected = contagion.propagate_quarantine("ghost", {})
        assert affected == []

    def test_no_cross_contamination_between_siblings(self):
        agents = {
            "parent": _make_agent("parent"),
            "sibling1": _make_agent("sibling1", delegated_by="parent", depth=1),
            "sibling2": _make_agent("sibling2", delegated_by="parent", depth=1),
        }
        # Quarantine sibling1 — sibling2 should NOT be directly affected
        contagion.propagate_quarantine("sibling1", agents)
        penalty, _ = contagion.get_contagion_penalty("sibling2")
        assert penalty == 0.0  # sibling2 is not sibling1's parent or child

    def test_grandparent_not_penalised(self):
        agents = {
            "grandparent": _make_agent("grandparent"),
            "parent": _make_agent("parent", delegated_by="grandparent", depth=1),
            "child": _make_agent("child", delegated_by="parent", depth=2),
        }
        # Quarantine child — only parent should be penalised, not grandparent
        contagion.propagate_quarantine("child", agents)
        p_parent, _ = contagion.get_contagion_penalty("parent")
        p_grand, _ = contagion.get_contagion_penalty("grandparent")
        assert p_parent == 15.0
        assert p_grand == 0.0

    def test_both_directions_when_agent_has_parent_and_children(self):
        agents = {
            "grandparent": _make_agent("grandparent"),
            "middle": _make_agent("middle", delegated_by="grandparent", depth=1),
            "child": _make_agent("child", delegated_by="middle", depth=2),
        }
        # Quarantine middle — grandparent gets from_child (-15), child gets from_parent (-30)
        affected = contagion.propagate_quarantine("middle", agents)
        assert set(affected) == {"grandparent", "child"}
        gp_penalty, gp_flags = contagion.get_contagion_penalty("grandparent")
        c_penalty, c_flags = contagion.get_contagion_penalty("child")
        assert gp_penalty == 15.0
        assert c_penalty == 30.0
        assert any("FROM_CHILD" in f for f in gp_flags)
        assert any("FROM_PARENT" in f for f in c_flags)


# ── Unit: get_contagion_penalty ────────────────────────────────────────────────

class TestGetContagionPenalty:
    def test_no_record_returns_zero(self):
        penalty, flags = contagion.get_contagion_penalty("nobody")
        assert penalty == 0.0
        assert flags == []

    def test_penalty_cap_at_60(self):
        agents = {
            "quarantined1": _make_agent("quarantined1"),
            "quarantined2": _make_agent("quarantined2"),
            "quarantined3": _make_agent("quarantined3"),
            "victim": _make_agent("victim"),
        }
        # Give victim 3 separate from_parent penalties of 30 each (= 90 raw, capped at 60)
        contagion._apply("victim", "quarantined1", "from_parent", 30.0)
        contagion._apply("victim", "quarantined2", "from_parent", 30.0)
        contagion._apply("victim", "quarantined3", "from_parent", 30.0)
        penalty, _ = contagion.get_contagion_penalty("victim")
        assert penalty == 60.0

    def test_expired_record_not_included(self):
        # Inject a record with a very short TTL
        record = contagion.ContagionRecord(
            source_agent_id="source",
            direction="from_parent",
            penalty=30.0,
            created_at=time.time() - 7200,  # 2 hours ago
            ttl_seconds=3600.0,
        )
        contagion._store["victim"] = [record]
        penalty, flags = contagion.get_contagion_penalty("victim")
        assert penalty == 0.0
        assert flags == []

    def test_duplicate_source_refreshed_not_doubled(self):
        agents = {
            "parent": _make_agent("parent"),
            "child": _make_agent("child", delegated_by="parent", depth=1),
        }
        contagion.propagate_quarantine("child", agents)
        contagion.propagate_quarantine("child", agents)  # second call, same source
        penalty, _ = contagion.get_contagion_penalty("parent")
        assert penalty == 15.0  # not 30


# ── Unit: clear_contagion ──────────────────────────────────────────────────────

class TestClearContagion:
    def test_clear_removes_records_from_source(self):
        agents = {
            "parent": _make_agent("parent"),
            "child": _make_agent("child", delegated_by="parent", depth=1),
        }
        contagion.propagate_quarantine("child", agents)
        penalty_before, _ = contagion.get_contagion_penalty("parent")
        assert penalty_before == 15.0

        contagion.clear_contagion("child")
        penalty_after, _ = contagion.get_contagion_penalty("parent")
        assert penalty_after == 0.0

    def test_clear_nonexistent_is_noop(self):
        contagion.clear_contagion("does_not_exist")  # must not raise

    def test_clear_only_removes_from_source(self):
        agents = {
            "parent": _make_agent("parent"),
            "child1": _make_agent("child1", delegated_by="parent", depth=1),
            "child2": _make_agent("child2", delegated_by="parent", depth=1),
        }
        contagion.propagate_quarantine("child1", agents)
        contagion.propagate_quarantine("child2", agents)
        # Both child1 and child2 penalised parent — clearing child1 keeps child2's record
        contagion.clear_contagion("child1")
        penalty, flags = contagion.get_contagion_penalty("parent")
        assert penalty == 15.0
        assert any("child2" in f for f in flags)


# ── Integration: contagion flag appears in trust score ─────────────────────────

class TestContagionTrustIntegration:
    """Verify that trust_engine.compute_trust applies contagion_penalty to beh_score."""

    def _agent(self, agent_id="agent-x"):
        from core.models import AgentRegistration, AuthorizationRequest
        reg = AgentRegistration(
            agent_id=agent_id,
            name=agent_id,
            declared_purpose="document retrieval",
            authorized_resources=["/documents/*"],
            authorized_actions=["read"],
        )
        req = AuthorizationRequest(
            agent_id=agent_id,
            action="read",
            resource="/documents/report.pdf",
        )
        return reg, req

    def test_contagion_penalty_reduces_behavioural_score(self):
        from core import trust_engine
        reg, req = self._agent()
        bd_clean, _ = trust_engine.compute_trust(reg, req, {}, 0.0, 0.0, [])
        bd_tainted, flags_tainted = trust_engine.compute_trust(
            reg, req, {}, 0.0, 30.0, ["CONTAGION:FROM_PARENT:some-parent"]
        )
        assert bd_tainted.behavioral_score < bd_clean.behavioral_score
        assert bd_tainted.final_score < bd_clean.final_score
        assert any("CONTAGION" in f for f in flags_tainted)

    def test_contagion_flag_appears_in_attack_flags(self):
        from core import trust_engine
        reg, req = self._agent()
        _, flags = trust_engine.compute_trust(
            reg, req, {}, 0.0, 15.0, ["CONTAGION:FROM_CHILD:bad-child"]
        )
        assert "CONTAGION:FROM_CHILD:bad-child" in flags

    def test_zero_contagion_no_effect(self):
        from core import trust_engine
        reg, req = self._agent()
        bd_a, f_a = trust_engine.compute_trust(reg, req, {}, 0.0, 0.0, [])
        bd_b, f_b = trust_engine.compute_trust(reg, req, {}, 0.0, 0.0, None)
        assert bd_a.behavioral_score == bd_b.behavioral_score
        assert not any("CONTAGION" in f for f in f_a)
        assert not any("CONTAGION" in f for f in f_b)


# ── Integration: API endpoint ──────────────────────────────────────────────────

class TestContagionAPI:
    @pytest.fixture(autouse=True)
    def api_client(self):
        import os
        from fastapi.testclient import TestClient
        from server.main import app, _agents
        saved_key = os.environ.pop("AGENTGATE_API_KEY", None)
        with TestClient(app) as client:
            self.client = client
            self._agents = _agents
            yield
        if saved_key:
            os.environ["AGENTGATE_API_KEY"] = saved_key

    def _register(self, agent_id: str, parent_id: str = None, parent_token: str = None) -> str:
        if parent_id:
            payload = {
                "parent_agent_id": parent_id,
                "parent_token": parent_token,
                "child_agent_id": agent_id,
                "child_name": agent_id,
                "child_declared_purpose": "testing",
                "child_resources": ["/*"],
                "child_actions": ["read"],
            }
            resp = self.client.post("/agents/delegate", json=payload)
        else:
            payload = {
                "agent_id": agent_id,
                "name": agent_id,
                "declared_purpose": "testing",
                "authorized_resources": ["/*"],
                "authorized_actions": ["read"],
            }
            resp = self.client.post("/agents/register", json=payload)
        assert resp.status_code == 200, resp.text
        return resp.json()["token"]

    def test_get_contagion_empty(self):
        resp = self.client.get("/contagion")
        assert resp.status_code == 200
        assert resp.json() == {}

    def test_quarantine_propagates_to_parent_visible_at_endpoint(self):
        import uuid
        parent_id = f"ctest-par-{uuid.uuid4().hex[:8]}"
        child_id = f"ctest-chd-{uuid.uuid4().hex[:8]}"
        parent_token = self._register(parent_id)
        self._register(child_id, parent_id=parent_id, parent_token=parent_token)

        resp = self.client.post(f"/agents/{child_id}/quarantine", json={"trigger": "TEST"})
        assert resp.status_code == 200

        data = self.client.get("/contagion").json()
        assert parent_id in data
        records = data[parent_id]
        assert any(r["source"] == child_id for r in records)
        assert any(r["direction"] == "from_child" for r in records)

    def test_clear_contagion_endpoint(self):
        import uuid
        parent_id = f"ctest-par-{uuid.uuid4().hex[:8]}"
        child_id = f"ctest-chd-{uuid.uuid4().hex[:8]}"
        parent_token = self._register(parent_id)
        self._register(child_id, parent_id=parent_id, parent_token=parent_token)

        self.client.post(f"/agents/{child_id}/quarantine", json={"trigger": "TEST"})
        assert parent_id in self.client.get("/contagion").json()

        resp = self.client.post(f"/agents/{child_id}/contagion/clear")
        assert resp.status_code == 200
        assert self.client.get("/contagion").json().get(parent_id) is None
