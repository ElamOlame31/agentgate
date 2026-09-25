"""
Quarantine Mode Test Suite.

Covers:
  - Unit: core/quarantine.py — all state transitions, triggers, timers
  - API: server endpoints — GET/POST/DELETE /agents/{id}/quarantine, GET /quarantines
  - Integration: authorize returns DENY+QUARANTINED when agent is quarantined
  - Soft trigger: 5 DENYs in 60s auto-quarantine
"""

import sys
import os
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import core.detection.quarantine as q
from core.detection.quarantine import (
    QUARANTINE_BASE_SECONDS, QUARANTINE_EXTENSION_SECONDS,
    QUARANTINE_MAX_SECONDS, CONSECUTIVE_DENY_THRESHOLD, DENY_WINDOW_SECONDS,
)


# ── Unit tests ─────────────────────────────────────────────────────────────────

class TestQuarantineUnit:
    """Pure unit tests — no I/O, no HTTP. Reset shared state before each test."""

    def setup_method(self):
        q._store.clear()
        q._deny_windows.clear()

    # ── quarantine() ─────────────────────────────────────────────────────────

    def test_quarantine_creates_record(self):
        rec = q.quarantine("agent1", "TEST")
        assert rec.agent_id == "agent1"
        assert rec.trigger == "TEST"
        assert rec.is_active()
        assert rec.violation_count == 1
        assert rec.extended_count == 0

    def test_quarantine_default_duration(self):
        rec = q.quarantine("agent_dur", "T")
        remaining = rec.remaining_seconds()
        assert QUARANTINE_BASE_SECONDS - 2 < remaining <= QUARANTINE_BASE_SECONDS

    def test_quarantine_permanent_pins_max_duration(self):
        rec = q.quarantine("agent_perm", "HARD", permanent=True)
        remaining = rec.remaining_seconds()
        assert remaining > QUARANTINE_MAX_SECONDS - 5

    def test_quarantine_idempotent_extends_window(self):
        rec1 = q.quarantine("agentY", "TRIGGER_A")
        exp1 = rec1.expires_at
        rec2 = q.quarantine("agentY", "TRIGGER_B")
        assert rec2.expires_at >= exp1
        assert rec2.violation_count == 2
        assert rec2.extended_count == 1
        assert rec2.trigger == "TRIGGER_B"

    def test_quarantine_extension_capped_at_max(self):
        rec = q.quarantine("capbot", "T")
        # Pin expires_at close to now+MAX to test the cap
        rec.expires_at = time.time() + QUARANTINE_MAX_SECONDS - 1
        q._store["capbot"] = rec
        rec2 = q.quarantine("capbot", "T")
        assert rec2.expires_at <= time.time() + QUARANTINE_MAX_SECONDS + 1

    # ── is_quarantined() ─────────────────────────────────────────────────────

    def test_is_quarantined_true_while_active(self):
        q.quarantine("agentX", "TEST")
        assert q.is_quarantined("agentX") is True

    def test_is_quarantined_false_before_quarantine(self):
        assert q.is_quarantined("nonexistent") is False

    def test_is_quarantined_false_after_expiry(self):
        rec = q.quarantine("expbot", "T")
        rec.expires_at = time.time() - 1  # manually expire
        assert q.is_quarantined("expbot") is False

    def test_expired_record_auto_evicted_from_store(self):
        rec = q.quarantine("evictbot", "T")
        rec.expires_at = time.time() - 1
        q.is_quarantined("evictbot")
        assert "evictbot" not in q._store

    # ── get_record() ─────────────────────────────────────────────────────────

    def test_get_record_returns_active(self):
        q.quarantine("agentA", "T1")
        rec = q.get_record("agentA")
        assert rec is not None
        assert rec.agent_id == "agentA"

    def test_get_record_none_for_unquarantined(self):
        assert q.get_record("nothere") is None

    def test_get_record_none_after_expiry(self):
        rec = q.quarantine("expA", "T")
        rec.expires_at = time.time() - 1
        assert q.get_record("expA") is None

    # ── release() ────────────────────────────────────────────────────────────

    def test_release_removes_quarantine(self):
        q.quarantine("agentZ", "TEST")
        assert q.is_quarantined("agentZ")
        released = q.release("agentZ")
        assert released is True
        assert not q.is_quarantined("agentZ")

    def test_release_nonexistent_returns_false(self):
        assert q.release("nobody") is False

    def test_release_clears_deny_window(self):
        q._deny_windows["agentD"] = __import__("collections").deque([time.time()])
        q.quarantine("agentD", "T")
        q.release("agentD")
        assert "agentD" not in q._deny_windows

    # ── get_all() ────────────────────────────────────────────────────────────

    def test_get_all_returns_active(self):
        q.quarantine("a1", "T")
        q.quarantine("a2", "T")
        all_q = q.get_all()
        ids = {r["agent_id"] for r in all_q}
        assert "a1" in ids and "a2" in ids

    def test_get_all_prunes_expired(self):
        rec = q.quarantine("expbot2", "T")
        rec.expires_at = time.time() - 1
        q._store["expbot2"] = rec
        all_q = q.get_all()
        assert not any(r["agent_id"] == "expbot2" for r in all_q)

    # ── record_deny() — soft trigger ─────────────────────────────────────────

    def test_soft_trigger_returns_none_below_threshold(self):
        for i in range(CONSECUTIVE_DENY_THRESHOLD - 1):
            trigger = q.record_deny("softbot")
            assert trigger is None, f"Should not trigger at iteration {i}"

    def test_soft_trigger_fires_at_threshold(self):
        for i in range(CONSECUTIVE_DENY_THRESHOLD - 1):
            q.record_deny("firebot")
        trigger = q.record_deny("firebot")
        assert trigger == "CONSECUTIVE_DENY"

    def test_soft_trigger_window_resets_after_fire(self):
        for _ in range(CONSECUTIVE_DENY_THRESHOLD):
            q.record_deny("resetbot")
        # Window cleared — next deny must not re-trigger immediately
        assert q.record_deny("resetbot") is None

    def test_soft_trigger_old_events_evicted(self):
        from collections import deque
        # Plant old timestamps outside the window
        old_ts = time.time() - DENY_WINDOW_SECONDS - 10
        q._deny_windows["oldbot"] = deque([old_ts] * (CONSECUTIVE_DENY_THRESHOLD - 1))
        # Even with old events, a single new deny should not trigger
        trigger = q.record_deny("oldbot")
        assert trigger is None

    # ── should_quarantine_on_flags() — hard trigger ──────────────────────────

    def test_hard_trigger_exfil_flag(self):
        flags = ["SOME_FLAG", "KILL_CHAIN:BULK_READ_THEN_EXFIL", "OTHER"]
        assert q.should_quarantine_on_flags(flags) == "KILL_CHAIN:BULK_READ_THEN_EXFIL"

    def test_hard_trigger_destroy_flag(self):
        flags = ["KILL_CHAIN:BULK_READ_THEN_DESTROY"]
        assert q.should_quarantine_on_flags(flags) == "KILL_CHAIN:BULK_READ_THEN_DESTROY"

    def test_hard_trigger_read_then_delete(self):
        flags = ["KILL_CHAIN:READ_THEN_DELETE"]
        assert q.should_quarantine_on_flags(flags) == "KILL_CHAIN:READ_THEN_DELETE"

    def test_hard_trigger_critical_velocity(self):
        flags = ["CRITICAL_VELOCITY"]
        assert q.should_quarantine_on_flags(flags) == "CRITICAL_VELOCITY"

    def test_clean_flags_no_hard_trigger(self):
        flags = ["SCOPE_VIOLATION", "VELOCITY_SPIKE", "KILL_CHAIN:SENSITIVITY_RAMP:5"]
        assert q.should_quarantine_on_flags(flags) is None

    def test_empty_flags_no_hard_trigger(self):
        assert q.should_quarantine_on_flags([]) is None

    # ── load_from_persistence() ───────────────────────────────────────────────

    def test_load_from_persistence_restores_active(self):
        future = time.time() + 900
        q.load_from_persistence([{
            "agent_id": "restored",
            "quarantined_at": time.time(),
            "expires_at": future,
            "trigger": "PERSISTENCE_TEST",
            "violation_count": 2,
            "extended_count": 1,
        }])
        assert q.is_quarantined("restored")
        rec = q.get_record("restored")
        assert rec.trigger == "PERSISTENCE_TEST"
        assert rec.violation_count == 2
        assert rec.extended_count == 1

    def test_load_from_persistence_skips_expired(self):
        q.load_from_persistence([{
            "agent_id": "expired_restore",
            "quarantined_at": time.time() - 2000,
            "expires_at": time.time() - 1,
            "trigger": "OLD",
        }])
        assert not q.is_quarantined("expired_restore")

    # ── to_dict() ────────────────────────────────────────────────────────────

    def test_to_dict_has_required_keys(self):
        rec = q.quarantine("dictbot", "T")
        d = rec.to_dict()
        for key in ("agent_id", "quarantined_at", "expires_at", "trigger",
                    "violation_count", "extended_count", "remaining_seconds", "active"):
            assert key in d, f"Missing key: {key}"

    def test_to_dict_active_true_while_active(self):
        rec = q.quarantine("activebot", "T")
        assert rec.to_dict()["active"] is True

    def test_to_dict_remaining_seconds_positive(self):
        rec = q.quarantine("rembot", "T")
        assert rec.to_dict()["remaining_seconds"] > 0


# ── API integration tests ──────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _clean_quarantine_global():
    """Reset quarantine state before every test in this module."""
    q._store.clear()
    q._deny_windows.clear()
    yield
    q._store.clear()
    q._deny_windows.clear()


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient
    from server.main import app
    saved = os.environ.pop("AGENTGATE_API_KEY", None)
    try:
        with TestClient(app) as c:
            yield c
    finally:
        if saved is not None:
            os.environ["AGENTGATE_API_KEY"] = saved


def _register(client, agent_id, actions=None, resources=None):
    r = client.post("/agents/register", json={
        "agent_id": agent_id,
        "name": "Quarantine Test Agent",
        "declared_purpose": "Read and summarize business reports",
        "authorized_resources": resources or ["/reports/*"],
        "authorized_actions": actions or ["read"],
    })
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _uid():
    return f"qtest_{uuid.uuid4().hex[:8]}"


class TestQuarantineAPI:

    def test_status_not_quarantined(self, client):
        aid = _uid()
        _register(client, aid)
        r = client.get(f"/agents/{aid}/quarantine")
        assert r.status_code == 200
        assert r.json()["quarantined"] is False

    def test_manual_quarantine_status(self, client):
        aid = _uid()
        _register(client, aid)
        r = client.post(f"/agents/{aid}/quarantine",
                        json={"trigger": "MANUAL_TEST"})
        assert r.status_code == 200
        data = r.json()
        assert data["agent_id"] == aid
        assert data["trigger"] == "MANUAL_TEST"
        assert data["active"] is True
        assert data["remaining_seconds"] > 0
        # GET endpoint must reflect quarantine
        r2 = client.get(f"/agents/{aid}/quarantine")
        d2 = r2.json()
        assert d2["quarantined"] is True
        assert d2["trigger"] == "MANUAL_TEST"

    def test_quarantined_agent_authorize_returns_deny(self, client):
        aid = _uid()
        token = _register(client, aid)
        client.post(f"/agents/{aid}/quarantine", json={"trigger": "TEST"})
        r = client.post("/authorize", json={
            "agent_id": aid,
            "action": "read",
            "resource": "/reports/q1.pdf",
            "justification": "Quarterly review",
            "token": token,
        })
        assert r.status_code == 200
        data = r.json()
        assert data["decision"] == "DENY"
        assert "QUARANTINED" in data["attack_flags"]
        assert any("QUARANTINE_TRIGGER" in f for f in data["attack_flags"])

    def test_quarantined_explanation_mentions_trigger(self, client):
        aid = _uid()
        token = _register(client, aid)
        client.post(f"/agents/{aid}/quarantine",
                    json={"trigger": "KILL_CHAIN:BULK_READ_THEN_EXFIL"})
        r = client.post("/authorize", json={
            "agent_id": aid,
            "action": "read",
            "resource": "/reports/q1.pdf",
            "justification": "Q review",
            "token": token,
        })
        assert "KILL_CHAIN:BULK_READ_THEN_EXFIL" in r.json()["explanation"]

    def test_release_quarantine(self, client):
        aid = _uid()
        token = _register(client, aid)
        client.post(f"/agents/{aid}/quarantine", json={"trigger": "TEST"})
        r = client.delete(f"/agents/{aid}/quarantine")
        assert r.status_code == 200
        assert r.json()["status"] == "released"
        # No longer quarantined
        r2 = client.get(f"/agents/{aid}/quarantine")
        assert r2.json()["quarantined"] is False

    def test_release_nonquarantined_returns_404(self, client):
        aid = _uid()
        _register(client, aid)
        r = client.delete(f"/agents/{aid}/quarantine")
        assert r.status_code == 404

    def test_release_unknown_agent_returns_404(self, client):
        r = client.delete("/agents/nobody_xyz_123/quarantine")
        assert r.status_code == 404

    def test_quarantine_unknown_agent_returns_404(self, client):
        r = client.post("/agents/nobody_xyz_456/quarantine",
                        json={"trigger": "TEST"})
        assert r.status_code == 404

    def test_list_quarantines_includes_all_active(self, client):
        a1, a2 = _uid(), _uid()
        _register(client, a1)
        _register(client, a2)
        client.post(f"/agents/{a1}/quarantine", json={"trigger": "T1"})
        client.post(f"/agents/{a2}/quarantine", json={"trigger": "T2"})
        r = client.get("/quarantines")
        assert r.status_code == 200
        ids = {item["agent_id"] for item in r.json()}
        assert a1 in ids
        assert a2 in ids

    def test_list_quarantines_excludes_released(self, client):
        aid = _uid()
        _register(client, aid)
        client.post(f"/agents/{aid}/quarantine", json={"trigger": "T"})
        client.delete(f"/agents/{aid}/quarantine")
        r = client.get("/quarantines")
        assert r.status_code == 200
        ids = {item["agent_id"] for item in r.json()}
        assert aid not in ids

    def test_soft_trigger_via_consecutive_denies(self, client):
        """5 DENYs in 60s must auto-quarantine the agent."""
        aid = _uid()
        token = _register(client, aid)
        # Force DENYs: unauthorized action causes DENY (identity check fails scope)
        for _ in range(CONSECUTIVE_DENY_THRESHOLD):
            client.post("/authorize", json={
                "agent_id": aid,
                "action": "delete",     # not in authorized_actions
                "resource": "/confidential/salary.txt",
                "justification": "test",
                "token": token,
            })
        assert q.is_quarantined(aid), (
            f"Agent must be quarantined after {CONSECUTIVE_DENY_THRESHOLD} consecutive DENYs"
        )
        # Next authorize must be blocked with QUARANTINED flag
        r = client.post("/authorize", json={
            "agent_id": aid,
            "action": "read",
            "resource": "/reports/q1.pdf",
            "justification": "legitimate",
            "token": token,
        })
        assert r.json()["decision"] == "DENY"
        assert "QUARANTINED" in r.json()["attack_flags"]

    def test_agents_list_includes_quarantine_status(self, client):
        aid = _uid()
        _register(client, aid)
        client.post(f"/agents/{aid}/quarantine", json={"trigger": "TEST"})
        r = client.get("/agents")
        assert r.status_code == 200
        agent_data = next((a for a in r.json() if a["agent_id"] == aid), None)
        assert agent_data is not None
        assert agent_data.get("quarantined") is True

    def test_agents_list_quarantined_false_when_not_quarantined(self, client):
        aid = _uid()
        _register(client, aid)
        r = client.get("/agents")
        agent_data = next((a for a in r.json() if a["agent_id"] == aid), None)
        assert agent_data is not None
        assert agent_data.get("quarantined") is False

    def test_permanent_quarantine_max_window(self, client):
        aid = _uid()
        _register(client, aid)
        r = client.post(f"/agents/{aid}/quarantine",
                        json={"trigger": "HARD", "permanent": True})
        assert r.status_code == 200
        assert r.json()["remaining_seconds"] > QUARANTINE_MAX_SECONDS - 10
