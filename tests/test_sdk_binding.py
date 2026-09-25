"""
SDK-side binding and redemption, tested against the real server.

These deliberately do not mock. The property being tested is that two separate
implementations — core/action_ref.py on the server, agentgate/action_ref.py in
the client — agree byte for byte, and a mock would assert only that the test
agrees with itself.
"""

import uuid

import pytest

import agentgate as sdk
from agentgate import action_ref as client_ref
from agentgate.exceptions import (
    AgentGateBindingError, AgentGateReceiptError,
)
from core.receipts.receipts import action_ref as server_ref


# ── The pin: client and server must not drift ─────────────────────────────────

class TestImplementationParity:
    @pytest.mark.parametrize("operation", [
        dict(agent_id="a", action="read", resource="/x", arguments=None),
        dict(agent_id="a", action="read", resource="/x", arguments={}),
        dict(agent_id="pay", action="TRANSFER", resource="/payments/./outbound",
             arguments={"amount_minor": 25_000, "recipient": "acct_9931"}),
        dict(agent_id="pay", action="transfer", resource="/a/../b",
             arguments={"nested": {"z": 1, "a": [1, 2, {"k": "v"}]}}),
        dict(agent_id="u", action="write", resource="/docs/rapport-été.pdf",
             arguments={"titre": "Résumé", "accent": "naïve façade"}),
        dict(agent_id="b", action="delete", resource="/x%2e%2e/y",
             arguments={"flag": True, "nothing": None, "count": 0}),
    ])
    def test_same_digest_on_both_sides(self, operation):
        assert client_ref.compute_action_ref(**operation) == \
               server_ref.compute_action_ref(**operation)

    def test_descriptor_versions_match(self):
        assert client_ref.DESCRIPTOR_VERSION == server_ref.DESCRIPTOR_VERSION

    def test_size_limits_match(self):
        assert client_ref.MAX_ARGUMENTS_BYTES == server_ref.MAX_ARGUMENTS_BYTES

    def test_normalization_matches(self):
        for path in ("/a/./b", "/a//b", "/a/../b", "a/b", "/a/%2e%2e/b", "/a/x\x00y"):
            assert client_ref.normalize_resource(path) == server_ref.normalize_resource(path)


# ── Live gate against the real app ────────────────────────────────────────────

def _wire_sdk_to_app(monkeypatch):
    """Point the SDK's module-level httpx calls at the real FastAPI app."""
    from fastapi.testclient import TestClient
    from server.main import app
    import server.main as sm

    client = TestClient(app)
    base = "http://live"

    def _post(url, **kw):
        return client.post(url[len(base):], json=kw.get("json"),
                           headers=kw.get("headers") or {})

    def _get(url, **kw):
        return client.get(url[len(base):], headers=kw.get("headers") or {})

    monkeypatch.setattr(sdk.httpx, "post", _post)
    monkeypatch.setattr(sdk.httpx, "get", _get)
    return sdk.AgentGate(base, api_key=sm._get_api_key() or "")


@pytest.fixture
def live_gate(monkeypatch):
    """A payment agent. Its decisions escalate, which is fine: the binding
    check is local and applies to any verdict."""
    gate = _wire_sdk_to_app(monkeypatch)
    # A fresh id per test: re-registering an existing agent is a 409 by design,
    # and these tests should not depend on the order they run in.
    gate.register(
        agent_id=f"sdk_pay_bot_{uuid.uuid4().hex[:8]}",
        name="PayBot",
        declared_purpose="Send approved supplier payments to known accounts",
        authorized_resources=["/payments/*"],
        authorized_actions=["transfer"],
    )
    return gate


@pytest.fixture
def permit_gate(monkeypatch):
    """A reporting agent whose in-scope reads are permitted.

    Redemption needs a PERMIT — a receipt for an escalation authorizes nothing
    and is refused — so the tests that spend receipts use this agent.
    """
    gate = _wire_sdk_to_app(monkeypatch)
    gate.register(
        agent_id=f"sdk_report_bot_{uuid.uuid4().hex[:8]}",
        name="ReportBot",
        declared_purpose="Summarize quarterly business reports for the executive team",
        authorized_resources=["/reports/*"],
        authorized_actions=["read", "search"],
    )
    return gate


ARGS = {"amount_minor": 25_000, "currency": "EUR", "recipient": "acct_9931"}
READ_ARGS = {"page_range": "1-10", "format": "text"}


class TestBindingOverTheWire:
    def test_a_permit_carries_a_binding_the_client_can_check(self, live_gate):
        result = live_gate.authorize("transfer", "/payments/outbound", arguments=ARGS)
        live_gate.check_binding(result, "transfer", "/payments/outbound", ARGS)

    def test_changed_amount_is_caught_before_execution(self, live_gate):
        """The headline case: an authorization for 250 EUR cannot pay 25000 EUR."""
        result = live_gate.authorize("transfer", "/payments/outbound", arguments=ARGS)
        with pytest.raises(AgentGateBindingError) as exc:
            live_gate.check_binding(
                result, "transfer", "/payments/outbound",
                dict(ARGS, amount_minor=2_500_000),
            )
        assert "changed after it was authorized" in str(exc.value)

    def test_redirected_recipient_is_caught(self, live_gate):
        result = live_gate.authorize("transfer", "/payments/outbound", arguments=ARGS)
        with pytest.raises(AgentGateBindingError):
            live_gate.check_binding(
                result, "transfer", "/payments/outbound",
                dict(ARGS, recipient="acct_attacker"),
            )

    def test_changed_resource_is_caught(self, live_gate):
        result = live_gate.authorize("transfer", "/payments/outbound", arguments=ARGS)
        with pytest.raises(AgentGateBindingError):
            live_gate.check_binding(result, "transfer", "/payments/internal", ARGS)

    def test_an_equivalent_path_spelling_still_binds(self, live_gate):
        result = live_gate.authorize("transfer", "/payments/outbound", arguments=ARGS)
        live_gate.check_binding(result, "transfer", "/payments/./outbound", ARGS)

    def test_a_response_without_a_binding_is_refused(self, live_gate):
        """No action_ref means nothing was bound; that cannot read as authorized."""
        result = live_gate.authorize("transfer", "/payments/outbound", arguments=ARGS)
        with pytest.raises(AgentGateBindingError):
            live_gate.check_binding(dict(result, action_ref=None),
                                    "transfer", "/payments/outbound", ARGS)


class TestRedemptionOverTheWire:
    def test_a_receipt_redeems_once(self, permit_gate):
        result = permit_gate.authorize("read", "/reports/q3.pdf", arguments=READ_ARGS)
        assert result["decision"] == "PERMIT"
        assert permit_gate.redeem(result)["redeemed"] is True

    def test_redeeming_twice_raises(self, permit_gate):
        result = permit_gate.authorize("read", "/reports/q3.pdf", arguments=READ_ARGS)
        permit_gate.redeem(result)
        with pytest.raises(AgentGateReceiptError) as exc:
            permit_gate.redeem(result)
        assert exc.value.reason == "RECEIPT_ALREADY_SPENT"

    def test_a_tampered_receipt_raises(self, permit_gate):
        result = permit_gate.authorize("read", "/reports/q3.pdf", arguments=READ_ARGS)
        with pytest.raises(AgentGateReceiptError) as exc:
            permit_gate.redeem(dict(result, response_sig="0" * 64))
        assert exc.value.reason == "SIGNATURE_MISMATCH"

    def test_a_receipt_that_authorizes_nothing_cannot_be_spent(self, live_gate):
        """An escalation is not a right to act, so it must not redeem."""
        result = live_gate.authorize("transfer", "/payments/outbound", arguments=ARGS)
        assert result["decision"] != "PERMIT"
        with pytest.raises(AgentGateReceiptError) as exc:
            live_gate.redeem(result)
        assert exc.value.reason == "RECEIPT_NOT_PERMIT"


# ── guard(): the path most callers will actually use ──────────────────────────

class TestGuard:
    def test_guard_authorizes_binds_redeems_and_runs(self, permit_gate):
        calls = []

        @permit_gate.guard("read", resource_arg="path")
        def read_report(path: str, page_range: str, fmt: str) -> str:
            calls.append((path, page_range, fmt))
            return "contents"

        assert read_report("/reports/q3.pdf", "1-10", "text") == "contents"
        assert calls == [("/reports/q3.pdf", "1-10", "text")]

    def test_guard_binds_every_argument_not_just_the_resource(self, live_gate):
        """
        The confused-deputy fix. Two calls that differ only in an argument the
        old guard() never saw must produce different authorizations.
        """
        seen = []

        @live_gate.guard("transfer", resource_arg="account", redeem=False)
        def transfer(account: str, amount_minor: int, recipient: str) -> str:
            return "sent"

        original_authorize = live_gate.authorize

        def capture(action, resource, justification="", arguments=None):
            result = original_authorize(action, resource, justification, arguments)
            seen.append(result["action_ref"])
            return result

        live_gate.authorize = capture
        transfer("/payments/outbound", 25_000, "acct_9931")
        transfer("/payments/outbound", 9_999_999, "acct_attacker")
        live_gate.authorize = original_authorize

        assert seen[0] != seen[1]

    def test_each_guarded_call_spends_its_own_receipt(self, permit_gate):
        """Two calls are two authorizations; neither reuses the other's receipt."""
        @permit_gate.guard("read", resource_arg="path")
        def read_report(path: str, page_range: str) -> str:
            return "contents"

        assert read_report("/reports/q3.pdf", "1-5") == "contents"
        assert read_report("/reports/q3.pdf", "1-5") == "contents"

    def test_guard_refuses_an_unbindable_argument(self, permit_gate):
        """Silently dropping it is how an argument ends up unbound by accident."""
        @permit_gate.guard("read", resource_arg="path")
        def read_report(path: str, sink) -> str:
            return "contents"

        with pytest.raises(client_ref.ActionRefError) as exc:
            read_report("/reports/q3.pdf", object())
        assert "exclude=('sink',)" in str(exc.value)

    def test_exclude_lets_an_unbindable_argument_through(self, permit_gate):
        @permit_gate.guard("read", resource_arg="path", exclude=("sink",))
        def read_report(path: str, sink) -> str:
            return "contents"

        assert read_report("/reports/q3.pdf", object()) == "contents"

    def test_defaults_are_bound_too(self, live_gate):
        """An argument left at its default still shapes what the call does."""
        seen = []

        @live_gate.guard("transfer", resource_arg="account", redeem=False)
        def transfer(account: str, amount_minor: int = 100) -> str:
            return "sent"

        original = live_gate.authorize

        def capture(action, resource, justification="", arguments=None):
            seen.append(arguments)
            return original(action, resource, justification, arguments)

        live_gate.authorize = capture
        transfer("/payments/outbound")
        live_gate.authorize = original

        assert seen[0] == {"amount_minor": 100}

    def test_a_denied_call_never_runs(self, permit_gate):
        """Out of scope: the decorator must stop the body, not merely log it."""
        ran = []

        @permit_gate.guard("read", resource_arg="path")
        def read_anything(path: str) -> str:
            ran.append(path)
            return "contents"

        from agentgate.exceptions import AgentGateDenied
        with pytest.raises(AgentGateDenied):
            read_anything("/hr/salaries.xlsx")
        assert ran == []
