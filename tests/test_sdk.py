"""
SDK tests for AgentGate (sync) and AsyncAgentGate.

Uses httpx.MockTransport to avoid a running server.
"""
import asyncio
import json
import uuid
import pytest
import httpx

from agentgate import AgentGate, AsyncAgentGate
from agentgate.exceptions import (
    AgentGateDenied,
    AgentGateEscalated,
    AgentGateNotRegistered,
    AgentGatePending,
    AgentGateUnavailable,
)


# ── Mock transport helpers ────────────────────────────────────────────────────

def _json_response(data: dict, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=data)


class MockTransport(httpx.BaseTransport, httpx.AsyncBaseTransport):
    """Simple sync+async request router for tests."""

    def __init__(self, routes: dict):
        self._routes = routes  # key: (method, path_prefix)

    def _dispatch(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        method = request.method
        for (m, p), handler in self._routes.items():
            if m == method and path.startswith(p):
                return handler(request)
        return httpx.Response(404, json={"detail": "not found"})

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return self._dispatch(request)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await request.aread()
        return self._dispatch(request)


def _make_transport(routes: dict) -> MockTransport:
    return MockTransport(routes)


# ── Sync AgentGate fixtures ───────────────────────────────────────────────────

FAKE_TOKEN = "tok_abc123"
FAKE_AGENT_ID = "test_bot"


def _register_handler(request):
    return _json_response({"token": FAKE_TOKEN, "agent_id": FAKE_AGENT_ID})


def _sealed(request, decision: str) -> dict:
    """Build the sealed part of a response the way the real server does.

    A bare verdict is no longer a complete answer: guard() checks that the
    decision names the operation it is about to run, so a mock that omits
    action_ref would be testing against a server that no longer exists.
    """
    import time as _time
    from agentgate import action_ref as _ref

    body = json.loads(request.content or b"{}")
    ref = _ref.compute_action_ref(
        agent_id=body.get("agent_id", ""),
        action=body.get("action", ""),
        resource=body.get("resource", ""),
        arguments=body.get("arguments"),
    )
    return {
        "request_id": body.get("request_id", str(uuid.uuid4())),
        "agent_id": body.get("agent_id", ""),
        "action": body.get("action", ""),
        "resource": body.get("resource", ""),
        "decision": decision,
        "timestamp": _time.time(),
        "action_ref": ref,
        "response_nonce": str(uuid.uuid4()),
        "response_sig": "mock-signature",
    }


def _redeem_handler(request):
    return _json_response({"redeemed": True})


def _permit_handler(request):
    return _json_response({
        **_sealed(request, "PERMIT"),
        "explanation": "Within scope",
        "trust_breakdown": {},
        "attack_flags": [],
    })


def _deny_handler(request):
    return _json_response({
        "decision": "DENY",
        "explanation": "Out of scope",
        "trust_breakdown": {},
        "attack_flags": [],
    })


def _escalate_handler(request):
    return _json_response({
        "decision": "ESCALATE",
        "explanation": "Needs review",
        "trust_breakdown": {},
        "attack_flags": [],
    })


def _scan_clean_handler(request):
    return _json_response({"level": "clean", "confidence": 0.1, "evidence": "no injection"})


def _scan_injection_handler(request):
    return _json_response({"level": "injection", "confidence": 0.95, "evidence": "pattern match"})


def _make_sync_gate(routes: dict, **kwargs) -> AgentGate:
    transport = _make_transport(routes)
    gate = AgentGate("http://fake", **kwargs)
    gate._http = httpx.Client(transport=transport)
    return gate


# ── Helper: patch gate to use mock transport ──────────────────────────────────

def _patched_sync_gate(routes: dict, **kwargs) -> AgentGate:
    """
    Build an AgentGate that routes through MockTransport by monkeypatching
    the httpx.post / httpx.get calls at module level isn't practical,
    so we use a subclass that overrides internal requests.
    """
    transport = _make_transport(routes)
    client = httpx.Client(transport=transport)

    gate = AgentGate("http://fake", **kwargs)

    # Patch: intercept all httpx calls by swapping the internal method
    original_post = httpx.post
    original_get = httpx.get

    def fake_post(url, **kw):
        req = httpx.Request("POST", url, **{k: v for k, v in kw.items() if k in ("json", "headers")})
        req = client.build_request("POST", url, json=kw.get("json"), headers=kw.get("headers", {}))
        return client.send(req)

    def fake_get(url, **kw):
        req = client.build_request("GET", url, headers=kw.get("headers", {}))
        return client.send(req)

    import agentgate as _sdk
    _sdk.httpx.post = fake_post
    _sdk.httpx.get = fake_get

    return gate, client, original_post, original_get


# Simpler approach: use pytest monkeypatch on the module-level httpx calls

@pytest.fixture
def sync_routes():
    return {
        ("POST", "/agents/register"): _register_handler,
        ("POST", "/authorize"): _permit_handler,
        ("POST", "/receipts/redeem"): _redeem_handler,
        ("POST", "/scan"): _scan_clean_handler,
    }


@pytest.fixture
def registered_gate(monkeypatch, sync_routes):
    transport = _make_transport(sync_routes)
    client = httpx.Client(transport=transport)

    import agentgate as sdk_module

    monkeypatch.setattr(sdk_module.httpx, "post", lambda url, **kw: client.send(
        client.build_request("POST", url, json=kw.get("json"), headers=kw.get("headers", {}))
    ))
    monkeypatch.setattr(sdk_module.httpx, "get", lambda url, **kw: client.send(
        client.build_request("GET", url, headers=kw.get("headers", {}))
    ))

    gate = AgentGate("http://fake", raise_on_deny=True, raise_on_escalate=False)
    gate.register(FAKE_AGENT_ID, "TestBot", "Testing", ["/reports/*"], ["read"])
    return gate


# ── Sync tests ────────────────────────────────────────────────────────────────

class TestAgentGateSync:

    def test_register_stores_token_and_agent_id(self, monkeypatch):
        transport = _make_transport({("POST", "/agents/register"): _register_handler})
        client = httpx.Client(transport=transport)
        import agentgate as sdk
        monkeypatch.setattr(sdk.httpx, "post", lambda url, **kw: client.send(
            client.build_request("POST", url, json=kw.get("json"), headers=kw.get("headers", {}))
        ))
        gate = AgentGate("http://fake")
        result = gate.register("bot", "Bot", "Do stuff", ["/data/*"], ["read"])
        assert gate.agent_id == "bot"
        assert gate.token == FAKE_TOKEN
        assert result is gate  # returns self

    def test_register_raises_unavailable_on_connect_error(self, monkeypatch):
        import agentgate as sdk

        def raise_connect(*a, **kw):
            raise httpx.ConnectError("refused")

        monkeypatch.setattr(sdk.httpx, "post", raise_connect)
        gate = AgentGate("http://localhost:9")
        with pytest.raises(AgentGateUnavailable):
            gate.register("b", "B", "x", [], [])

    def test_authorize_not_registered_raises(self):
        gate = AgentGate("http://fake")
        with pytest.raises(AgentGateNotRegistered):
            gate.authorize("read", "/file.txt")

    def test_authorize_permit_returns_dict(self, registered_gate):
        result = registered_gate.authorize("read", "/reports/q3.pdf")
        assert result["decision"] == "PERMIT"

    def test_authorize_deny_raises_when_flag_set(self, monkeypatch):
        transport = _make_transport({
            ("POST", "/agents/register"): _register_handler,
            ("POST", "/authorize"): _deny_handler,
        })
        client = httpx.Client(transport=transport)
        import agentgate as sdk
        monkeypatch.setattr(sdk.httpx, "post", lambda url, **kw: client.send(
            client.build_request("POST", url, json=kw.get("json"), headers=kw.get("headers", {}))
        ))
        gate = AgentGate("http://fake", raise_on_deny=True)
        gate.register("bot", "B", "x", [], [])
        with pytest.raises(AgentGateDenied):
            gate.authorize("delete", "/secrets")

    def test_authorize_deny_returns_dict_when_flag_off(self, monkeypatch):
        transport = _make_transport({
            ("POST", "/agents/register"): _register_handler,
            ("POST", "/authorize"): _deny_handler,
        })
        client = httpx.Client(transport=transport)
        import agentgate as sdk
        monkeypatch.setattr(sdk.httpx, "post", lambda url, **kw: client.send(
            client.build_request("POST", url, json=kw.get("json"), headers=kw.get("headers", {}))
        ))
        gate = AgentGate("http://fake", raise_on_deny=False)
        gate.register("bot", "B", "x", [], [])
        result = gate.authorize("delete", "/secrets")
        assert result["decision"] == "DENY"

    def test_authorize_escalate_raises_when_flag_set(self, monkeypatch):
        transport = _make_transport({
            ("POST", "/agents/register"): _register_handler,
            ("POST", "/authorize"): _escalate_handler,
        })
        client = httpx.Client(transport=transport)
        import agentgate as sdk
        monkeypatch.setattr(sdk.httpx, "post", lambda url, **kw: client.send(
            client.build_request("POST", url, json=kw.get("json"), headers=kw.get("headers", {}))
        ))
        gate = AgentGate("http://fake", raise_on_deny=False, raise_on_escalate=True)
        gate.register("bot", "B", "x", [], [])
        with pytest.raises(AgentGateEscalated):
            gate.authorize("read", "/sensitive")

    def test_authorize_escalate_returns_dict_when_flag_off(self, registered_gate, monkeypatch):
        transport = _make_transport({
            ("POST", "/agents/register"): _register_handler,
            ("POST", "/authorize"): _escalate_handler,
        })
        client = httpx.Client(transport=transport)
        import agentgate as sdk
        monkeypatch.setattr(sdk.httpx, "post", lambda url, **kw: client.send(
            client.build_request("POST", url, json=kw.get("json"), headers=kw.get("headers", {}))
        ))
        gate = AgentGate("http://fake", raise_on_deny=False, raise_on_escalate=False)
        gate.register("bot", "B", "x", [], [])
        result = gate.authorize("read", "/sensitive")
        assert result["decision"] == "ESCALATE"

    def test_check_returns_true_on_permit(self, registered_gate):
        assert registered_gate.check("read", "/reports/q3.pdf") is True

    def test_check_returns_false_on_deny(self, monkeypatch):
        transport = _make_transport({
            ("POST", "/agents/register"): _register_handler,
            ("POST", "/authorize"): _deny_handler,
        })
        client = httpx.Client(transport=transport)
        import agentgate as sdk
        monkeypatch.setattr(sdk.httpx, "post", lambda url, **kw: client.send(
            client.build_request("POST", url, json=kw.get("json"), headers=kw.get("headers", {}))
        ))
        gate = AgentGate("http://fake", raise_on_deny=True)
        gate.register("bot", "B", "x", [], [])
        assert gate.check("delete", "/secrets") is False

    def test_scan_returns_clean(self, registered_gate):
        result = registered_gate.scan("This is a normal report summary.")
        assert result["level"] == "clean"

    def test_scan_not_registered_raises(self):
        gate = AgentGate("http://fake")
        with pytest.raises(AgentGateNotRegistered):
            gate.scan("hello")

    def test_guard_decorator_calls_authorize(self, registered_gate):
        calls = []

        @registered_gate.guard("read", resource_arg="path")
        def read_file(path: str) -> str:
            calls.append(path)
            return "content"

        result = read_file(path="/reports/q3.pdf")
        assert result == "content"
        assert len(calls) == 1

    def test_guard_decorator_raises_on_deny(self, monkeypatch):
        transport = _make_transport({
            ("POST", "/agents/register"): _register_handler,
            ("POST", "/authorize"): _deny_handler,
        })
        client = httpx.Client(transport=transport)
        import agentgate as sdk
        monkeypatch.setattr(sdk.httpx, "post", lambda url, **kw: client.send(
            client.build_request("POST", url, json=kw.get("json"), headers=kw.get("headers", {}))
        ))
        gate = AgentGate("http://fake", raise_on_deny=True)
        gate.register("bot", "B", "x", [], [])

        @gate.guard("write", resource_arg="path")
        def write_file(path: str) -> None:
            pass

        with pytest.raises(AgentGateDenied):
            write_file(path="/secrets/key.pem")

    def test_operation_context_manager_authorizes(self, registered_gate):
        ran = []
        with registered_gate.operation("read", "/reports/q3.pdf"):
            ran.append(True)
        assert ran == [True]

    def test_operation_context_manager_deny_raises(self, monkeypatch):
        transport = _make_transport({
            ("POST", "/agents/register"): _register_handler,
            ("POST", "/authorize"): _deny_handler,
        })
        client = httpx.Client(transport=transport)
        import agentgate as sdk
        monkeypatch.setattr(sdk.httpx, "post", lambda url, **kw: client.send(
            client.build_request("POST", url, json=kw.get("json"), headers=kw.get("headers", {}))
        ))
        gate = AgentGate("http://fake", raise_on_deny=True)
        gate.register("bot", "B", "x", [], [])
        with pytest.raises(AgentGateDenied):
            with gate.operation("delete", "/db/prod"):
                pass

    def test_pending_raises_when_auto_resolve_off(self, monkeypatch):
        req_id = str(uuid.uuid4())

        def pending_handler(request):
            return _json_response({
                "decision": "PENDING",
                "request_id": req_id,
                "explanation": "needs human",
                "trust_breakdown": {},
                "attack_flags": [],
            })

        transport = _make_transport({
            ("POST", "/agents/register"): _register_handler,
            ("POST", "/authorize"): pending_handler,
        })
        client = httpx.Client(transport=transport)
        import agentgate as sdk
        monkeypatch.setattr(sdk.httpx, "post", lambda url, **kw: client.send(
            client.build_request("POST", url, json=kw.get("json"), headers=kw.get("headers", {}))
        ))
        gate = AgentGate("http://fake", auto_resolve_pending=False)
        gate.register("bot", "B", "x", [], [])
        with pytest.raises(AgentGatePending):
            gate.authorize("delete", "/critical")

    def test_pending_auto_resolve_approved(self, monkeypatch):
        req_id = str(uuid.uuid4())
        call_count = {"n": 0}

        def pending_handler(request):
            return _json_response({
                "decision": "PENDING",
                "request_id": req_id,
                "explanation": "needs human",
                "trust_breakdown": {},
                "attack_flags": [],
            })

        def decision_handler(request):
            call_count["n"] += 1
            if call_count["n"] < 2:
                return _json_response({"status": "PENDING", "expires_at": 9999999999})
            return _json_response({"status": "APPROVED"})

        transport = _make_transport({
            ("POST", "/agents/register"): _register_handler,
            ("POST", "/authorize"): pending_handler,
            ("GET", "/decisions/"): decision_handler,
        })
        client = httpx.Client(transport=transport)
        import agentgate as sdk

        monkeypatch.setattr(sdk.httpx, "post", lambda url, **kw: client.send(
            client.build_request("POST", url, json=kw.get("json"), headers=kw.get("headers", {}))
        ))
        monkeypatch.setattr(sdk.httpx, "get", lambda url, **kw: client.send(
            client.build_request("GET", url, headers=kw.get("headers", {}))
        ))
        monkeypatch.setattr(sdk.time, "sleep", lambda _: None)

        gate = AgentGate("http://fake", auto_resolve_pending=True, raise_on_deny=True)
        gate.register("bot", "B", "x", [], [])
        result = gate.authorize("delete", "/critical")
        assert result["decision"] == "PERMIT"
        assert "HUMAN APPROVED" in result["explanation"]

    def test_pending_auto_resolve_denied(self, monkeypatch):
        req_id = str(uuid.uuid4())

        def pending_handler(request):
            return _json_response({
                "decision": "PENDING",
                "request_id": req_id,
                "explanation": "needs human",
                "trust_breakdown": {},
                "attack_flags": [],
            })

        def decision_handler(request):
            return _json_response({"status": "DENIED"})

        transport = _make_transport({
            ("POST", "/agents/register"): _register_handler,
            ("POST", "/authorize"): pending_handler,
            ("GET", "/decisions/"): decision_handler,
        })
        client = httpx.Client(transport=transport)
        import agentgate as sdk

        monkeypatch.setattr(sdk.httpx, "post", lambda url, **kw: client.send(
            client.build_request("POST", url, json=kw.get("json"), headers=kw.get("headers", {}))
        ))
        monkeypatch.setattr(sdk.httpx, "get", lambda url, **kw: client.send(
            client.build_request("GET", url, headers=kw.get("headers", {}))
        ))

        gate = AgentGate("http://fake", auto_resolve_pending=True, raise_on_deny=True)
        gate.register("bot", "B", "x", [], [])
        with pytest.raises(AgentGateDenied):
            gate.authorize("delete", "/critical")

    def test_api_key_sent_in_header(self, monkeypatch):
        captured = {}

        def capture_handler(request):
            captured["key"] = request.headers.get("x-api-key", "")
            return _json_response({"token": FAKE_TOKEN})

        transport = _make_transport({("POST", "/agents/register"): capture_handler})
        client = httpx.Client(transport=transport)
        import agentgate as sdk
        monkeypatch.setattr(sdk.httpx, "post", lambda url, **kw: client.send(
            client.build_request("POST", url, json=kw.get("json"), headers=kw.get("headers", {}))
        ))
        gate = AgentGate("http://fake", api_key="my-secret-key")
        gate.register("bot", "B", "x", [], [])
        assert captured["key"] == "my-secret-key"

    def test_no_api_key_sends_no_header(self, monkeypatch):
        captured = {}

        def capture_handler(request):
            captured["key"] = request.headers.get("x-api-key", None)
            return _json_response({"token": FAKE_TOKEN})

        transport = _make_transport({("POST", "/agents/register"): capture_handler})
        client = httpx.Client(transport=transport)
        import agentgate as sdk
        monkeypatch.setattr(sdk.httpx, "post", lambda url, **kw: client.send(
            client.build_request("POST", url, json=kw.get("json"), headers=kw.get("headers", {}))
        ))
        gate = AgentGate("http://fake")
        gate.register("bot", "B", "x", [], [])
        assert captured["key"] is None


# ── Async AgentGate tests ─────────────────────────────────────────────────────

def _make_async_client(routes: dict) -> httpx.AsyncClient:
    transport = _make_transport(routes)
    return httpx.AsyncClient(transport=transport)


@pytest.fixture
def async_routes():
    return {
        ("POST", "/agents/register"): _register_handler,
        ("POST", "/authorize"): _permit_handler,
        ("POST", "/receipts/redeem"): _redeem_handler,
        ("POST", "/scan"): _scan_clean_handler,
    }


@pytest.fixture
def async_client_fixture(async_routes):
    return _make_async_client(async_routes)


def _patch_async_client(monkeypatch, transport):
    """
    Monkeypatch httpx.AsyncClient so requests go through MockTransport.

    sdk.httpx IS the same module object as httpx, so we must capture the real
    class BEFORE patching to avoid an infinite recursion in the lambda.
    All kwargs (headers, timeout, etc.) are forwarded so the gate's config is preserved.
    """
    import agentgate as sdk
    _Real = httpx.AsyncClient  # capture before patch

    def _factory(**kw):
        return _Real(transport=transport, **kw)

    monkeypatch.setattr(sdk.httpx, "AsyncClient", _factory)


class TestAsyncAgentGate:

    @pytest.mark.asyncio
    async def test_register_stores_token_and_agent_id(self, monkeypatch):
        transport = _make_transport({("POST", "/agents/register"): _register_handler})
        _patch_async_client(monkeypatch, transport)

        gate = AsyncAgentGate("http://fake")
        result = await gate.register("bot", "Bot", "Do stuff", ["/data/*"], ["read"])
        assert gate.agent_id == "bot"
        assert gate.token == FAKE_TOKEN
        assert result is gate

    @pytest.mark.asyncio
    async def test_authorize_permit_returns_dict(self, monkeypatch):
        transport = _make_transport({
            ("POST", "/agents/register"): _register_handler,
            ("POST", "/authorize"): _permit_handler,
            ("POST", "/receipts/redeem"): _redeem_handler,
        })
        _patch_async_client(monkeypatch, transport)

        gate = AsyncAgentGate("http://fake")
        await gate.register("bot", "B", "x", [], [])
        result = await gate.authorize("read", "/reports/q3.pdf")
        assert result["decision"] == "PERMIT"

    @pytest.mark.asyncio
    async def test_authorize_not_registered_raises(self):
        gate = AsyncAgentGate("http://fake")
        with pytest.raises(AgentGateNotRegistered):
            await gate.authorize("read", "/file.txt")

    @pytest.mark.asyncio
    async def test_authorize_deny_raises_when_flag_set(self, monkeypatch):
        transport = _make_transport({
            ("POST", "/agents/register"): _register_handler,
            ("POST", "/authorize"): _deny_handler,
        })
        _patch_async_client(monkeypatch, transport)

        gate = AsyncAgentGate("http://fake", raise_on_deny=True)
        await gate.register("bot", "B", "x", [], [])
        with pytest.raises(AgentGateDenied):
            await gate.authorize("delete", "/secrets")

    @pytest.mark.asyncio
    async def test_authorize_deny_returns_dict_when_flag_off(self, monkeypatch):
        transport = _make_transport({
            ("POST", "/agents/register"): _register_handler,
            ("POST", "/authorize"): _deny_handler,
        })
        _patch_async_client(monkeypatch, transport)

        gate = AsyncAgentGate("http://fake", raise_on_deny=False)
        await gate.register("bot", "B", "x", [], [])
        result = await gate.authorize("delete", "/secrets")
        assert result["decision"] == "DENY"

    @pytest.mark.asyncio
    async def test_check_returns_true_on_permit(self, monkeypatch):
        transport = _make_transport({
            ("POST", "/agents/register"): _register_handler,
            ("POST", "/authorize"): _permit_handler,
            ("POST", "/receipts/redeem"): _redeem_handler,
        })
        _patch_async_client(monkeypatch, transport)

        gate = AsyncAgentGate("http://fake")
        await gate.register("bot", "B", "x", [], [])
        assert await gate.check("read", "/reports/q3.pdf") is True

    @pytest.mark.asyncio
    async def test_check_returns_false_on_deny(self, monkeypatch):
        transport = _make_transport({
            ("POST", "/agents/register"): _register_handler,
            ("POST", "/authorize"): _deny_handler,
        })
        _patch_async_client(monkeypatch, transport)

        gate = AsyncAgentGate("http://fake", raise_on_deny=True)
        await gate.register("bot", "B", "x", [], [])
        assert await gate.check("delete", "/secrets") is False

    @pytest.mark.asyncio
    async def test_scan_returns_clean(self, monkeypatch):
        transport = _make_transport({
            ("POST", "/agents/register"): _register_handler,
            ("POST", "/scan"): _scan_clean_handler,
        })
        _patch_async_client(monkeypatch, transport)

        gate = AsyncAgentGate("http://fake")
        await gate.register("bot", "B", "x", [], [])
        result = await gate.scan("Normal report content.")
        assert result["level"] == "clean"

    @pytest.mark.asyncio
    async def test_scan_not_registered_raises(self):
        gate = AsyncAgentGate("http://fake")
        with pytest.raises(AgentGateNotRegistered):
            await gate.scan("hello")

    @pytest.mark.asyncio
    async def test_guard_decorator_wraps_async_function(self, monkeypatch):
        transport = _make_transport({
            ("POST", "/agents/register"): _register_handler,
            ("POST", "/authorize"): _permit_handler,
            ("POST", "/receipts/redeem"): _redeem_handler,
        })
        _patch_async_client(monkeypatch, transport)

        gate = AsyncAgentGate("http://fake")
        await gate.register("bot", "B", "x", [], [])
        calls = []

        @gate.guard("read", resource_arg="path")
        async def read_file(path: str) -> str:
            calls.append(path)
            return "content"

        result = await read_file(path="/reports/q3.pdf")
        assert result == "content"
        assert len(calls) == 1

    @pytest.mark.asyncio
    async def test_guard_decorator_raises_on_deny(self, monkeypatch):
        transport = _make_transport({
            ("POST", "/agents/register"): _register_handler,
            ("POST", "/authorize"): _deny_handler,
        })
        _patch_async_client(monkeypatch, transport)

        gate = AsyncAgentGate("http://fake", raise_on_deny=True)
        await gate.register("bot", "B", "x", [], [])

        @gate.guard("write", resource_arg="path")
        async def write_file(path: str) -> None:
            pass

        with pytest.raises(AgentGateDenied):
            await write_file(path="/secrets/key.pem")

    @pytest.mark.asyncio
    async def test_operation_async_context_manager(self, monkeypatch):
        transport = _make_transport({
            ("POST", "/agents/register"): _register_handler,
            ("POST", "/authorize"): _permit_handler,
            ("POST", "/receipts/redeem"): _redeem_handler,
        })
        _patch_async_client(monkeypatch, transport)

        gate = AsyncAgentGate("http://fake")
        await gate.register("bot", "B", "x", [], [])
        ran = []
        async with gate.operation("read", "/reports/q3.pdf"):
            ran.append(True)
        assert ran == [True]

    @pytest.mark.asyncio
    async def test_operation_deny_raises(self, monkeypatch):
        transport = _make_transport({
            ("POST", "/agents/register"): _register_handler,
            ("POST", "/authorize"): _deny_handler,
        })
        _patch_async_client(monkeypatch, transport)

        gate = AsyncAgentGate("http://fake", raise_on_deny=True)
        await gate.register("bot", "B", "x", [], [])
        with pytest.raises(AgentGateDenied):
            async with gate.operation("delete", "/db/prod"):
                pass

    @pytest.mark.asyncio
    async def test_pending_raises_when_auto_resolve_off(self, monkeypatch):
        req_id = str(uuid.uuid4())

        def pending_handler(request):
            return _json_response({
                "decision": "PENDING",
                "request_id": req_id,
                "explanation": "needs human",
                "trust_breakdown": {},
                "attack_flags": [],
            })

        transport = _make_transport({
            ("POST", "/agents/register"): _register_handler,
            ("POST", "/authorize"): pending_handler,
        })
        _patch_async_client(monkeypatch, transport)

        gate = AsyncAgentGate("http://fake", auto_resolve_pending=False)
        await gate.register("bot", "B", "x", [], [])
        with pytest.raises(AgentGatePending):
            await gate.authorize("delete", "/critical")

    @pytest.mark.asyncio
    async def test_pending_auto_resolve_approved(self, monkeypatch):
        req_id = str(uuid.uuid4())
        call_count = {"n": 0}

        def pending_handler(request):
            return _json_response({
                "decision": "PENDING",
                "request_id": req_id,
                "explanation": "needs human",
                "trust_breakdown": {},
                "attack_flags": [],
            })

        def decision_handler(request):
            call_count["n"] += 1
            if call_count["n"] < 2:
                return _json_response({"status": "PENDING", "expires_at": 9999999999})
            return _json_response({"status": "APPROVED"})

        transport = _make_transport({
            ("POST", "/agents/register"): _register_handler,
            ("POST", "/authorize"): pending_handler,
            ("GET", "/decisions/"): decision_handler,
        })
        _patch_async_client(monkeypatch, transport)

        import agentgate as sdk

        async def fake_sleep(_):
            pass

        monkeypatch.setattr(sdk.asyncio, "sleep", fake_sleep)

        gate = AsyncAgentGate("http://fake", auto_resolve_pending=True, raise_on_deny=True)
        await gate.register("bot", "B", "x", [], [])
        result = await gate.authorize("delete", "/critical")
        assert result["decision"] == "PERMIT"
        assert "HUMAN APPROVED" in result["explanation"]

    @pytest.mark.asyncio
    async def test_unavailable_raises_on_connect_error(self, monkeypatch):
        class FailTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request):
                raise httpx.ConnectError("refused")

        import agentgate as sdk
        _Real = httpx.AsyncClient

        def _fail_factory(**kw):
            return _Real(transport=FailTransport())

        monkeypatch.setattr(sdk.httpx, "AsyncClient", _fail_factory)
        gate = AsyncAgentGate("http://localhost:9")
        with pytest.raises(AgentGateUnavailable):
            await gate.register("b", "B", "x", [], [])

    @pytest.mark.asyncio
    async def test_api_key_sent_in_header(self, monkeypatch):
        captured = {}

        def capture_handler(request):
            captured["key"] = request.headers.get("x-api-key", "")
            return _json_response({"token": FAKE_TOKEN})

        transport = _make_transport({("POST", "/agents/register"): capture_handler})
        _patch_async_client(monkeypatch, transport)

        gate = AsyncAgentGate("http://fake", api_key="my-secret-key")
        await gate.register("bot", "B", "x", [], [])
        assert captured["key"] == "my-secret-key"
