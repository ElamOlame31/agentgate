"""
AgentGate SDK — drop-in trust authorization for AI agents.

Sync quickstart:

    from agentgate import AgentGate

    gate = AgentGate("http://localhost:8000", api_key="your-key")
    gate.register("my_bot", "ReportBot", "Summarize reports",
                  authorized_resources=["/reports/*"],
                  authorized_actions=["read"])

    result = gate.authorize("read", "/reports/q3.pdf")
    # result["decision"] -> "PERMIT" | "ESCALATE" | "DENY"

    @gate.guard("read", resource_arg="path")
    def read_document(path: str) -> str:
        return open(path).read()

    scan = gate.scan(email_body)
    if scan["level"] == "injection":
        raise ValueError("Injection detected")

Async quickstart (LangGraph, CrewAI, Autogen):

    from agentgate import AsyncAgentGate

    gate = AsyncAgentGate("http://localhost:8000", api_key="your-key")
    await gate.register("my_bot", "ReportBot", "Summarize reports",
                        authorized_resources=["/reports/*"],
                        authorized_actions=["read"])

    result = await gate.authorize("read", "/reports/q3.pdf")

    @gate.guard("read", resource_arg="path")
    async def read_document(path: str) -> str:
        return open(path).read()
"""

__version__ = "0.2.1"

import asyncio
import time
import uuid
import httpx
from functools import wraps

from agentgate.exceptions import (
    AgentGateDenied, AgentGateEscalated, AgentGateNotRegistered,
    AgentGatePending, AgentGateUnavailable,
)


class AgentGate:
    """
    Client for the AgentGate Policy Decision Point.

    Args:
        url:                  AgentGate server URL (e.g. "http://localhost:8000")
        api_key:              API key for the AgentGate server
        raise_on_deny:        If True (default), .authorize() raises AgentGateDenied on DENY
        raise_on_escalate:    If True, .authorize() raises AgentGateEscalated on ESCALATE
        auto_resolve_pending: If True (default), .authorize() blocks and polls until a human
                              approves or denies. If False, returns the raw PENDING response
                              immediately — caller is responsible for polling.
        pending_timeout:      Seconds to wait for human approval (default 95, server auto-denies at 90)
        timeout:              HTTP request timeout in seconds (default 30)
    """

    def __init__(
        self,
        url: str,
        api_key: str = "",
        raise_on_deny: bool = True,
        raise_on_escalate: bool = False,
        auto_resolve_pending: bool = True,
        pending_timeout: int = 95,
        timeout: float = 30.0,
    ):
        self.url = url.rstrip("/")
        self._headers = {"X-API-Key": api_key} if api_key else {}
        self.raise_on_deny = raise_on_deny
        self.raise_on_escalate = raise_on_escalate
        self.auto_resolve_pending = auto_resolve_pending
        self.pending_timeout = pending_timeout
        self.timeout = timeout
        self._agent_id: str | None = None
        self._token: str | None = None

    # ── Registration ──────────────────────────────────────────────────────────

    def register(
        self,
        agent_id: str,
        name: str,
        declared_purpose: str,
        authorized_resources: list[str],
        authorized_actions: list[str],
        delegation_depth: int = 0,
        delegated_by: str | None = None,
        scope_at_delegation: list[str] | None = None,
        processes_external_content: bool = False,
        requires_human_approval: bool = False,
    ) -> "AgentGate":
        """Register this agent with AgentGate. Returns self for chaining."""
        payload: dict = {
            "agent_id": agent_id,
            "name": name,
            "declared_purpose": declared_purpose,
            "authorized_resources": authorized_resources,
            "authorized_actions": authorized_actions,
            "delegation_depth": delegation_depth,
            "processes_external_content": processes_external_content,
            "requires_human_approval": requires_human_approval,
        }
        if delegated_by:
            payload["delegated_by"] = delegated_by
        if scope_at_delegation:
            payload["scope_at_delegation"] = scope_at_delegation

        try:
            r = httpx.post(
                f"{self.url}/agents/register",
                json=payload,
                headers=self._headers,
                timeout=self.timeout,
            )
            r.raise_for_status()
        except (httpx.ConnectError, httpx.TimeoutException, httpx.ConnectTimeout) as e:
            raise AgentGateUnavailable(self.url, e)
        self._agent_id = agent_id
        self._token = r.json()["token"]
        return self

    # ── Authorization ─────────────────────────────────────────────────────────

    def authorize(self, action: str, resource: str, justification: str = "") -> dict:
        """
        Request authorization before performing an action.

        Returns dict with decision, trust_breakdown, explanation, attack_flags.

        PENDING decisions are handled automatically when auto_resolve_pending=True:
        the call blocks until a human approves/denies or the timeout fires.

        Raises AgentGateDenied on DENY (if raise_on_deny=True).
        Raises AgentGateEscalated on ESCALATE (if raise_on_escalate=True).
        Raises AgentGatePending on PENDING (only if auto_resolve_pending=False).
        """
        if not self._agent_id or not self._token:
            raise AgentGateNotRegistered("Call gate.register(...) before gate.authorize()")

        try:
            r = httpx.post(
                f"{self.url}/authorize",
                headers=self._headers,
                json={
                    "agent_id": self._agent_id,
                    "token": self._token,
                    "action": action,
                    "resource": resource,
                    "justification": justification,
                    "request_id": str(uuid.uuid4()),
                },
                timeout=self.timeout,
            )
            r.raise_for_status()
        except (httpx.ConnectError, httpx.TimeoutException, httpx.ConnectTimeout) as e:
            raise AgentGateUnavailable(self.url, e)
        result = r.json()
        decision = result["decision"]

        if decision == "PENDING":
            if not self.auto_resolve_pending:
                raise AgentGatePending(result.get("request_id", ""), action, resource)
            # Block until human decides or timeout
            request_id = result.get("request_id", "")
            human_decision = self._wait_for_human(request_id)
            # Synthesize a final result so callers see PERMIT or DENY
            result = dict(result)
            result["decision"] = "PERMIT" if human_decision == "APPROVED" else "DENY"
            result["explanation"] = (
                f"[HUMAN {'APPROVED' if human_decision == 'APPROVED' else 'DENIED'}] "
                + result.get("explanation", "")
            )
            decision = result["decision"]

        if decision == "DENY" and self.raise_on_deny:
            raise AgentGateDenied(action, resource, result.get("explanation", ""))
        if decision == "ESCALATE" and self.raise_on_escalate:
            raise AgentGateEscalated(action, resource, result.get("explanation", ""))

        return result

    def _wait_for_human(self, request_id: str) -> str:
        """
        Poll /decisions/{id} every 2s until resolved or timeout.
        Returns 'APPROVED' or 'DENIED'.
        """
        deadline = time.time() + self.pending_timeout
        print(f"[AgentGate] Waiting for human approval ({self.pending_timeout}s timeout)...")
        while time.time() < deadline:
            try:
                r = httpx.get(
                    f"{self.url}/decisions/{request_id}",
                    headers=self._headers,
                    timeout=5.0,
                )
                if r.status_code == 200:
                    data = r.json()
                    status = data.get("status", "PENDING")
                    if status in ("APPROVED", "DENIED"):
                        print(f"[AgentGate] Human decision: {status}")
                        return status
                    remaining = max(0, int(data.get("expires_at", 0) - time.time()))
                    print(f"[AgentGate] Still pending... {remaining}s remaining", end="\r")
            except Exception:
                pass
            time.sleep(2)
        print("[AgentGate] Timeout — auto-denied")
        return "DENIED"

    # ── Content scan ──────────────────────────────────────────────────────────

    def scan(self, content: str) -> dict:
        """
        Scan document/email content for prompt injection before processing.
        Returns dict with level ("clean"/"suspicious"/"injection"), confidence, evidence.
        """
        if not self._agent_id:
            raise AgentGateNotRegistered("Call gate.register(...) before gate.scan()")

        try:
            r = httpx.post(
                f"{self.url}/scan",
                headers=self._headers,
                json={"agent_id": self._agent_id, "content": content},
                timeout=self.timeout,
            )
            r.raise_for_status()
        except (httpx.ConnectError, httpx.TimeoutException, httpx.ConnectTimeout) as e:
            raise AgentGateUnavailable(self.url, e)
        return r.json()

    # ── Helpers ───────────────────────────────────────────────────────────────

    def check(self, action: str, resource: str, justification: str = "") -> bool:
        """Non-raising boolean check. Returns False on DENY, True otherwise."""
        try:
            result = self.authorize(action, resource, justification)
            return result["decision"] != "DENY"
        except AgentGateDenied:
            return False

    def guard(self, action: str, resource_arg: str = "resource"):
        """
        Decorator — authorizes before the wrapped function runs.

        @gate.guard("read", resource_arg="path")
        def read_file(path: str) -> str:
            return open(path).read()
        """
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                resource = kwargs.get(resource_arg) or (args[0] if args else "unknown")
                self.authorize(action, str(resource), f"Calling {func.__name__}")
                return func(*args, **kwargs)
            return wrapper
        return decorator

    def operation(self, action: str, resource: str, justification: str = ""):
        """
        Context manager — authorizes on enter.

        with gate.operation("delete", "/confidential/salary.xlsx"):
            delete_file(...)
        """
        return _AuthorizedOperation(self, action, resource, justification)

    @property
    def agent_id(self) -> str | None:
        return self._agent_id

    @property
    def token(self) -> str | None:
        return self._token


class _AuthorizedOperation:
    def __init__(self, gate: AgentGate, action: str, resource: str, justification: str):
        self._gate = gate
        self._action = action
        self._resource = resource
        self._justification = justification

    def __enter__(self):
        self._gate.authorize(self._action, self._resource, self._justification)
        return self

    def __exit__(self, *_):
        pass


class AsyncAgentGate:
    """
    Async client for the AgentGate Policy Decision Point.

    Designed for async-native agentic frameworks: LangGraph, CrewAI, Autogen.

    Args:
        url:                  AgentGate server URL (e.g. "http://localhost:8000")
        api_key:              API key for the AgentGate server
        raise_on_deny:        If True (default), .authorize() raises AgentGateDenied on DENY
        raise_on_escalate:    If True, .authorize() raises AgentGateEscalated on ESCALATE
        auto_resolve_pending: If True (default), .authorize() awaits human approval
        pending_timeout:      Seconds to wait for human approval (default 95)
        timeout:              HTTP request timeout in seconds (default 30)
    """

    def __init__(
        self,
        url: str,
        api_key: str = "",
        raise_on_deny: bool = True,
        raise_on_escalate: bool = False,
        auto_resolve_pending: bool = True,
        pending_timeout: int = 95,
        timeout: float = 30.0,
    ):
        self.url = url.rstrip("/")
        self._headers = {"X-API-Key": api_key} if api_key else {}
        self.raise_on_deny = raise_on_deny
        self.raise_on_escalate = raise_on_escalate
        self.auto_resolve_pending = auto_resolve_pending
        self.pending_timeout = pending_timeout
        self.timeout = timeout
        self._agent_id: str | None = None
        self._token: str | None = None

    # ── Registration ──────────────────────────────────────────────────────────

    async def register(
        self,
        agent_id: str,
        name: str,
        declared_purpose: str,
        authorized_resources: list[str],
        authorized_actions: list[str],
        delegation_depth: int = 0,
        delegated_by: str | None = None,
        scope_at_delegation: list[str] | None = None,
        processes_external_content: bool = False,
        requires_human_approval: bool = False,
    ) -> "AsyncAgentGate":
        """Register this agent with AgentGate. Returns self for chaining."""
        payload: dict = {
            "agent_id": agent_id,
            "name": name,
            "declared_purpose": declared_purpose,
            "authorized_resources": authorized_resources,
            "authorized_actions": authorized_actions,
            "delegation_depth": delegation_depth,
            "processes_external_content": processes_external_content,
            "requires_human_approval": requires_human_approval,
        }
        if delegated_by:
            payload["delegated_by"] = delegated_by
        if scope_at_delegation:
            payload["scope_at_delegation"] = scope_at_delegation

        try:
            async with httpx.AsyncClient(headers=self._headers, timeout=self.timeout) as client:
                r = await client.post(f"{self.url}/agents/register", json=payload)
                r.raise_for_status()
        except (httpx.ConnectError, httpx.TimeoutException, httpx.ConnectTimeout) as e:
            raise AgentGateUnavailable(self.url, e)
        self._agent_id = agent_id
        self._token = r.json()["token"]
        return self

    # ── Authorization ─────────────────────────────────────────────────────────

    async def authorize(self, action: str, resource: str, justification: str = "") -> dict:
        """
        Request authorization before performing an action.

        Returns dict with decision, trust_breakdown, explanation, attack_flags.

        PENDING decisions are handled automatically when auto_resolve_pending=True:
        the call awaits until a human approves/denies or the timeout fires.

        Raises AgentGateDenied on DENY (if raise_on_deny=True).
        Raises AgentGateEscalated on ESCALATE (if raise_on_escalate=True).
        Raises AgentGatePending on PENDING (only if auto_resolve_pending=False).
        """
        if not self._agent_id or not self._token:
            raise AgentGateNotRegistered("Call await gate.register(...) before gate.authorize()")

        try:
            async with httpx.AsyncClient(headers=self._headers, timeout=self.timeout) as client:
                r = await client.post(
                    f"{self.url}/authorize",
                    json={
                        "agent_id": self._agent_id,
                        "token": self._token,
                        "action": action,
                        "resource": resource,
                        "justification": justification,
                        "request_id": str(uuid.uuid4()),
                    },
                )
                r.raise_for_status()
        except (httpx.ConnectError, httpx.TimeoutException, httpx.ConnectTimeout) as e:
            raise AgentGateUnavailable(self.url, e)

        result = r.json()
        decision = result["decision"]

        if decision == "PENDING":
            if not self.auto_resolve_pending:
                raise AgentGatePending(result.get("request_id", ""), action, resource)
            request_id = result.get("request_id", "")
            human_decision = await self._wait_for_human(request_id)
            result = dict(result)
            result["decision"] = "PERMIT" if human_decision == "APPROVED" else "DENY"
            result["explanation"] = (
                f"[HUMAN {'APPROVED' if human_decision == 'APPROVED' else 'DENIED'}] "
                + result.get("explanation", "")
            )
            decision = result["decision"]

        if decision == "DENY" and self.raise_on_deny:
            raise AgentGateDenied(action, resource, result.get("explanation", ""))
        if decision == "ESCALATE" and self.raise_on_escalate:
            raise AgentGateEscalated(action, resource, result.get("explanation", ""))

        return result

    async def _wait_for_human(self, request_id: str) -> str:
        """
        Poll /decisions/{id} every 2s until resolved or timeout.
        Returns 'APPROVED' or 'DENIED'.
        """
        deadline = time.time() + self.pending_timeout
        print(f"[AgentGate] Waiting for human approval ({self.pending_timeout}s timeout)...")
        async with httpx.AsyncClient(headers=self._headers, timeout=5.0) as client:
            while time.time() < deadline:
                try:
                    r = await client.get(f"{self.url}/decisions/{request_id}")
                    if r.status_code == 200:
                        data = r.json()
                        status = data.get("status", "PENDING")
                        if status in ("APPROVED", "DENIED"):
                            print(f"[AgentGate] Human decision: {status}")
                            return status
                        remaining = max(0, int(data.get("expires_at", 0) - time.time()))
                        print(f"[AgentGate] Still pending... {remaining}s remaining", end="\r")
                except Exception:
                    pass
                await asyncio.sleep(2)
        print("[AgentGate] Timeout — auto-denied")
        return "DENIED"

    # ── Content scan ──────────────────────────────────────────────────────────

    async def scan(self, content: str) -> dict:
        """
        Scan document/email content for prompt injection before processing.
        Returns dict with level ("clean"/"suspicious"/"injection"), confidence, evidence.
        """
        if not self._agent_id:
            raise AgentGateNotRegistered("Call await gate.register(...) before gate.scan()")

        try:
            async with httpx.AsyncClient(headers=self._headers, timeout=self.timeout) as client:
                r = await client.post(
                    f"{self.url}/scan",
                    json={"agent_id": self._agent_id, "content": content},
                )
                r.raise_for_status()
        except (httpx.ConnectError, httpx.TimeoutException, httpx.ConnectTimeout) as e:
            raise AgentGateUnavailable(self.url, e)
        return r.json()

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def check(self, action: str, resource: str, justification: str = "") -> bool:
        """Non-raising boolean check. Returns False on DENY, True otherwise."""
        try:
            result = await self.authorize(action, resource, justification)
            return result["decision"] != "DENY"
        except AgentGateDenied:
            return False

    def guard(self, action: str, resource_arg: str = "resource"):
        """
        Decorator — authorizes before the wrapped async function runs.

        @gate.guard("read", resource_arg="path")
        async def read_file(path: str) -> str:
            return open(path).read()
        """
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                resource = kwargs.get(resource_arg) or (args[0] if args else "unknown")
                await self.authorize(action, str(resource), f"Calling {func.__name__}")
                return await func(*args, **kwargs)
            return wrapper
        return decorator

    def operation(self, action: str, resource: str, justification: str = ""):
        """
        Async context manager — authorizes on enter.

        async with gate.operation("delete", "/confidential/salary.xlsx"):
            await delete_file(...)
        """
        return _AsyncAuthorizedOperation(self, action, resource, justification)

    @property
    def agent_id(self) -> str | None:
        return self._agent_id

    @property
    def token(self) -> str | None:
        return self._token


class _AsyncAuthorizedOperation:
    def __init__(self, gate: AsyncAgentGate, action: str, resource: str, justification: str):
        self._gate = gate
        self._action = action
        self._resource = resource
        self._justification = justification

    async def __aenter__(self):
        await self._gate.authorize(self._action, self._resource, self._justification)
        return self

    async def __aexit__(self, *_):
        pass
