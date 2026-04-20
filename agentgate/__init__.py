"""
AgentGate SDK — drop-in trust authorization for AI agents.

Quickstart:

    from agentgate import AgentGate

    gate = AgentGate("http://localhost:8000")
    gate.register("my_agent", "MyBot", "Summarize PDF reports", ["/reports/*"], ["read"])

    # Authorize before any action
    result = gate.authorize("read", "/reports/q3.pdf")

    # Decorator style
    @gate.guard("read", resource_arg="path")
    def read_document(path: str) -> str:
        return open(path).read()

    # Scan for prompt injection
    scan = gate.scan(email_body)
    if scan["level"] == "injection":
        raise ValueError("Injection detected — content blocked")
"""

import uuid
import httpx
from functools import wraps

from agentgate.exceptions import AgentGateDenied, AgentGateEscalated, AgentGateNotRegistered


class AgentGate:
    """
    Client for the AgentGate Policy Decision Point.

    Args:
        url:               AgentGate server URL (e.g. "http://localhost:8000")
        raise_on_deny:     If True (default), .authorize() raises AgentGateDenied on DENY
        raise_on_escalate: If True, .authorize() raises AgentGateEscalated on ESCALATE
        timeout:           HTTP request timeout in seconds (default 30)
    """

    def __init__(
        self,
        url: str,
        api_key: str = "",
        raise_on_deny: bool = True,
        raise_on_escalate: bool = False,
        timeout: float = 30.0,
    ):
        self.url = url.rstrip("/")
        self._headers = {"X-API-Key": api_key} if api_key else {}
        self.raise_on_deny = raise_on_deny
        self.raise_on_escalate = raise_on_escalate
        self.timeout = timeout
        self._agent_id: str | None = None
        self._token: str | None = None

    # ── Registration ─────────────────────────────────────────────────────────

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
        }
        if delegated_by:
            payload["delegated_by"] = delegated_by
        if scope_at_delegation:
            payload["scope_at_delegation"] = scope_at_delegation

        r = httpx.post(f"{self.url}/agents/register", json=payload, headers=self._headers, timeout=self.timeout)
        r.raise_for_status()
        self._agent_id = agent_id
        self._token = r.json()["token"]
        return self

    # ── Authorization ─────────────────────────────────────────────────────────

    def authorize(self, action: str, resource: str, justification: str = "") -> dict:
        """Request authorization before performing an action.

        Returns dict with decision, trust_breakdown, explanation, attack_flags.
        Raises AgentGateDenied on DENY (if raise_on_deny=True).
        """
        if not self._agent_id or not self._token:
            raise AgentGateNotRegistered("Call gate.register(...) before gate.authorize()")

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
        result = r.json()
        decision = result["decision"]

        if decision == "DENY" and self.raise_on_deny:
            raise AgentGateDenied(action, resource, result.get("explanation", ""))
        if decision == "ESCALATE" and self.raise_on_escalate:
            raise AgentGateEscalated(action, resource, result.get("explanation", ""))

        return result

    # ── Content scan ──────────────────────────────────────────────────────────

    def scan(self, content: str) -> dict:
        """Scan document/email content for prompt injection before processing.

        Returns dict with level ("clean"/"suspicious"/"injection"), confidence, evidence.
        """
        if not self._agent_id:
            raise AgentGateNotRegistered("Call gate.register(...) before gate.scan()")

        r = httpx.post(
            f"{self.url}/scan",
            headers=self._headers,
            json={"agent_id": self._agent_id, "content": content},
            timeout=self.timeout,
        )
        r.raise_for_status()
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
        """Decorator — authorizes before the wrapped function runs.

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
        """Context manager — authorizes on enter.

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
