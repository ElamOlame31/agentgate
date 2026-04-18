"""
AgentGate SDK — drop-in trust authorization for AI agents.

Quickstart (3 lines):

    from sdk import AgentGate

    gate = AgentGate("http://localhost:8000")
    gate.register("my_agent", "MyBot", "Summarize PDF reports", ["/reports/*"], ["read"])

    # Option A — explicit check before any tool call
    result = gate.authorize("read", "/reports/q3.pdf", justification="User requested")

    # Option B — decorator, raises AgentGateDenied automatically
    @gate.guard("read", resource_arg="path")
    def read_document(path: str) -> str:
        return open(path).read()

    # Option C — silent boolean check
    if gate.check("delete", "/confidential/salary.xlsx"):
        delete_file(...)
"""

import uuid
import httpx
from functools import wraps

from sdk.exceptions import AgentGateDenied, AgentGateEscalated, AgentGateNotRegistered


class AgentGate:
    """
    Client for the AgentGate Policy Decision Point.

    Args:
        url:               AgentGate server URL (e.g. "http://localhost:8000")
        raise_on_deny:     If True (default), .authorize() raises AgentGateDenied on DENY
        raise_on_escalate: If True, .authorize() raises AgentGateEscalated on ESCALATE
        timeout:           HTTP request timeout in seconds (default 10)
    """

    def __init__(
        self,
        url: str,
        raise_on_deny: bool = True,
        raise_on_escalate: bool = False,
        timeout: float = 30.0,
    ):
        self.url = url.rstrip("/")
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
    ) -> "AgentGate":
        """Register this agent with AgentGate and store the returned token.

        Returns self so calls can be chained.
        """
        payload: dict = {
            "agent_id": agent_id,
            "name": name,
            "declared_purpose": declared_purpose,
            "authorized_resources": authorized_resources,
            "authorized_actions": authorized_actions,
            "delegation_depth": delegation_depth,
        }
        if delegated_by:
            payload["delegated_by"] = delegated_by
        if scope_at_delegation:
            payload["scope_at_delegation"] = scope_at_delegation

        r = httpx.post(
            f"{self.url}/agents/register",
            json=payload,
            timeout=self.timeout,
        )
        r.raise_for_status()
        data = r.json()
        self._agent_id = agent_id
        self._token = data["token"]
        return self

    # ── Authorization ─────────────────────────────────────────────────────────

    def authorize(
        self,
        action: str,
        resource: str,
        justification: str = "",
    ) -> dict:
        """Request authorization from AgentGate before performing an action.

        Returns the full decision dict:
            {
                "decision": "PERMIT" | "ESCALATE" | "DENY",
                "trust_breakdown": { identity_score, delegation_score, ... },
                "explanation": "plain-English reason",
                "attack_flags": [...],
            }

        Raises:
            AgentGateNotRegistered: if called before .register()
            AgentGateDenied:        if decision is DENY (and raise_on_deny=True)
            AgentGateEscalated:     if decision is ESCALATE (and raise_on_escalate=True)
        """
        if not self._agent_id or not self._token:
            raise AgentGateNotRegistered(
                "Call gate.register(...) before gate.authorize()"
            )

        payload = {
            "agent_id": self._agent_id,
            "token": self._token,
            "action": action,
            "resource": resource,
            "justification": justification,
            "request_id": str(uuid.uuid4()),
        }

        r = httpx.post(
            f"{self.url}/authorize",
            json=payload,
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

    def check(self, action: str, resource: str, justification: str = "") -> bool:
        """Non-raising boolean check. Returns False on DENY, True otherwise."""
        try:
            result = self.authorize(action, resource, justification)
            return result["decision"] != "DENY"
        except AgentGateDenied:
            return False

    # ── Decorator ─────────────────────────────────────────────────────────────

    def guard(self, action: str, resource_arg: str = "resource"):
        """Decorator that calls authorize() before the wrapped function runs.

        Args:
            action:       The action to authorize (e.g. "read", "write", "delete")
            resource_arg: Name of the function argument that holds the resource path

        Example:
            @gate.guard("read", resource_arg="path")
            def read_file(path: str) -> str:
                return open(path).read()
        """
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                resource = kwargs.get(resource_arg)
                if resource is None and args:
                    resource = args[0]
                resource = str(resource) if resource is not None else "unknown"
                justification = kwargs.get("justification", f"Calling {func.__name__}")
                self.authorize(action, resource, justification)
                return func(*args, **kwargs)
            return wrapper
        return decorator

    # ── Context manager ───────────────────────────────────────────────────────

    def operation(self, action: str, resource: str, justification: str = ""):
        """Context manager — authorizes on enter, no-op on exit.

        with gate.operation("delete", "/confidential/salary.xlsx"):
            delete_file(...)
        """
        return _AuthorizedOperation(self, action, resource, justification)

    # ── Properties ────────────────────────────────────────────────────────────

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
