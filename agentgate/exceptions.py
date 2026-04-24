class AgentGateDenied(Exception):
    """Raised when AgentGate returns a hard DENY decision."""
    def __init__(self, action: str, resource: str, explanation: str = ""):
        self.action = action
        self.resource = resource
        self.explanation = explanation
        super().__init__(f"AgentGate DENIED {action} on {resource}: {explanation}")


class AgentGateEscalated(Exception):
    """Raised when AgentGate returns ESCALATE and strict mode is on."""
    def __init__(self, action: str, resource: str, explanation: str = ""):
        self.action = action
        self.resource = resource
        self.explanation = explanation
        super().__init__(f"AgentGate ESCALATED {action} on {resource}: {explanation}")


class AgentGateNotRegistered(Exception):
    """Raised when .authorize() is called before .register()."""
    pass


class AgentGatePending(Exception):
    """Raised when PENDING and auto_resolve_pending=False — caller must poll manually."""
    def __init__(self, request_id: str, action: str, resource: str):
        self.request_id = request_id
        self.action = action
        self.resource = resource
        super().__init__(f"AgentGate PENDING human approval for {action} on {resource} (id={request_id})")


class AgentGateUnavailable(Exception):
    """Raised when the AgentGate server cannot be reached.

    The caller decides how to handle this — recommended pattern is fail-closed:

        try:
            gate.authorize("read", "/documents/report.pdf")
        except AgentGateUnavailable:
            raise PermissionError("Security layer unavailable — action denied")
    """
    def __init__(self, url: str, original: Exception):
        self.url = url
        self.original = original
        super().__init__(f"AgentGate server unreachable at {url}: {original}")
