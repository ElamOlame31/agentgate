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


class AgentGateBindingError(Exception):
    """Raised when the operation about to run is not the one that was authorized.

    The decision named a specific operation — this agent, this action, this
    resource, these arguments. Something changed between the decision and the
    dispatch, so the decision does not cover what is about to happen and the
    call must not proceed on the strength of it.

    This is the Loopjacking failure caught at the point it would have mattered.
    """
    def __init__(self, action: str, resource: str, expected: str, actual: str):
        self.action = action
        self.resource = resource
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"AgentGate binding mismatch on {action} {resource}: "
            f"authorized {expected[:16]}..., about to run {actual[:16]}.... "
            "The operation changed after it was authorized."
        )


class AgentGateReceiptError(Exception):
    """Raised when a receipt could not be spent.

    Common reasons: RECEIPT_ALREADY_SPENT (this authorization has been used),
    SIGNATURE_MISMATCH (forged or altered), RESPONSE_EXPIRED (too old to honour).
    """
    def __init__(self, reason: str, action: str = "", resource: str = ""):
        self.reason = reason
        self.action = action
        self.resource = resource
        super().__init__(f"AgentGate refused the receipt for {action} {resource}: {reason}")


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
