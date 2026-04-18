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
