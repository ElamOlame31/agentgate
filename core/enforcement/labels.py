"""
Information-flow labels for agent sessions.

The question a policy engine answers is "may this action run". The question
that actually stops exfiltration is "may this *data* reach this destination".
CaMeL (Google, SaTML 2026) and FIDES (Microsoft) answer the second with
information-flow control: every value carries a confidentiality and an
integrity label, labels propagate through the computation, and a sink is
refused when the flow would violate the lattice.

Both do it from inside the agent — CaMeL with its own interpreter, FIDES as
middleware in Agent Framework. AgentGate sits outside, reached over HTTP, and
never sees the agent's variables. Value-level tracking is therefore not
available to us, and claiming it would be a lie.

What is available is the session. AgentGate already mediates every read, so it
knows what an agent has been exposed to before it attempts a sink. That gives a
*watermark*: the join of everything read in the session window. It is a
conservative over-approximation — an agent that read a salary file and then
sends an unrelated public message is refused, because from outside we cannot
prove the two are unrelated. Over-approximation is what information-flow
control does when precision is unavailable; the escape is declassification,
which is explicit and recorded rather than silent.

The state is derived from the audit log rather than held separately. That is
deliberate: it means the flow claim inside a receipt can be recomputed by
anyone holding the trail, so the claim is checkable rather than merely asserted
by the server that made it. It also means the property survives a restart.

Limits, stated plainly:
  - Session granularity, not value granularity. We bound what the agent could
    have seen, not what it actually used.
  - Correct only for reads that pass through AgentGate. Data an agent obtains
    by a path we do not mediate is invisible, as it is to any reference monitor.
  - The watermark only rises within a window. Long-lived agents need
    declassification or they saturate; that is the intended pressure, since a
    session that has touched everything should not be quietly trusted with a
    sink.
"""

from enum import IntEnum

from core.platform import audit
from core.platform.models import EXFILTRATION_ACTIONS, ResourceSensitivity


class Confidentiality(IntEnum):
    """How restricted the data is. Ordered: a sink must dominate what flows in."""
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    SECRET = 3


class Integrity(IntEnum):
    """Where the influence came from. UNTRUSTED is the lower, absorbing element."""
    UNTRUSTED = 0
    TRUSTED = 1


# The sensitivity classifier already reads a resource path and grades it; the
# confidentiality lattice is that grading under a name that says what it is for.
_SENSITIVITY_TO_CONFIDENTIALITY = {
    ResourceSensitivity.LOW: Confidentiality.PUBLIC,
    ResourceSensitivity.MEDIUM: Confidentiality.INTERNAL,
    ResourceSensitivity.HIGH: Confidentiality.CONFIDENTIAL,
    ResourceSensitivity.CRITICAL: Confidentiality.SECRET,
}

# Actions that move data out of the agent's reach and therefore need a check.
SINK_ACTIONS = frozenset(EXFILTRATION_ACTIONS)

# How far back a session extends. Matches the kill-chain window so an operator
# reasons about one notion of "this session" rather than two.
SESSION_WINDOW_SECONDS = 86_400.0

# Reads count toward the watermark; sinks and writes do not add exposure.
_READ_ACTIONS = frozenset({"read", "search", "list", "query", "get", "fetch", "view"})


def confidentiality_of(resource: str, action: str = "") -> Confidentiality:
    """Grade a resource on the confidentiality lattice."""
    from core.enforcement.trust_engine import classify_resource_sensitivity

    sensitivity = classify_resource_sensitivity(resource, action)
    return _SENSITIVITY_TO_CONFIDENTIALITY[sensitivity]


def clearance_of_destination(resource: str) -> Confidentiality:
    """
    How much confidentiality a destination may receive.

    A sink's destination is graded the same way a source is: sending a payroll
    export to /reports/public/ is a drop from SECRET to PUBLIC, and that drop is
    the violation. Grading the destination without the action avoids the
    circularity of EXFILTRATION_ACTIONS forcing every sink target to CRITICAL.
    """
    return confidentiality_of(resource, action="")


class FlowState:
    """What a session has been exposed to, and whether it can still be trusted."""

    def __init__(
        self,
        confidentiality: Confidentiality,
        integrity: Integrity,
        sources: list[str],
        untrusted_reason: str = "",
    ):
        self.confidentiality = confidentiality
        self.integrity = integrity
        # Which reads raised the watermark. Carried so a refusal can name the
        # exposure that caused it instead of stating a level with no cause.
        self.sources = sources
        self.untrusted_reason = untrusted_reason

    def to_dict(self) -> dict:
        return {
            "confidentiality": self.confidentiality.name,
            "integrity": self.integrity.name,
            "sources": self.sources[:8],
            "untrusted_reason": self.untrusted_reason,
        }

    def canonical(self) -> str:
        """Stable string form, for binding the state into a receipt signature."""
        return f"{self.confidentiality.name}|{self.integrity.name}"


def compute_flow_state(
    agent_id: str,
    processes_external_content: bool = False,
    injection_detected: bool = False,
    window_seconds: float = SESSION_WINDOW_SECONDS,
) -> FlowState:
    """
    Derive the session's labels from what the agent has already been allowed to do.

    Recomputed per request from the audit trail rather than accumulated in
    memory, so it cannot drift from the record it is supposed to describe, and
    an auditor holding the trail reaches the same answer.
    """
    history = audit.get_agent_request_history(agent_id, window_seconds=window_seconds)

    watermark = Confidentiality.PUBLIC
    sources: list[str] = []
    for entry in history:
        if entry["action"].lower() not in _READ_ACTIONS:
            continue
        level = confidentiality_of(entry["resource"], entry["action"])
        if level > watermark:
            watermark = level
            sources = [entry["resource"]]
        elif level == watermark and level > Confidentiality.PUBLIC:
            if entry["resource"] not in sources:
                sources.append(entry["resource"])

    integrity = Integrity.TRUSTED
    reason = ""
    if injection_detected:
        integrity = Integrity.UNTRUSTED
        reason = "injection detected in content submitted with this request"
    elif processes_external_content:
        # The agent declared that it consumes content it did not author. That is
        # a statement about its inputs, so its decisions are influenced by
        # material no one vetted, whether or not a scanner objected to it.
        integrity = Integrity.UNTRUSTED
        reason = "agent declares it processes external content"

    return FlowState(watermark, integrity, sources, reason)


# Argument names that name where data is going. A sink's destination usually
# lives in the arguments, not the resource path: "send /outbox/reply.txt" is in
# scope while {"to": "attacker@evil.com"} is the whole attack.
_DESTINATION_ARGS = (
    "to", "recipient", "recipients", "destination", "dest", "target",
    "url", "endpoint", "webhook", "email", "address", "channel", "bucket",
)


def extract_destinations(resource: str, arguments: dict | None) -> list[str]:
    """Everywhere this action would send data, from the path and the arguments."""
    found = [resource]
    for name, value in (arguments or {}).items():
        if name.lower() not in _DESTINATION_ARGS:
            continue
        if isinstance(value, str):
            found.append(value)
        elif isinstance(value, (list, tuple)):
            found.extend(str(v) for v in value)
    return found


def _sanctioned(destination: str, allowed: list[str] | None) -> bool:
    """Whether a destination matches something the agent declared in advance."""
    import fnmatch

    if not allowed:
        return False
    d = destination.lower()
    return any(fnmatch.fnmatch(d, pattern.lower()) for pattern in allowed)


def check_flow(
    state: FlowState,
    action: str,
    resource: str,
    arguments: dict | None = None,
    allowed_destinations: list[str] | None = None,
) -> list[str]:
    """
    Decide whether this action may carry the session's data where it is going.

    Returns flow violation flags, empty when the lattice permits the action.
    Only sinks are checked: a read raises the watermark, it does not spend it.
    """
    if action.lower() not in SINK_ACTIONS:
        return []

    flags = []
    destinations = extract_destinations(resource, arguments)

    # Confidentiality: what leaves must not be more restricted than where it goes.
    # Judged on the least-cleared destination, since data sent to several places
    # is only as contained as the most permissive of them.
    clearances = [clearance_of_destination(d) for d in destinations]
    lowest = min(clearances) if clearances else Confidentiality.PUBLIC
    if state.confidentiality > lowest:
        flags.append(
            f"FLOW_VIOLATION:CONFIDENTIALITY:{state.confidentiality.name}"
            f"_TO_{lowest.name}"
        )

    # Integrity: when material the agent did not author is in the session, the
    # instruction to send may itself be the attack, so the agent no longer gets
    # to choose where data goes — only destinations declared before the content
    # arrived still count.
    #
    # Refusing every send instead would be simpler and useless: reading a
    # ticket and replying to it is what a support agent is for. What must not
    # happen is a reply addressed somewhere nobody sanctioned.
    if state.integrity == Integrity.UNTRUSTED:
        unsanctioned = [
            d for d in destinations if not _sanctioned(d, allowed_destinations)
        ]
        if unsanctioned:
            flags.append(
                f"FLOW_VIOLATION:INTEGRITY:UNDECLARED_DESTINATION:{unsanctioned[0][:80]}"
            )

    return flags


def explain_violation(flags: list[str], state: FlowState) -> str:
    """One sentence naming the exposure, for the audit record and the operator."""
    for flag in flags:
        if flag.startswith("FLOW_VIOLATION:CONFIDENTIALITY"):
            where = ", ".join(state.sources[:3]) or "a restricted resource"
            return (
                f"this session read {state.confidentiality.name.lower()} material "
                f"({where}) and the destination only clears "
                f"{flag.rsplit('_TO_', 1)[-1].lower()}"
            )
        if flag.startswith("FLOW_VIOLATION:INTEGRITY"):
            where = flag.rsplit(":", 1)[-1]
            return (
                f"this send is addressed to '{where}', which the agent never "
                f"declared, and its session carries content it did not author — "
                f"{state.untrusted_reason or 'untrusted influence in session'}"
            )
    return ""


def capability_warning(
    processes_external_content: bool,
    authorized_resources: list[str],
    authorized_actions: list[str],
) -> str:
    """
    Tell an operator at registration when an agent's declared shape is the
    dangerous one, and return "" otherwise.

    Exposure to content the agent did not author, reach into sensitive
    resources, and a way to send outward: each is ordinary, and the three
    together are one instruction away from exfiltration. Simon Willison named
    the combination the lethal trifecta.

    This is a warning, not a refusal. A capability-based version of this check
    was written as a runtime veto and rejected: every support agent holds all
    three by design, so denying on the configuration would deny the product's
    most obvious use. What the runtime enforces instead is narrower and
    provable — an untrusted session cannot pick an undeclared destination, and
    a session that has actually exercised all three arms is denied by the
    trifecta detector. The configuration is worth knowing about; it is not
    worth blocking on.
    """
    if not processes_external_content:
        return ""

    reach = [r for r in authorized_resources
             if confidentiality_of(r) >= Confidentiality.CONFIDENTIAL]
    if not reach:
        return ""

    egress = sorted({a.lower() for a in authorized_actions} & SINK_ACTIONS)
    if not egress:
        return ""

    return (
        "This agent declares all three arms of the lethal trifecta: it reads "
        f"content it did not author, it can reach {', '.join(reach[:3])}, and it "
        f"can send via {', '.join(egress)}. Nothing is blocked on this, but "
        "declare allowed_destinations — without them, every send from a session "
        "carrying external content will be refused."
    )
