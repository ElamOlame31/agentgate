from pydantic import BaseModel, Field
from typing import Optional, List
from enum import Enum
import time


# Single source of truth for exfiltration action verbs.
# Imported by trust_engine, kill_chain, and purpose_engine.
EXFILTRATION_ACTIONS: frozenset[str] = frozenset({
    "send", "email", "upload", "post", "forward", "export", "transfer", "publish",
})


class ResourceSensitivity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Decision(str, Enum):
    PERMIT = "PERMIT"
    DENY = "DENY"
    ESCALATE = "ESCALATE"
    PENDING = "PENDING"


class AgentRegistration(BaseModel):
    agent_id: str
    name: str = Field(max_length=128)
    declared_purpose: str = Field(max_length=500)
    authorized_resources: List[str] = Field(max_length=100)
    authorized_actions: List[str] = Field(max_length=50)
    delegated_by: Optional[str] = None
    delegation_depth: int = Field(default=0, ge=0)
    scope_at_delegation: Optional[List[str]] = None
    token: Optional[str] = None
    token_expires_at: Optional[float] = None
    processes_external_content: bool = False
    requires_human_approval: bool = False
    # Behavioral contract — hard limits declared at registration time.
    # Violations produce CONTRACT_* flags that always result in DENY, regardless of trust score.
    max_requests_per_minute: Optional[int] = Field(default=None, ge=1)
    allowed_time_windows: Optional[List[str]] = Field(default=None)  # e.g. ["09:00-17:00"] UTC
    max_consecutive_same_action: Optional[int] = Field(default=None, ge=1)
    # Trust ceiling — delegated agents cannot exceed their parent's trust score.
    # Set at delegation time. Prevents trust-washing: a low-trust parent cannot spawn
    # a child that earns a higher score than the parent could ever reach.
    trust_ceiling: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    # Where this agent may send data. Declared before any content arrives,
    # which is what makes it meaningful: once a session carries material the
    # agent did not author, that material must not get to choose the
    # destination. Patterns are fnmatch, e.g. ["/outbox/*", "*@ourcompany.com"].
    allowed_destinations: Optional[List[str]] = Field(default=None, max_length=100)


class AuthorizationRequest(BaseModel):
    agent_id: str
    action: str = Field(max_length=128)
    resource: str = Field(max_length=2048)
    justification: Optional[str] = Field(default="", max_length=2000)
    token: Optional[str] = None
    request_id: Optional[str] = None
    timestamp: float = Field(default_factory=time.time)
    content: Optional[str] = Field(default=None, max_length=20_000)
    # Material arguments of the call — the amount, the recipient, the body.
    # Whatever is left out is not bound by action_ref and may therefore
    # change between the decision and the dispatch without detection.
    arguments: Optional[dict] = None


class ContentScanRequest(BaseModel):
    agent_id: str
    content: str = Field(max_length=100_000)
    declared_purpose: Optional[str] = ""


class ReceiptRedeemRequest(BaseModel):
    """A receipt handed back at dispatch, to be spent before the action runs.

    Every field comes straight from the /authorize response. The caller does
    not construct any of it, which is what makes the redemption meaningful:
    it can only present what the server issued.
    """
    nonce: str = Field(max_length=128)
    mac: str = Field(max_length=128)
    request_id: str = Field(max_length=128)
    agent_id: str = Field(max_length=128)
    decision: str = Field(max_length=32)
    timestamp: float
    action_ref: str = Field(default="", max_length=128)
    # Signed alongside the rest, so it has to come back to check the MAC.
    flow: str = Field(default="", max_length=128)


class OutputSanitizeRequest(BaseModel):
    agent_id: str
    content: str = Field(max_length=100_000)
    token: Optional[str] = None


class ContentScanResponse(BaseModel):
    level: str          # "clean", "suspicious", "injection"
    confidence: float
    evidence: str
    scanned: bool       # False if scan was skipped (agent not eligible)


class TrustBreakdown(BaseModel):
    identity_score: float
    delegation_score: float
    purpose_alignment_score: float
    behavioral_score: float
    resource_sensitivity: ResourceSensitivity
    final_score: float
    threshold_required: float


class AuthorizationResponse(BaseModel):
    request_id: str
    agent_id: str
    action: str
    resource: str
    decision: Decision
    trust_breakdown: TrustBreakdown
    explanation: str
    timestamp: float = Field(default_factory=time.time)
    attack_flags: List[str] = []
    injection_score: Optional[float] = None  # set when a prior /scan result exists for this agent
    # NSA-aligned response MAC (HMAC-SHA256 + nonce).
    # SDK clients can call core.receipts.response_signing.verify_response() to confirm
    # the response originated from this instance and has not been replayed.
    response_nonce: Optional[str] = None
    response_sig: Optional[str] = None
    # Content address of the authorized operation. The caller recomputes it
    # at dispatch and refuses to execute on a mismatch.
    action_ref: Optional[str] = None
    # Resource in the normalized form action_ref was computed over, so the
    # caller can reproduce the digest without reimplementing normalization.
    normalized_resource: Optional[str] = None
    # Information-flow state of the session at decision time: what the agent
    # had been exposed to, and whether anything it did not author influenced
    # it. Derived from the audit trail, so a holder of the trail can recompute
    # it rather than take the server's word for it.
    flow: Optional[dict] = None
    # Ed25519 signature over the same canonical bytes as response_sig.
    # The HMAC authenticates the receipt to whoever holds the shared secret;
    # this one lets an auditor check it with only the published key.
    receipt_sig: Optional[str] = None
    # Fingerprint of the key that signed, so a verifier can tell a key
    # rotation from a forgery.
    key_id: Optional[str] = None
