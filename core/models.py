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


class AuthorizationRequest(BaseModel):
    agent_id: str
    action: str = Field(max_length=128)
    resource: str = Field(max_length=2048)
    justification: Optional[str] = Field(default="", max_length=2000)
    token: Optional[str] = None
    request_id: Optional[str] = None
    timestamp: float = Field(default_factory=time.time)
    content: Optional[str] = Field(default=None, max_length=20_000)


class ContentScanRequest(BaseModel):
    agent_id: str
    content: str = Field(max_length=100_000)
    declared_purpose: Optional[str] = ""


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
