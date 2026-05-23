from pydantic import BaseModel, Field
from typing import Optional, List
from enum import Enum
import time


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
