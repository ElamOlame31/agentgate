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


class AgentRegistration(BaseModel):
    agent_id: str
    name: str
    declared_purpose: str
    authorized_resources: List[str]
    authorized_actions: List[str]
    delegated_by: Optional[str] = None
    delegation_depth: int = 0
    scope_at_delegation: Optional[List[str]] = None
    token: Optional[str] = None


class AuthorizationRequest(BaseModel):
    agent_id: str
    action: str
    resource: str
    justification: Optional[str] = ""
    token: Optional[str] = None
    request_id: Optional[str] = None
    timestamp: float = Field(default_factory=time.time)


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
