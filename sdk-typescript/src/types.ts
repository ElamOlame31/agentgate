export type Decision = "PERMIT" | "DENY" | "ESCALATE" | "PENDING";

export type ResourceSensitivity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface TrustBreakdown {
  identity_score:            number;
  delegation_score:          number;
  purpose_alignment_score:   number;
  behavioral_score:          number;
  final_score:               number;
  resource_sensitivity:      ResourceSensitivity;
  threshold_required:        number;
}

export interface AuthorizeResult {
  decision:        Decision;
  trust_breakdown: TrustBreakdown;
  explanation:     string;
  attack_flags:    string[];
  request_id:      string;
  agent_id:        string;
  action:          string;
  resource:        string;
  timestamp:       number;
  injection_score?: number;
}

export interface ScanResult {
  level:      "clean" | "suspicious" | "injection";
  confidence: number;
  evidence:   string;
  scanned:    boolean;
}

export interface AgentRegistration {
  agent_id:                    string;
  name:                        string;
  declared_purpose:            string;
  authorized_resources:        string[];
  authorized_actions:          string[];
  processes_external_content?: boolean;
  requires_human_approval?:    boolean;
  /** Hard rate limit declared at registration. Violations always DENY. */
  max_requests_per_minute?:    number;
  /** UTC time windows where the agent is allowed to operate, e.g. ["09:00-17:00"] */
  allowed_time_windows?:       string[];
  /** Max consecutive identical actions before DENY */
  max_consecutive_same_action?: number;
}

export interface DelegationRequest {
  parent_agent_id:       string;
  parent_token:          string;
  child_agent_id:        string;
  child_name:            string;
  child_declared_purpose: string;
  child_resources:       string[];
  child_actions:         string[];
}

export interface DelegationResult {
  agent_id:         string;
  token:            string;
  delegation_depth: number;
  delegated_by:     string;
  status:           string;
}

export interface RevokeChainResult {
  status:  string;
  root:    string;
  revoked: string[];
  count:   number;
}

export interface AgentGateConfig {
  /** AgentGate server URL, e.g. "http://localhost:8000" */
  url:                   string;
  /** API key (X-API-Key header) */
  apiKey?:               string;
  /** Throw AgentGateDeniedError on DENY decisions (default: true) */
  raiseOnDeny?:          boolean;
  /** Throw AgentGateEscalatedError on ESCALATE decisions (default: false) */
  raiseOnEscalate?:      boolean;
  /** Poll for human decision when PENDING (default: true) */
  autoResolvePending?:   boolean;
  /** Seconds before auto-deny on PENDING (default: 95) */
  pendingTimeout?:       number;
  /** Request timeout in ms (default: 30000) */
  requestTimeout?:       number;
}
