export type Decision = "PERMIT" | "DENY" | "ESCALATE" | "PENDING";

export interface TrustBreakdown {
  identity:    number;
  delegation:  number;
  purpose:     number;
  behavioral:  number;
  final_score: number;
}

export interface AuthorizeResult {
  decision:        Decision;
  trust_breakdown: TrustBreakdown;
  explanation:     string;
  attack_flags:    string[];
  request_id:      string;
  sensitivity:     string;
}

export interface ScanResult {
  level:    "clean" | "suspicious" | "injection";
  evidence: string;
  patterns: string[];
}

export interface AgentRegistration {
  agent_id:                   string;
  name:                       string;
  declared_purpose:           string;
  authorized_resources:       string[];
  authorized_actions:         string[];
  delegation_depth?:          number;
  processes_external_content?: boolean;
  requires_human_approval?:   boolean;
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
