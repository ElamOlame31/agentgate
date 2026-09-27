import type { FlowState } from "./receipt.js";

export type Decision = "PERMIT" | "DENY" | "ESCALATE" | "PENDING";

export type ResourceSensitivity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type { FlowState };

/**
 * The heuristic layer. It is useful and it is not what the product rests on —
 * a score is an opinion, and an opinion cannot be checked by an auditor. The
 * lattice and the receipt are the checkable parts.
 */
export interface TrustBreakdown {
  identity_score: number;
  delegation_score: number;
  purpose_alignment_score: number;
  behavioral_score: number;
  final_score: number;
  resource_sensitivity: ResourceSensitivity;
  threshold_required: number;
}

export interface AuthorizeResult {
  decision: Decision;
  trust_breakdown: TrustBreakdown;
  explanation: string;
  attack_flags: string[];
  request_id: string;
  agent_id: string;
  action: string;
  resource: string;
  timestamp: number;
  injection_score?: number | null;

  /**
   * Content address of the authorized operation. Recompute it at dispatch and
   * refuse to execute on a mismatch — `AgentGate.dispatch` does this for you.
   * Absent when the descriptor could not be canonicalized, in which case the
   * verdict still stands but binds nothing.
   */
  action_ref?: string | null;

  /** The resource in the form action_ref was computed over. */
  normalized_resource?: string | null;

  /**
   * What the session had been exposed to at decision time, and whether
   * anything it did not author influenced it. Derived from the audit trail, so
   * a holder of the trail can recompute it rather than take the server's word.
   */
  flow?: FlowState | null;

  /** HMAC over the receipt, for a holder of the shared secret. */
  response_nonce?: string | null;
  response_sig?: string | null;

  /** Ed25519 over the same bytes, for everyone else. */
  receipt_sig?: string | null;
  key_id?: string | null;
}

export interface RedeemResult {
  status: string;
  reason?: string;
  request_id?: string;
}

export interface ScanResult {
  level: "clean" | "suspicious" | "injection";
  confidence: number;
  evidence: string;
  scanned: boolean;
}

export interface AgentRegistration {
  agent_id: string;
  name: string;
  declared_purpose: string;
  authorized_resources: string[];
  authorized_actions: string[];
  processes_external_content?: boolean;
  requires_human_approval?: boolean;
  /** Hard rate limit declared at registration. Violations always DENY. */
  max_requests_per_minute?: number;
  /** UTC windows the agent may operate in, e.g. ["09:00-17:00"]. */
  allowed_time_windows?: string[];
  /** Max consecutive identical actions before DENY. */
  max_consecutive_same_action?: number;
  /**
   * Where this agent may send data, as fnmatch patterns — e.g.
   * ["/outbox/*", "*@ourcompany.com"]. Declared before any content arrives,
   * which is what makes it meaningful: once a session carries material the
   * agent did not author, that material must not choose the destination.
   */
  allowed_destinations?: string[];
}

export interface DelegationRequest {
  parent_agent_id: string;
  parent_token: string;
  child_agent_id: string;
  child_name: string;
  child_declared_purpose: string;
  child_resources: string[];
  child_actions: string[];
}

export interface DelegationResult {
  agent_id: string;
  token: string;
  delegation_depth: number;
  delegated_by: string;
  status: string;
}

export interface RevokeChainResult {
  status: string;
  root: string;
  revoked: string[];
  count: number;
}

/** Options for a single authorization. */
export interface AuthorizeOptions {
  /**
   * Every material argument of the call — the amount, the recipient, the body.
   * What you leave out is not bound by action_ref and may therefore change
   * between the decision and the dispatch without detection.
   */
  arguments?: Record<string, unknown>;
  justification?: string;
  /** Untrusted content the agent just read, for injection scoring. */
  content?: string;
}

export interface AgentGateConfig {
  /** AgentGate server URL, e.g. "http://localhost:8000" */
  url: string;
  /** API key (X-API-Key header) */
  apiKey?: string;
  /** Throw AgentGateDeniedError on DENY decisions (default: true) */
  raiseOnDeny?: boolean;
  /** Throw AgentGateEscalatedError on ESCALATE decisions (default: false) */
  raiseOnEscalate?: boolean;
  /** Poll for the human decision when PENDING (default: true) */
  autoResolvePending?: boolean;
  /** Seconds before auto-deny on PENDING (default: 95) */
  pendingTimeout?: number;
  /** Request timeout in ms (default: 30000) */
  requestTimeout?: number;
  /**
   * Treat a PERMIT that carries no action_ref as a refusal (default: true).
   *
   * A verdict without a binding authorizes "something" rather than this
   * operation, which is the gap this SDK exists to close. Turn it off only if
   * you are knowingly running against an instance that cannot bind.
   */
  requireBinding?: boolean;
}
