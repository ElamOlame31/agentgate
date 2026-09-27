/**
 * AgentGate — runtime authorization for autonomous agents, with receipts.
 *
 * The client is small on purpose. Its one non-obvious job is to make the
 * dispatch-time check impossible to skip by accident: `run()` authorizes an
 * operation, re-derives the operation's content address from the values it is
 * actually about to pass, and refuses to execute if those disagree. Everything
 * else here is plumbing around that.
 */

import type {
  AgentGateConfig,
  AgentRegistration,
  AuthorizeOptions,
  AuthorizeResult,
  DelegationRequest,
  DelegationResult,
  RedeemResult,
  RevokeChainResult,
  ScanResult,
} from "./types.js";
import {
  AgentGateBindingError,
  AgentGateDeniedError,
  AgentGateEscalatedError,
  AgentGateNotRegisteredError,
  AgentGatePendingError,
  AgentGateUnavailableError,
  AgentGateUnboundError,
} from "./errors.js";
import { computeActionRef, type Operation } from "./actionRef.js";

export * from "./types.js";
export * from "./errors.js";
export * from "./actionRef.js";
export * from "./receipt.js";

// ── Helpers ────────────────────────────────────────────────────────────────

function randomUUID(): string {
  return crypto.randomUUID();
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// ── AgentGate client ───────────────────────────────────────────────────────

export class AgentGate {
  readonly url: string;
  private readonly headers: Record<string, string>;
  private readonly raiseOnDeny: boolean;
  private readonly raiseOnEscalate: boolean;
  private readonly autoResolvePending: boolean;
  private readonly pendingTimeout: number;
  private readonly requestTimeout: number;
  private readonly requireBinding: boolean;

  private _agentId: string | null = null;
  private _token: string | null = null;

  constructor(config: AgentGateConfig | string) {
    const c: AgentGateConfig = typeof config === "string" ? { url: config } : config;

    this.url = c.url.replace(/\/$/, "");
    this.headers = c.apiKey ? { "X-API-Key": c.apiKey } : {};
    this.raiseOnDeny = c.raiseOnDeny ?? true;
    this.raiseOnEscalate = c.raiseOnEscalate ?? false;
    this.autoResolvePending = c.autoResolvePending ?? true;
    this.pendingTimeout = c.pendingTimeout ?? 95;
    this.requestTimeout = c.requestTimeout ?? 30_000;
    this.requireBinding = c.requireBinding ?? true;
  }

  // ── Internal fetch wrapper ───────────────────────────────────────────────

  private async _fetch<T>(path: string, options: RequestInit = {}): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.requestTimeout);

    try {
      const res = await fetch(`${this.url}${path}`, {
        ...options,
        headers: {
          "Content-Type": "application/json",
          ...this.headers,
          ...(options.headers as Record<string, string> | undefined),
        },
        signal: controller.signal,
      });

      if (!res.ok) {
        const body = await res.text().catch(() => "");
        throw new Error(`HTTP ${res.status}: ${body}`);
      }

      return (await res.json()) as T;
    } catch (err: unknown) {
      if (err instanceof Error && err.name === "AbortError") {
        throw new AgentGateUnavailableError(this.url, err);
      }
      if (err instanceof TypeError) {
        throw new AgentGateUnavailableError(this.url, err);
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }

  // ── Registration ─────────────────────────────────────────────────────────

  async register(reg: AgentRegistration): Promise<string> {
    const res = await this._fetch<{ token: string }>("/agents/register", {
      method: "POST",
      body: JSON.stringify({
        delegation_depth: 0,
        processes_external_content: false,
        requires_human_approval: false,
        ...reg,
      }),
    });
    this._agentId = reg.agent_id;
    this._token = res.token;
    return res.token;
  }

  // ── Authorization ────────────────────────────────────────────────────────

  /**
   * Ask whether an operation may proceed.
   *
   * Pass `arguments` — the amount, the recipient, the path. Whatever you leave
   * out is not covered by the receipt and may change between this call and the
   * one that executes without anything noticing.
   */
  async authorize(
    action: string,
    resource: string,
    options: AuthorizeOptions = {},
  ): Promise<AuthorizeResult> {
    if (!this._agentId || !this._token) {
      throw new AgentGateNotRegisteredError();
    }

    const result = await this._fetch<AuthorizeResult>("/authorize", {
      method: "POST",
      body: JSON.stringify({
        agent_id: this._agentId,
        token: this._token,
        action,
        resource,
        arguments: options.arguments ?? null,
        content: options.content ?? null,
        justification: options.justification ?? `${action} ${resource}`,
        request_id: randomUUID(),
      }),
    });

    if (result.decision === "PENDING" && !this.autoResolvePending) {
      throw new AgentGatePendingError(result.request_id);
    }

    if (result.decision === "PENDING" && this.autoResolvePending) {
      const humanDecision = await this._pollPending(result.request_id);
      if (humanDecision !== "APPROVED") {
        const denied: AuthorizeResult = {
          ...result,
          decision: "DENY",
          explanation: "Denied by human reviewer",
        };
        if (this.raiseOnDeny) {
          throw new AgentGateDeniedError(action, resource, denied);
        }
        return denied;
      }
      return { ...result, decision: "PERMIT" };
    }

    if (result.decision === "DENY" && this.raiseOnDeny) {
      throw new AgentGateDeniedError(action, resource, result);
    }

    if (result.decision === "ESCALATE" && this.raiseOnEscalate) {
      throw new AgentGateEscalatedError(action, resource, result);
    }

    // A PERMIT that binds nothing authorizes "something", not this. Treated as
    // a refusal by default, because the alternative is a caller that believes
    // it checked something it did not.
    if (result.decision === "PERMIT" && this.requireBinding && !result.action_ref) {
      throw new AgentGateUnboundError(result.request_id);
    }

    return result;
  }

  /**
   * Re-derive the operation's address and compare it with the receipt.
   *
   * Call this immediately before dispatch, with the values you are actually
   * about to pass — not the ones you sent to `authorize`. Reading them from
   * the same variables the real call will use is the entire point: anything
   * that rewrote them in between shows up here as a mismatch.
   */
  checkBinding(result: AuthorizeResult, operation: Omit<Operation, "agent_id">): void {
    const op: Operation = { ...operation, agent_id: result.agent_id };
    const actual = computeActionRef(op);
    if (actual !== (result.action_ref ?? "")) {
      throw new AgentGateBindingError(result.action_ref ?? "", actual, result.request_id);
    }
  }

  /**
   * Authorize an operation and run it only if the dispatch still matches.
   *
   * The ergonomic path, and the one worth using: there is no arrangement of
   * these two steps that lets the call happen without the check.
   */
  async run<T>(
    action: string,
    resource: string,
    options: AuthorizeOptions,
    fn: (result: AuthorizeResult) => T | Promise<T>,
  ): Promise<T> {
    const result = await this.authorize(action, resource, options);
    if (result.decision === "PERMIT" && result.action_ref) {
      this.checkBinding(result, {
        action,
        resource,
        arguments: options.arguments ?? null,
      });
    }
    return fn(result);
  }

  // ── Pending polling ──────────────────────────────────────────────────────

  private async _pollPending(requestId: string): Promise<string> {
    const deadline = Date.now() + this.pendingTimeout * 1000;
    while (Date.now() < deadline) {
      try {
        const data = await this._fetch<{ status: string }>(`/decisions/${requestId}`);
        if (data.status === "APPROVED" || data.status === "DENIED") {
          return data.status;
        }
      } catch {
        // Transient errors during polling are not decisions. The deadline
        // below is what resolves this, and it resolves it to DENIED.
      }
      await sleep(2000);
    }
    return "DENIED";
  }

  // ── Receipts ─────────────────────────────────────────────────────────────

  /**
   * Spend a receipt at the moment of dispatch.
   *
   * The server checks the signature and then burns the nonce, so a second
   * attempt with the same receipt fails. This is what stops a PERMIT from
   * being replayed into two transfers.
   */
  async redeem(result: AuthorizeResult): Promise<RedeemResult> {
    return this._fetch<RedeemResult>("/receipts/redeem", {
      method: "POST",
      body: JSON.stringify({
        nonce: result.response_nonce ?? "",
        mac: result.response_sig ?? "",
        request_id: result.request_id,
        agent_id: result.agent_id,
        decision: result.decision,
        timestamp: result.timestamp,
        action_ref: result.action_ref ?? "",
        flow: result.flow?.confidentiality
          ? `${result.flow.confidentiality}|${result.flow.integrity ?? ""}`
          : "",
      }),
    });
  }

  /**
   * The published Ed25519 key, for verifying receipts offline.
   *
   * Unauthenticated by design — an auditor checking evidence should not need
   * an account with the party being audited.
   */
  async receiptPublicKey(): Promise<{
    public_key_pem: string;
    key_id: string;
    algorithm: string;
  }> {
    const res = await fetch(`${this.url}/receipts/public-key`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return (await res.json()) as {
      public_key_pem: string;
      key_id: string;
      algorithm: string;
    };
  }

  // ── Content scanning ─────────────────────────────────────────────────────

  async scan(content: string): Promise<ScanResult> {
    if (!this._agentId) throw new AgentGateNotRegisteredError();
    return this._fetch<ScanResult>("/scan", {
      method: "POST",
      body: JSON.stringify({ agent_id: this._agentId, content }),
    });
  }

  // ── Delegation and revocation ────────────────────────────────────────────

  async delegate(req: DelegationRequest): Promise<DelegationResult> {
    return this._fetch<DelegationResult>("/agents/delegate", {
      method: "POST",
      body: JSON.stringify(req),
    });
  }

  async revoke(agentId: string): Promise<{ status: string; agent_id: string }> {
    return this._fetch(`/agents/${encodeURIComponent(agentId)}/revoke`, {
      method: "POST",
    });
  }

  /** Revoke an agent and every descendant in its delegation chain, atomically. */
  async revokeChain(agentId: string): Promise<RevokeChainResult> {
    return this._fetch(`/agents/${encodeURIComponent(agentId)}/revoke_chain`, {
      method: "POST",
    });
  }

  // ── Agent state ──────────────────────────────────────────────────────────

  /** Adopt an already-registered agent by id and token. */
  load(agentId: string, token: string): this {
    this._agentId = agentId;
    this._token = token;
    return this;
  }

  get agentId(): string | null {
    return this._agentId;
  }
  get token(): string | null {
    return this._token;
  }
  get isRegistered(): boolean {
    return this._agentId !== null;
  }
}

export default AgentGate;
