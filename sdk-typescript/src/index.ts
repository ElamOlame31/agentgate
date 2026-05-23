import type {
  AgentGateConfig,
  AgentRegistration,
  AuthorizeResult,
  ScanResult,
} from "./types.js";
import {
  AgentGateDeniedError,
  AgentGateEscalatedError,
  AgentGateNotRegisteredError,
  AgentGateUnavailableError,
} from "./errors.js";

export * from "./types.js";
export * from "./errors.js";

// ── Helpers ────────────────────────────────────────────────────────────────

function randomUUID(): string {
  if (typeof crypto !== "undefined" && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  // Node 18 fallback
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    return (c === "x" ? r : (r & 0x3) | 0x8).toString(16);
  });
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

  private _agentId: string | null = null;
  private _token: string | null   = null;

  constructor(config: AgentGateConfig | string) {
    const c: AgentGateConfig =
      typeof config === "string" ? { url: config } : config;

    this.url                = c.url.replace(/\/$/, "");
    this.headers            = c.apiKey ? { "X-API-Key": c.apiKey } : {};
    this.raiseOnDeny        = c.raiseOnDeny        ?? true;
    this.raiseOnEscalate    = c.raiseOnEscalate    ?? false;
    this.autoResolvePending = c.autoResolvePending  ?? true;
    this.pendingTimeout     = c.pendingTimeout      ?? 95;
    this.requestTimeout     = c.requestTimeout      ?? 30_000;
  }

  // ── Internal fetch wrapper ───────────────────────────────────────────────

  private async _fetch<T>(
    path: string,
    options: RequestInit = {},
  ): Promise<T> {
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

      return res.json() as Promise<T>;
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
        delegation_depth:           0,
        processes_external_content: false,
        requires_human_approval:    false,
        ...reg,
      }),
    });
    this._agentId = reg.agent_id;
    this._token   = res.token;
    return res.token;
  }

  // ── Authorization ─────────────────────────────────────────────────────────

  async authorize(
    action: string,
    resource: string,
    justification?: string,
  ): Promise<AuthorizeResult> {
    if (!this._agentId || !this._token) {
      throw new AgentGateNotRegisteredError();
    }

    const result = await this._fetch<AuthorizeResult>("/authorize", {
      method: "POST",
      body: JSON.stringify({
        agent_id:     this._agentId,
        token:        this._token,
        action,
        resource,
        justification: justification ?? `${action} ${resource}`,
        request_id:   randomUUID(),
      }),
    });

    if (result.decision === "PENDING" && this.autoResolvePending) {
      const humanDecision = await this._pollPending(result.request_id);
      if (humanDecision !== "APPROVED") {
        if (this.raiseOnDeny) {
          throw new AgentGateDeniedError(action, resource, {
            ...result,
            decision: "DENY",
            explanation: "Denied by human reviewer",
          });
        }
      }
      return { ...result, decision: humanDecision === "APPROVED" ? "PERMIT" : "DENY" };
    }

    if (result.decision === "DENY" && this.raiseOnDeny) {
      throw new AgentGateDeniedError(action, resource, result);
    }

    if (result.decision === "ESCALATE" && this.raiseOnEscalate) {
      throw new AgentGateEscalatedError(action, resource, result);
    }

    return result;
  }

  // ── Pending polling ───────────────────────────────────────────────────────

  private async _pollPending(requestId: string): Promise<string> {
    const deadline = Date.now() + this.pendingTimeout * 1000;
    while (Date.now() < deadline) {
      try {
        const data = await this._fetch<{ status: string }>(
          `/decisions/${requestId}`,
        );
        if (data.status === "APPROVED" || data.status === "DENIED") {
          return data.status;
        }
      } catch {
        // ignore transient errors during polling
      }
      await sleep(2000);
    }
    return "DENIED";
  }

  // ── Content scanning ──────────────────────────────────────────────────────

  async scan(content: string): Promise<ScanResult> {
    if (!this._agentId) throw new AgentGateNotRegisteredError();
    return this._fetch<ScanResult>("/scan", {
      method: "POST",
      body: JSON.stringify({ agent_id: this._agentId, content }),
    });
  }

  // ── Guard decorator ───────────────────────────────────────────────────────

  guard(
    action: string,
    options: { resourceArg?: string; justification?: string } = {},
  ) {
    const gate = this;
    const { resourceArg = "path", justification } = options;

    return function <T extends (...args: unknown[]) => unknown>(fn: T): T {
      return async function guarded(...args: unknown[]) {
        // Extract resource from named argument or first positional arg
        const resource =
          (args[0] as Record<string, unknown>)?.[resourceArg] ??
          (typeof args[0] === "string" ? args[0] : action);

        await gate.authorize(action, String(resource), justification);
        return fn(...args);
      } as unknown as T;
    };
  }

  // ── Operation context helper ──────────────────────────────────────────────

  async operation<T>(
    action: string,
    resource: string,
    fn: () => T | Promise<T>,
    justification?: string,
  ): Promise<T> {
    await this.authorize(action, resource, justification);
    return fn();
  }

  // ── Agent state ───────────────────────────────────────────────────────────

  get agentId(): string | null { return this._agentId; }
  get token():   string | null { return this._token; }
  get isRegistered(): boolean  { return this._agentId !== null; }
}

// ── Default export ─────────────────────────────────────────────────────────

export default AgentGate;
