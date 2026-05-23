import type { AuthorizeResult } from "./types.js";

export class AgentGateDeniedError extends Error {
  readonly decision = "DENY" as const;
  constructor(
    public readonly action: string,
    public readonly resource: string,
    public readonly result: AuthorizeResult,
  ) {
    super(`AgentGate DENIED: ${action} on '${resource}' — ${result.explanation}`);
    this.name = "AgentGateDeniedError";
  }
}

export class AgentGateEscalatedError extends Error {
  readonly decision = "ESCALATE" as const;
  constructor(
    public readonly action: string,
    public readonly resource: string,
    public readonly result: AuthorizeResult,
  ) {
    super(`AgentGate ESCALATED: ${action} on '${resource}' — ${result.explanation}`);
    this.name = "AgentGateEscalatedError";
  }
}

export class AgentGateNotRegisteredError extends Error {
  constructor() {
    super("Agent is not registered. Call agentgate.register() before authorize().");
    this.name = "AgentGateNotRegisteredError";
  }
}

export class AgentGatePendingError extends Error {
  constructor(public readonly requestId: string) {
    super(`AgentGate decision is PENDING (request_id: ${requestId})`);
    this.name = "AgentGatePendingError";
  }
}

export class AgentGateUnavailableError extends Error {
  constructor(url: string, cause?: unknown) {
    super(`AgentGate server unreachable at ${url}`);
    this.name = "AgentGateUnavailableError";
    if (cause) this.cause = cause;
  }
}
