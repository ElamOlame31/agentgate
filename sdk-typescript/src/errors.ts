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

/**
 * The operation drifted between authorization and dispatch.
 *
 * This is the one the SDK exists for. A receipt says "PERMIT for a 250 EUR
 * payment to acct_9931"; if what is about to run is a 25,000 EUR payment to
 * acct_0002, the decision does not cover it, and the caller must not execute
 * on the strength of that decision. Loopjacking (arXiv 2609.21081) is this
 * failure with a human in the middle: the person approves A, the system
 * dispatches B, and every log afterwards records an approval.
 */
export class AgentGateBindingError extends Error {
  constructor(
    public readonly expected: string,
    public readonly actual: string,
    public readonly requestId: string,
  ) {
    super(
      "AgentGate binding mismatch: the operation about to run is not the one " +
        `that was authorized (request_id: ${requestId})\n` +
        `  authorized: ${expected || "<none>"}\n` +
        `  supplied:   ${actual}`,
    );
    this.name = "AgentGateBindingError";
  }
}

/**
 * A PERMIT arrived with no action_ref, so it binds no operation.
 *
 * Raised rather than passed through because the alternative is a caller that
 * believes it checked something. Disable with `requireBinding: false` if you
 * are knowingly running against an instance that cannot bind.
 */
export class AgentGateUnboundError extends Error {
  constructor(public readonly requestId: string) {
    super(
      "AgentGate returned a decision with no action_ref, so it authorizes no " +
        `specific operation (request_id: ${requestId}). Set requireBinding: false ` +
        "to accept unbound decisions.",
    );
    this.name = "AgentGateUnboundError";
  }
}
