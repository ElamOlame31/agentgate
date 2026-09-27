/**
 * Offline receipt verification.
 *
 * A receipt answers three questions about an agent action, with no server, no
 * account and no network:
 *
 *   1. Did this instance really authorize it?   — Ed25519 signature
 *   2. What exactly did it authorize?           — action_ref over the operation
 *   3. Under what information flow?             — the labels the session carried
 *
 * None of those answers require trusting whoever hands you the receipt. The
 * signature is asymmetric, so the holder cannot have produced it. The operation
 * digest is recomputable, so "this authorized a 250 EUR payment to acct_9931"
 * can be checked against the payment that actually happened rather than
 * believed. That is the difference between a log and evidence.
 *
 * This file deliberately imports nothing from the client. A verifier that needs
 * the SDK configured, a server reachable, or a key the issuer holds is not a
 * verifier — it is a second request. `verifyReceipt` takes the receipt and the
 * published key and reads no module state at all.
 */

import { createHash, createHmac, createPublicKey, timingSafeEqual, verify as cryptoVerify } from "node:crypto";

import { computeActionRef, type Operation } from "./actionRef.js";

export const CANONICAL_SEP = "|";

/**
 * Field order of the signed string, published at GET /receipts/public-key so a
 * mismatch between implementations is detectable rather than silent.
 */
export const CANONICAL_FIELDS = [
  "response_nonce",
  "request_id",
  "agent_id",
  "decision",
  "timestamp",
  "action_ref",
  "flow",
] as const;

export interface FlowState {
  confidentiality?: string;
  integrity?: string;
  sources?: string[];
  untrusted_reason?: string;
}

/** The subset of an /authorize response a verifier needs. */
export interface Receipt {
  request_id?: string;
  agent_id?: string;
  decision?: string;
  timestamp?: number;
  action_ref?: string | null;
  response_nonce?: string | null;
  response_sig?: string | null;
  receipt_sig?: string | null;
  key_id?: string | null;
  flow?: FlowState | null;
}

// ── Python float formatting ─────────────────────────────────────────────────

/**
 * `round(x, 3)` with Python's banker's rounding.
 *
 * The half-way case is close to unreachable for a Unix timestamp, but the
 * alternative is a verifier that agrees with the server 99.9% of the time,
 * which is the worst possible failure mode for evidence: rare enough to ship,
 * frequent enough to eventually reject a genuine receipt.
 */
function roundHalfEven(x: number, digits: number): number {
  const factor = 10 ** digits;
  const scaled = x * factor;
  const floor = Math.floor(scaled);
  const diff = scaled - floor;
  let rounded: number;
  if (diff > 0.5) rounded = floor + 1;
  else if (diff < 0.5) rounded = floor;
  else rounded = floor % 2 === 0 ? floor : floor + 1;
  return rounded / factor;
}

/**
 * Python's `str()` of a float, for the range receipts actually occupy.
 *
 * Two departures from JavaScript: a float that landed on a whole number keeps
 * its ".0", and single-digit exponents are padded to two. Above 1e16 Python
 * switches to exponential notation at a different threshold than JavaScript
 * does; a Unix timestamp is nine digits, so that range is unreachable here and
 * is left unhandled rather than half-handled.
 */
export function pyFloatString(x: number): string {
  if (!Number.isFinite(x)) {
    throw new RangeError(`cannot format ${x} as a Python float`);
  }
  if (Number.isInteger(x) && Math.abs(x) < 1e16) {
    return `${x}.0`;
  }
  return String(x).replace(/e([+-])(\d)$/, "e$10$2");
}

/** The stable string form of the session's labels, as bound into the signature. */
export function flowToken(flow?: FlowState | null): string {
  if (!flow || !flow.confidentiality) return "";
  return `${flow.confidentiality}${CANONICAL_SEP}${flow.integrity ?? ""}`;
}

/**
 * Rebuild the exact bytes the issuer signed.
 *
 * Both signature schemes cover these same bytes: the HMAC authenticates the
 * receipt to whoever holds the shared secret, the Ed25519 signature to
 * everyone else.
 */
export function canonicalReceiptBytes(receipt: Receipt): Buffer {
  const parts = [
    receipt.response_nonce ?? "",
    receipt.request_id ?? "",
    receipt.agent_id ?? "",
    (receipt.decision ?? "").toUpperCase(),
    pyFloatString(roundHalfEven(Number(receipt.timestamp ?? 0), 3)),
    receipt.action_ref ?? "",
    flowToken(receipt.flow),
  ];
  return Buffer.from(parts.join(CANONICAL_SEP), "utf8");
}

// ── The checks ──────────────────────────────────────────────────────────────

export interface VerificationResult {
  /** Authentic and, if an operation was supplied, bound to it. */
  verified: boolean;
  signatureValid: boolean;
  signatureDetail: string;
  /** null when no operation was supplied to check against. */
  operationMatches: boolean | null;
  operationDetail: string;
  decision?: string;
  agentId?: string;
  requestId?: string;
  keyId?: string | null;
  flow: string[];
}

/** Whether the receipt was issued by the holder of that key. */
export function checkSignature(
  receipt: Receipt,
  publicKeyPem: string,
): { valid: boolean; detail: string } {
  if (!receipt.receipt_sig) {
    return { valid: false, detail: "receipt carries no Ed25519 signature" };
  }
  try {
    const key = createPublicKey(publicKeyPem);
    if (key.asymmetricKeyType !== "ed25519") {
      return { valid: false, detail: "the supplied key is not an Ed25519 public key" };
    }
    const ok = cryptoVerify(
      null,
      canonicalReceiptBytes(receipt),
      key,
      Buffer.from(receipt.receipt_sig, "base64"),
    );
    return ok
      ? { valid: true, detail: "signed by the holder of this key" }
      : {
          valid: false,
          detail: "signature does not match — forged, altered, or a different key",
        };
  } catch (err) {
    return {
      valid: false,
      detail: `could not check the signature: ${(err as Error).message}`,
    };
  }
}

/**
 * Whether the receipt authorizes the operation you are asking about.
 *
 * Without an operation to compare against, a receipt says only that
 * *something* was authorized. Supplying what actually ran is what turns it
 * into proof that this specific thing was.
 */
export function checkOperation(
  receipt: Receipt,
  operation?: Operation | null,
): { matches: boolean | null; detail: string } {
  if (!operation) {
    return {
      matches: null,
      detail: "no operation supplied — signature checked, binding not",
    };
  }
  const expected = receipt.action_ref ?? "";
  if (!expected) {
    return {
      matches: false,
      detail: "receipt carries no action_ref, so it binds no operation",
    };
  }
  let actual: string;
  try {
    actual = computeActionRef({
      ...operation,
      agent_id: operation.agent_id || receipt.agent_id || "",
    });
  } catch (err) {
    return { matches: false, detail: `operation is not canonicalizable: ${(err as Error).message}` };
  }
  if (actual === expected) {
    return { matches: true, detail: "this receipt authorizes exactly this operation" };
  }
  return {
    matches: false,
    detail:
      "this receipt does not authorize that operation\n" +
      `      authorized: ${expected}\n` +
      `      supplied:   ${actual}`,
  };
}

/** Plain sentences for what the session carried when the decision was made. */
export function describeFlow(receipt: Receipt): string[] {
  const flow = receipt.flow;
  if (!flow || !flow.confidentiality) return ["no information-flow state recorded"];

  const lines = [
    `session had been exposed to ${flow.confidentiality.toLowerCase()} material`,
    `decision inputs were ${(flow.integrity ?? "?").toLowerCase()}`,
  ];
  if (flow.sources?.length) lines.push("raised by: " + flow.sources.slice(0, 3).join(", "));
  if (flow.untrusted_reason) lines.push("untrusted because: " + flow.untrusted_reason);
  return lines;
}

/**
 * Run every check and return a structured result.
 *
 * A receipt is evidence only when it is authentic *and* binds the operation in
 * question. Either check failing makes it inadmissible, which is why
 * `verified` is not simply the signature result.
 */
export function verifyReceipt(
  receipt: Receipt,
  publicKeyPem: string,
  operation?: Operation | null,
): VerificationResult {
  const sig = checkSignature(receipt, publicKeyPem);
  const bind = checkOperation(receipt, operation);
  return {
    verified: sig.valid && bind.matches !== false,
    signatureValid: sig.valid,
    signatureDetail: sig.detail,
    operationMatches: bind.matches,
    operationDetail: bind.detail,
    decision: receipt.decision,
    agentId: receipt.agent_id,
    requestId: receipt.request_id,
    keyId: receipt.key_id ?? null,
    flow: describeFlow(receipt),
  };
}

// ── The symmetric check, for the holder of the shared secret ────────────────

const MAC_DOMAIN = "agentgate-response-mac|";

/** Responses older than this are stale. Mirrors AGENTGATE_RESPONSE_MAX_AGE. */
export const RESPONSE_MAX_AGE_SECONDS = 300;

/** Clock-skew tolerance for a receipt timestamped in the future. */
export const RESPONSE_MAX_FUTURE_SKEW_SECONDS = 5;

/**
 * Verify the HMAC a receipt carries.
 *
 * This is the weaker of the two checks and it is here for completeness: it
 * proves the receipt came from an instance holding AGENTGATE_SIGNING_KEY,
 * which is only meaningful to someone who already holds that key. Anyone being
 * shown evidence should use `verifyReceipt` instead — a symmetric scheme can
 * offer an auditor "trust us, or become us", and nothing between.
 */
export function verifyResponseMac(
  receipt: Receipt,
  signingKey: string,
  now: number = Date.now() / 1000,
): { valid: boolean; reason: string } {
  const age = now - Number(receipt.timestamp ?? 0);
  if (age > RESPONSE_MAX_AGE_SECONDS) {
    return {
      valid: false,
      reason: `RESPONSE_EXPIRED:age=${Math.round(age)}s_max=${RESPONSE_MAX_AGE_SECONDS}s`,
    };
  }
  if (age < -RESPONSE_MAX_FUTURE_SKEW_SECONDS) {
    return { valid: false, reason: `RESPONSE_FROM_FUTURE:skew=${Math.round(-age * 10) / 10}s` };
  }
  if (!receipt.response_sig) return { valid: false, reason: "SIGNATURE_MISSING" };

  const key = createHash("sha256").update(MAC_DOMAIN + signingKey, "utf8").digest();
  const expected = createHmac("sha256", key)
    .update(canonicalReceiptBytes(receipt))
    .digest("hex");

  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(receipt.response_sig, "utf8");
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return { valid: false, reason: "SIGNATURE_MISMATCH" };
  }
  return { valid: true, reason: "OK" };
}
