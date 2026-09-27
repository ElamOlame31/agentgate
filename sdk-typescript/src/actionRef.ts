/**
 * action_ref — a content address for the operation an agent is about to perform.
 *
 * This is a second implementation of what `core/receipts/action_ref.py` does,
 * and it has to agree with it byte for byte: the server computes the digest,
 * this code recomputes it at dispatch, and a mismatch is the whole signal. A
 * divergence here would not fail loudly — it would silently refuse valid
 * operations, or worse, accept drifted ones. `test/parity.test.mjs` runs both
 * implementations over the same vectors for exactly that reason.
 *
 *     action_ref = SHA-256( canonicalJson( descriptor ) )
 *
 * Deliberately absent from the descriptor: nonce, timestamp, decision. Those
 * belong to one authorization event and differ between the request and the
 * dispatch that follows it, which would make the reference unrecomputable —
 * the opposite of what it is for. They are bound separately by the receipt
 * signature, which covers action_ref alongside them.
 */

import { createHash } from "node:crypto";

/** Bumped when the descriptor shape changes in a way that alters digests. */
export const DESCRIPTOR_VERSION = 1;

/**
 * Arguments are bound in full, so a runaway payload would be hashed in full
 * too. Anything larger is refused rather than truncated: truncation would let
 * everything past the cutoff vary without changing the digest.
 */
export const MAX_ARGUMENTS_BYTES = 16_384;

export class ActionRefError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ActionRefError";
  }
}

// ── Python-compatible percent-decoding ──────────────────────────────────────

const HEX_PAIR = /^[0-9A-Fa-f]{2}$/;

/**
 * `urllib.parse.unquote` semantics, which are not `decodeURIComponent`.
 *
 * Three differences matter, and all three are reachable from a path an
 * attacker controls: Python leaves a stray percent alone where
 * decodeURIComponent throws, leaves an invalid pair such as %zz alone for the
 * same reason, and substitutes U+FFFD for undecodable UTF-8 rather than
 * raising. Using the built-in would mean this client rejects resources the
 * server normalizes without complaint.
 */
export function unquote(text: string): string {
  if (!text.includes("%")) return text;

  const decoder = new TextDecoder("utf-8", { fatal: false });
  const parts = text.split("%");
  let out = parts[0];
  let pending: number[] = [];

  const flush = () => {
    if (pending.length) {
      out += decoder.decode(new Uint8Array(pending));
      pending = [];
    }
  };

  for (let i = 1; i < parts.length; i++) {
    const part = parts[i];
    const head = part.slice(0, 2);
    if (HEX_PAIR.test(head)) {
      // A run of consecutive escapes decodes as one UTF-8 sequence, so bytes
      // accumulate until something interrupts the run.
      pending.push(parseInt(head, 16));
      const tail = part.slice(2);
      if (tail) {
        flush();
        out += tail;
      }
    } else {
      flush();
      out += "%" + part;
    }
  }
  flush();
  return out;
}

/**
 * `posixpath.normpath`, ported.
 *
 * The two-leading-slash rule is not decoration. POSIX reserves exactly two
 * initial slashes as implementation-defined and Python preserves them, so
 * "//etc/passwd" normalizes to itself while "///etc/passwd" collapses to
 * "/etc/passwd". A client that collapsed both would compute a different digest
 * than the server for a path the caller does not control.
 */
export function normpath(path: string): string {
  if (path === "") return ".";

  let initialSlashes = path.startsWith("/") ? 1 : 0;
  if (initialSlashes && path.startsWith("//") && !path.startsWith("///")) {
    initialSlashes = 2;
  }

  const out: string[] = [];
  for (const comp of path.split("/")) {
    if (comp === "" || comp === ".") continue;
    if (
      comp !== ".." ||
      (!initialSlashes && out.length === 0) ||
      (out.length > 0 && out[out.length - 1] === "..")
    ) {
      out.push(comp);
    } else if (out.length) {
      out.pop();
    }
  }

  const joined = "/".repeat(initialSlashes) + out.join("/");
  return joined || ".";
}

/**
 * Normalize a resource to the form the reference is computed over.
 *
 * Client and server must agree byte for byte or every dispatch check fails, so
 * this mirrors the server's single definition: decode twice (catching double
 * encoding, %252e%252e to %2e%2e to ..), strip NULs, normalize, and guarantee
 * a leading slash.
 */
export function normalizeResource(resource: string): string {
  const decoded = unquote(unquote(resource)).replace(/\0/g, "");
  const normalized = normpath(decoded);
  return normalized.startsWith("/") ? normalized : "/" + normalized;
}

// ── Canonical JSON ──────────────────────────────────────────────────────────

/**
 * Number formatting that survives the round trip through the server.
 *
 * The server does not hash this JS value; it hashes what Python's json module
 * makes of the bytes this SDK put on the wire. So the target is not "Python's
 * repr of this number" but "Python's repr of what json.loads produced from
 * JSON.stringify(n)". Those agree everywhere except one spot, handled here:
 * Python pads a single-digit exponent to two digits, writing 1e-07 where
 * JavaScript writes 1e-7.
 */
function formatNumber(n: number): string {
  if (!Number.isFinite(n)) {
    throw new ActionRefError(`${n} is not representable in canonical JSON`);
  }
  return String(n).replace(/e([+-])(\d)$/, "e$10$2");
}

/**
 * Serialize to the canonical form the digest is taken over: sorted keys, no
 * insignificant whitespace, real UTF-8 rather than escape sequences.
 *
 * Equivalent to the server's `json.dumps(v, sort_keys=True,
 * separators=(",", ":"), ensure_ascii=False, allow_nan=False)`.
 */
export function canonicalJson(value: unknown): string {
  if (value === null) return "null";

  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number":
      return formatNumber(value);
    case "string":
      // JSON.stringify already matches Python's escaping under
      // ensure_ascii=False: quote, backslash, and control characters only.
      return JSON.stringify(value);
    case "object":
      break;
    default:
      throw new ActionRefError(
        `operation is not canonicalizable: ${typeof value} has no JSON form`,
      );
  }

  if (Array.isArray(value)) {
    return "[" + value.map(canonicalJson).join(",") + "]";
  }

  const obj = value as Record<string, unknown>;
  return (
    "{" +
    Object.keys(obj)
      .sort()
      .map((k) => JSON.stringify(k) + ":" + canonicalJson(obj[k]))
      .join(",") +
    "}"
  );
}

// ── The descriptor ──────────────────────────────────────────────────────────

export interface Operation {
  agent_id: string;
  action: string;
  resource: string;
  /**
   * Every material argument of the call — the amount, the recipient, the body.
   * Anything omitted here is unbound: it can change between authorization and
   * execution without invalidating the receipt, which is precisely the
   * confused-deputy hole. Omit only what cannot affect the consequence.
   */
  arguments?: Record<string, unknown> | null;
  policy_version?: string;
}

export interface Descriptor {
  v: number;
  agent_id: string;
  action: string;
  resource: string;
  arguments: Record<string, unknown>;
  policy_version: string;
}

export function buildDescriptor(op: Operation): Descriptor {
  const args = op.arguments ?? {};
  if (typeof args !== "object" || Array.isArray(args)) {
    throw new ActionRefError("arguments must be a JSON object");
  }

  const size = Buffer.byteLength(canonicalJson(args), "utf8");
  if (size > MAX_ARGUMENTS_BYTES) {
    throw new ActionRefError(
      `arguments too large to bind: ${size} bytes > ${MAX_ARGUMENTS_BYTES}`,
    );
  }

  return {
    v: DESCRIPTOR_VERSION,
    agent_id: op.agent_id,
    action: op.action.toLowerCase(),
    resource: normalizeResource(op.resource),
    arguments: args,
    policy_version: op.policy_version ?? "",
  };
}

/** The SHA-256 hex digest that addresses this operation. */
export function computeActionRef(op: Operation): string {
  return createHash("sha256")
    .update(canonicalJson(buildDescriptor(op)), "utf8")
    .digest("hex");
}

/**
 * Whether an operation still resolves to the reference issued for it.
 *
 * This is the dispatch-time check, and it fails closed: a descriptor that
 * cannot be canonicalized returns false rather than throwing, because the
 * caller's question is "may I run this", and "I could not tell" is a no.
 */
export function matches(actionRef: string, op: Operation): boolean {
  if (!actionRef) return false;
  try {
    return computeActionRef(op) === actionRef;
  } catch {
    return false;
  }
}
