/**
 * AgentGate × Vercel AI SDK integration.
 *
 * Wraps Vercel AI SDK tools with pre-execution authorization.
 * Every tool call is intercepted — AgentGate decides PERMIT / ESCALATE / DENY
 * before the tool's execute function runs.
 *
 * Usage — single tool:
 *
 *   import { tool } from "ai";
 *   import { z } from "zod";
 *   import AgentGate from "agentgate-pdp";
 *   import { guardTool } from "agentgate-pdp/vercel";
 *
 *   const gate = new AgentGate({ url: "http://localhost:8000", apiKey: "your-key" });
 *   await gate.register({
 *     agent_id: "report_bot",
 *     name: "ReportBot",
 *     declared_purpose: "Summarize quarterly business reports",
 *     authorized_resources: ["/reports/*"],
 *     authorized_actions: ["read"],
 *   });
 *
 *   const readReport = guardTool(gate, tool({
 *     description: "Read a quarterly report",
 *     parameters: z.object({ path: z.string() }),
 *     execute: async ({ path }) => fs.readFile(path, "utf-8"),
 *   }), { action: "read", resourceParam: "path" });
 *
 * Usage — wrap an entire tools object at once:
 *
 *   const tools = guardTools(gate, {
 *     readReport: tool({ ... }),
 *     searchDocuments: tool({ ... }),
 *     exportSummary: tool({ ... }),
 *   });
 *
 *   // Pass to streamText / generateText
 *   const result = await streamText({ model, tools, prompt });
 */

import AgentGate from "./index.js";
import { AgentGateDeniedError } from "./errors.js";

// ── Types ──────────────────────────────────────────────────────────────────────

/**
 * Minimal shape of a Vercel AI SDK tool.
 * We don't import from "ai" to avoid a hard dependency — any object matching
 * this shape (including CoreTool from the "ai" package) is compatible.
 */
export interface VercelTool<TParams extends Record<string, unknown> = Record<string, unknown>> {
  description?: string;
  parameters: unknown;
  execute?: (params: TParams, options?: unknown) => Promise<unknown>;
}

export type ToolRecord = Record<string, VercelTool>;

export interface GuardToolOptions {
  /** The action verb for AgentGate (e.g. "read", "write", "delete"). Inferred from tool name if omitted. */
  action?: string;
  /** Which parameter holds the resource path/identifier (default: "path"). */
  resourceParam?: string;
  /** Static justification string. Defaults to "<action> <resource>". */
  justification?: string;
  /**
   * Whether to allow ESCALATE decisions to proceed.
   * When true, execution continues but the result is annotated with a warning.
   * When false, ESCALATE throws AgentGateDeniedError (default: true).
   */
  allowEscalate?: boolean;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function inferAction(toolName: string): string {
  const name = toolName.toLowerCase();
  if (["delete", "remove", "drop", "erase", "purge"].some((k) => name.includes(k))) return "delete";
  if (["write", "create", "save", "update", "insert", "post", "send", "upload", "export"].some((k) => name.includes(k))) return "write";
  if (["search", "list", "find", "query", "browse", "fetch"].some((k) => name.includes(k))) return "search";
  return "read";
}

function extractResource(params: Record<string, unknown>, resourceParam: string): string {
  if (params[resourceParam] !== undefined) return String(params[resourceParam]);
  for (const key of ["url", "file", "filepath", "file_path", "path", "query", "topic", "id"]) {
    if (params[key] !== undefined) return String(params[key]);
  }
  // Last resort: first string value in params
  for (const val of Object.values(params)) {
    if (typeof val === "string" && val.length > 0) return val;
  }
  return "unknown";
}

// ── Core wrapper ───────────────────────────────────────────────────────────────

/**
 * Wrap a single Vercel AI SDK tool with AgentGate pre-execution authorization.
 *
 * The returned tool is structurally identical to the input — description,
 * parameters, and the execute signature are preserved. Only the execute function
 * is intercepted: AgentGate runs first, then the original execute.
 */
export function guardTool<TParams extends Record<string, unknown>>(
  gate: AgentGate,
  inputTool: VercelTool<TParams>,
  options: GuardToolOptions = {},
): VercelTool<TParams> {
  if (!inputTool.execute) return inputTool; // passthrough for tools with no execute (type-only)

  const originalExecute = inputTool.execute;
  const {
    resourceParam = "path",
    justification,
    allowEscalate = true,
  } = options;

  return {
    ...inputTool,
    execute: async (params: TParams, executeOptions?: unknown): Promise<unknown> => {
      const action   = options.action ?? "read";
      const resource = extractResource(params as Record<string, unknown>, resourceParam);
      const reason   = justification ?? `${action} ${resource}`;

      const result = await gate.authorize(action, resource, reason);

      if (result.decision === "DENY") {
        throw new AgentGateDeniedError(action, resource, result);
      }

      if (result.decision === "ESCALATE" && !allowEscalate) {
        throw new AgentGateDeniedError(action, resource, result);
      }

      const output = await originalExecute(params, executeOptions);

      if (result.decision === "ESCALATE") {
        const score = result.trust_breakdown.final_score;
        const flags = result.attack_flags.length > 0
          ? ` Flags: ${result.attack_flags.slice(0, 3).join(", ")}.`
          : "";
        return `${String(output)}\n\n[AgentGate FLAGGED: score ${score.toFixed(0)}/100.${flags} ${result.explanation}]`;
      }

      return output;
    },
  };
}

/**
 * Wrap an entire record of Vercel AI SDK tools at once.
 *
 * The tool name is used to infer the action (read/write/delete/search) unless
 * you supply an explicit actionMap.
 *
 *   const tools = guardTools(gate, {
 *     readReport: tool({ ... }),       // inferred action: "read"
 *     deleteRecord: tool({ ... }),     // inferred action: "delete"
 *     exportSummary: tool({ ... }),    // inferred action: "write"
 *   });
 */
export function guardTools<T extends ToolRecord>(
  gate: AgentGate,
  tools: T,
  options: Omit<GuardToolOptions, "action"> & {
    /** Override the inferred action for specific tools: { readReport: "read", exportSummary: "write" } */
    actionMap?: Partial<Record<keyof T, string>>;
  } = {},
): T {
  const { actionMap = {}, ...sharedOptions } = options;
  const result = {} as T;

  for (const [name, t] of Object.entries(tools) as [keyof T & string, VercelTool][]) {
    const action = (actionMap[name as keyof T] as string | undefined) ?? inferAction(name);
    result[name as keyof T] = guardTool(gate, t, {
      ...sharedOptions,
      action,
    }) as T[keyof T];
  }

  return result;
}

/**
 * Convenience: create an execute wrapper you can drop directly into a tool definition.
 *
 *   const readReport = tool({
 *     description: "Read a report",
 *     parameters: z.object({ path: z.string() }),
 *     execute: withGate(gate, "read", "path", async ({ path }) => {
 *       return fs.readFile(path, "utf-8");
 *     }),
 *   });
 */
export function withGate<TParams extends Record<string, unknown>>(
  gate: AgentGate,
  action: string,
  resourceParam: string,
  fn: (params: TParams) => Promise<unknown>,
  justification?: string,
): (params: TParams) => Promise<unknown> {
  return async (params: TParams): Promise<unknown> => {
    const resource = extractResource(params as Record<string, unknown>, resourceParam);
    await gate.authorize(action, resource, justification ?? `${action} ${resource}`);
    return fn(params);
  };
}
