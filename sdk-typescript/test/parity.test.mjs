/**
 * The TypeScript implementation must agree with the Python one byte for byte.
 *
 * Every expected value in test/vectors.json was produced by the code the
 * server actually runs (see generate_vectors.py). A test that only checked
 * this implementation against itself would pass happily while the two drifted,
 * and the symptom in production is not a crash — it is valid operations being
 * refused, or drifted ones accepted.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  ActionRefError,
  MAX_ARGUMENTS_BYTES,
  canonicalJson,
  computeActionRef,
  matches,
  normalizeResource,
} from "../dist/index.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(here, "vectors.json"), "utf8"));

test("resource normalization matches the server", () => {
  for (const v of vectors.operations) {
    assert.equal(
      normalizeResource(v.operation.resource),
      v.normalized_resource,
      `${v.name}: normalized "${v.operation.resource}"`,
    );
  }
});

test("canonical descriptor bytes match the server", () => {
  for (const v of vectors.operations) {
    const op = v.operation;
    const descriptor = {
      v: vectors.descriptor_version,
      agent_id: op.agent_id,
      action: op.action.toLowerCase(),
      resource: normalizeResource(op.resource),
      arguments: op.arguments ?? {},
      policy_version: op.policy_version ?? "",
    };
    assert.equal(canonicalJson(descriptor), v.descriptor_json, v.name);
  }
});

test("action_ref matches the server", () => {
  for (const v of vectors.operations) {
    assert.equal(computeActionRef(v.operation), v.action_ref, v.name);
  }
});

test("key order in arguments does not change the digest", () => {
  const a = computeActionRef({
    agent_id: "a",
    action: "transfer",
    resource: "/p",
    arguments: { amount: 1, to: "x", memo: "m" },
  });
  const b = computeActionRef({
    agent_id: "a",
    action: "transfer",
    resource: "/p",
    arguments: { memo: "m", to: "x", amount: 1 },
  });
  assert.equal(a, b);
});

test("changing any bound field changes the digest", () => {
  const base = {
    agent_id: "billing",
    action: "transfer",
    resource: "/payments/outbound",
    arguments: { amount_cents: 25000, to: "acct_9931" },
  };
  const ref = computeActionRef(base);

  const drifted = [
    { ...base, agent_id: "billing2" },
    { ...base, action: "refund" },
    { ...base, resource: "/payments/internal" },
    { ...base, arguments: { amount_cents: 25001, to: "acct_9931" } },
    { ...base, arguments: { amount_cents: 25000, to: "acct_0002" } },
    { ...base, arguments: { amount_cents: 25000, to: "acct_9931", extra: 1 } },
    { ...base, policy_version: "v2" },
  ];
  for (const op of drifted) {
    assert.notEqual(computeActionRef(op), ref, JSON.stringify(op));
  }
});

test("a string amount is not the same operation as a numeric one", () => {
  // The confused-deputy case that looks equal to a careless comparison.
  const a = computeActionRef({
    agent_id: "billing",
    action: "transfer",
    resource: "/p",
    arguments: { amount: 25000 },
  });
  const b = computeActionRef({
    agent_id: "billing",
    action: "transfer",
    resource: "/p",
    arguments: { amount: "25000" },
  });
  assert.notEqual(a, b);
});

test("matches() fails closed", () => {
  const op = { agent_id: "a", action: "read", resource: "/x" };
  assert.equal(matches(computeActionRef(op), op), true);
  assert.equal(matches("", op), false, "no reference means no binding");
  assert.equal(matches("deadbeef", op), false);
  assert.equal(
    matches("deadbeef", { ...op, arguments: { bad: Infinity } }),
    false,
    "uncanonicalizable operations are refused, not thrown past the caller",
  );
});

test("oversized arguments are refused rather than truncated", () => {
  const big = { blob: "x".repeat(MAX_ARGUMENTS_BYTES) };
  assert.throws(
    () => computeActionRef({ agent_id: "a", action: "w", resource: "/x", arguments: big }),
    ActionRefError,
  );
});

test("NaN and Infinity have no canonical form", () => {
  for (const bad of [NaN, Infinity, -Infinity]) {
    assert.throws(() => canonicalJson({ n: bad }), ActionRefError);
  }
});

test("arguments must be an object", () => {
  assert.throws(
    () =>
      computeActionRef({
        agent_id: "a",
        action: "w",
        resource: "/x",
        arguments: [1, 2],
      }),
    ActionRefError,
  );
});
