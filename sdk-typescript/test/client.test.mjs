/**
 * The client's one real job: make the dispatch-time check impossible to skip.
 *
 * These tests run against a stub server rather than a live one, because what
 * is being tested is not the verdict — it is what the client does with a
 * verdict when the operation underneath it has changed. A live server cannot
 * produce that case on demand; a stub can produce nothing else.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  AgentGate,
  AgentGateBindingError,
  AgentGateDeniedError,
  AgentGateUnboundError,
  computeActionRef,
} from "../dist/index.mjs";

const AGENT = "billing-agent";

/** Install a fetch stub and return the recorded request bodies. */
function stubServer(handler) {
  const calls = [];
  globalThis.fetch = async (url, options = {}) => {
    const body = options.body ? JSON.parse(options.body) : null;
    calls.push({ url: String(url), body });
    const response = handler(String(url), body);
    return {
      ok: response.ok !== false,
      status: response.status ?? 200,
      json: async () => response.json,
      text: async () => JSON.stringify(response.json),
    };
  };
  return calls;
}

/** A PERMIT bound to exactly the operation that was asked about. */
function permitFor(action, resource, args) {
  return {
    request_id: "req-1",
    agent_id: AGENT,
    action,
    resource,
    decision: "PERMIT",
    explanation: "within declared scope",
    attack_flags: [],
    timestamp: 1758888888.123,
    trust_breakdown: {
      identity_score: 100,
      delegation_score: 100,
      purpose_alignment_score: 90,
      behavioral_score: 95,
      final_score: 96,
      resource_sensitivity: "HIGH",
      threshold_required: 70,
    },
    action_ref: computeActionRef({ agent_id: AGENT, action, resource, arguments: args }),
    response_nonce: "nonce-1",
    response_sig: "mac-1",
    receipt_sig: "sig-1",
    key_id: "key-1",
    flow: { confidentiality: "CONFIDENTIAL", integrity: "TRUSTED", sources: [] },
  };
}

function connect(overrides = {}) {
  const gate = new AgentGate({ url: "http://stub", ...overrides });
  gate.load(AGENT, "token-1");
  return gate;
}

const originalFetch = globalThis.fetch;

test.afterEach(() => {
  globalThis.fetch = originalFetch;
});

test("authorize sends the arguments, not just the action and resource", async () => {
  const args = { amount_cents: 25000, to: "acct_9931" };
  const calls = stubServer(() => ({
    json: permitFor("transfer", "/payments/outbound", args),
  }));

  await connect().authorize("transfer", "/payments/outbound", { arguments: args });

  assert.deepEqual(calls[0].body.arguments, args);
  // Without this the receipt would bind "a transfer to /payments/outbound" and
  // leave the amount free to change afterwards, which is the whole hole.
});

test("run() executes when the dispatch matches the receipt", async () => {
  const args = { amount_cents: 25000, to: "acct_9931" };
  stubServer(() => ({ json: permitFor("transfer", "/payments/outbound", args) }));

  let executed = false;
  const out = await connect().run(
    "transfer",
    "/payments/outbound",
    { arguments: args },
    () => {
      executed = true;
      return "sent";
    },
  );

  assert.equal(executed, true);
  assert.equal(out, "sent");
});

test("run() refuses when the amount changed after authorization", async () => {
  // The server authorized 250 EUR. Something rewrote the amount between the
  // decision and the dispatch — a rewritten tool argument, a poisoned retry,
  // a bug. The receipt still verifies; it just does not cover this.
  const authorized = { amount_cents: 25000, to: "acct_9931" };
  stubServer(() => ({ json: permitFor("transfer", "/payments/outbound", authorized) }));

  const gate = connect();
  const result = await gate.authorize("transfer", "/payments/outbound", {
    arguments: authorized,
  });

  let executed = false;
  assert.throws(
    () => {
      gate.checkBinding(result, {
        action: "transfer",
        resource: "/payments/outbound",
        arguments: { amount_cents: 2_500_000, to: "acct_0002" },
      });
      executed = true;
    },
    AgentGateBindingError,
  );
  assert.equal(executed, false, "the call must not have run");
});

test("the binding error names both digests", async () => {
  const args = { amount_cents: 1 };
  stubServer(() => ({ json: permitFor("transfer", "/p", args) }));
  const gate = connect();
  const result = await gate.authorize("transfer", "/p", { arguments: args });

  try {
    gate.checkBinding(result, { action: "transfer", resource: "/p", arguments: { amount_cents: 2 } });
    assert.fail("expected a binding error");
  } catch (err) {
    assert.ok(err instanceof AgentGateBindingError);
    assert.equal(err.expected, result.action_ref);
    assert.notEqual(err.actual, result.action_ref);
    assert.match(err.message, /authorized:/);
    assert.match(err.message, /supplied:/);
  }
});

test("a PERMIT carrying no action_ref is refused by default", async () => {
  stubServer(() => {
    const r = permitFor("transfer", "/p", {});
    r.action_ref = null;
    return { json: r };
  });

  await assert.rejects(
    () => connect().authorize("transfer", "/p", { arguments: {} }),
    AgentGateUnboundError,
  );
});

test("requireBinding: false accepts an unbound decision", async () => {
  stubServer(() => {
    const r = permitFor("transfer", "/p", {});
    r.action_ref = null;
    return { json: r };
  });

  const result = await connect({ requireBinding: false }).authorize("transfer", "/p", {});
  assert.equal(result.decision, "PERMIT");
  assert.equal(result.action_ref, null);
});

test("a DENY throws before anything can dispatch", async () => {
  stubServer(() => ({
    json: {
      ...permitFor("transfer", "/p", {}),
      decision: "DENY",
      explanation: "destination not declared",
      attack_flags: ["FLOW_UNDECLARED_DESTINATION"],
    },
  }));

  let executed = false;
  await assert.rejects(
    () => connect().run("transfer", "/p", {}, () => (executed = true)),
    AgentGateDeniedError,
  );
  assert.equal(executed, false);
});

test("redeem sends back exactly what the server issued", async () => {
  const args = { amount_cents: 25000 };
  const calls = stubServer((url) =>
    url.endsWith("/receipts/redeem")
      ? { json: { status: "REDEEMED", request_id: "req-1" } }
      : { json: permitFor("transfer", "/payments/outbound", args) },
  );

  const gate = connect();
  const result = await gate.authorize("transfer", "/payments/outbound", { arguments: args });
  const redeemed = await gate.redeem(result);

  assert.equal(redeemed.status, "REDEEMED");
  const sent = calls[1].body;
  assert.equal(sent.nonce, result.response_nonce);
  assert.equal(sent.mac, result.response_sig);
  assert.equal(sent.action_ref, result.action_ref);
  assert.equal(sent.flow, "CONFIDENTIAL|TRUSTED", "the flow is signed, so it has to come back");
});

test("authorize refuses before the network when no agent is loaded", async () => {
  let reached = false;
  stubServer(() => {
    reached = true;
    return { json: {} };
  });

  await assert.rejects(() => new AgentGate("http://stub").authorize("read", "/x"));
  assert.equal(reached, false);
});
