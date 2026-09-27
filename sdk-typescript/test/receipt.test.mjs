/**
 * Offline verification, against receipts the Python server actually signed.
 *
 * The interesting assertions here are the negative ones. A verifier that says
 * "valid" for genuine receipts and also for altered ones is worse than no
 * verifier, because it converts an unchecked claim into a checked-looking one.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  canonicalReceiptBytes,
  flowToken,
  pyFloatString,
  verifyReceipt,
  verifyResponseMac,
} from "../dist/index.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(here, "vectors.json"), "utf8"));
const PEM = vectors.public_key_pem;
const SIGNING_KEY = "agentgate-dev-signing-key-change-in-production";

test("canonical receipt bytes match the server", () => {
  for (const v of vectors.receipts) {
    assert.equal(canonicalReceiptBytes(v.receipt).toString("utf8"), v.canonical, v.name);
  }
});

test("a whole-second timestamp keeps its .0", () => {
  // Python writes 1758888888.0 where JavaScript writes 1758888888. Roughly one
  // receipt in a thousand lands here, which is exactly often enough to reject
  // a genuine receipt in production and never in a demo.
  assert.equal(pyFloatString(1758888888.0), "1758888888.0");
  assert.equal(pyFloatString(1758888888.1234), "1758888888.1234");
});

test("genuine receipts verify against the published key", () => {
  for (const v of vectors.receipts) {
    const result = verifyReceipt(v.receipt, PEM);
    assert.equal(result.signatureValid, true, `${v.name}: ${result.signatureDetail}`);
    assert.equal(result.operationMatches, null, "no operation supplied");
    assert.equal(result.verified, true);
  }
});

test("altering any signed field breaks the signature", () => {
  const original = vectors.receipts[0].receipt;
  const tampered = [
    ["decision", { ...original, decision: "DENY" }],
    ["agent_id", { ...original, agent_id: "someone-else" }],
    ["request_id", { ...original, request_id: "req-9999" }],
    ["timestamp", { ...original, timestamp: original.timestamp + 1 }],
    ["action_ref", { ...original, action_ref: "0".repeat(64) }],
    ["nonce", { ...original, response_nonce: "00000000-0000-4000-8000-000000000000" }],
    [
      "flow",
      { ...original, flow: { confidentiality: "PUBLIC", integrity: "TRUSTED" } },
    ],
  ];
  for (const [field, receipt] of tampered) {
    const result = verifyReceipt(receipt, PEM);
    assert.equal(result.signatureValid, false, `altered ${field} still verified`);
    assert.equal(result.verified, false);
  }
});

test("a receipt with no signature does not verify", () => {
  const result = verifyReceipt({ ...vectors.receipts[0].receipt, receipt_sig: null }, PEM);
  assert.equal(result.signatureValid, false);
  assert.match(result.signatureDetail, /no Ed25519 signature/);
});

test("a different key does not verify", async () => {
  // A syntactically valid Ed25519 key that did not sign this receipt.
  const { generateKeyPairSync } = await import("node:crypto");
  const { publicKey } = generateKeyPairSync("ed25519");
  const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const result = verifyReceipt(vectors.receipts[0].receipt, pem);
  assert.equal(result.signatureValid, false);
});

test("an RSA key is rejected rather than misread", async () => {
  const { generateKeyPairSync } = await import("node:crypto");
  const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const result = verifyReceipt(vectors.receipts[0].receipt, pem);
  assert.equal(result.signatureValid, false);
  assert.match(result.signatureDetail, /not an Ed25519/);
});

test("binding: the receipt authorizes exactly one operation", () => {
  const receipt = vectors.receipts[0].receipt;
  const op = vectors.reference_operation;

  const ok = verifyReceipt(receipt, PEM, op);
  assert.equal(ok.operationMatches, true);
  assert.equal(ok.verified, true);

  const drifted = {
    ...op,
    arguments: { ...op.arguments, amount_cents: 2_500_000 },
  };
  const bad = verifyReceipt(receipt, PEM, drifted);
  assert.equal(bad.signatureValid, true, "the receipt itself is still authentic");
  assert.equal(bad.operationMatches, false, "and it does not cover this operation");
  assert.equal(bad.verified, false, "authentic but unbound is not evidence");
});

test("a receipt with no action_ref binds nothing", () => {
  const receipt = { ...vectors.receipts[0].receipt, action_ref: "" };
  const result = verifyReceipt(receipt, PEM, vectors.reference_operation);
  assert.equal(result.operationMatches, false);
  assert.match(result.operationDetail, /binds no operation/);
});

test("flow is reported in plain language", () => {
  const result = verifyReceipt(vectors.receipts[1].receipt, PEM);
  assert.deepEqual(result.flow, [
    "session had been exposed to internal material",
    "decision inputs were untrusted",
  ]);
  assert.equal(flowToken(vectors.receipts[1].receipt.flow), "INTERNAL|UNTRUSTED");
  assert.equal(flowToken(null), "");
});

test("the HMAC verifies for a holder of the shared secret", () => {
  const v = vectors.receipts[0];
  const now = v.receipt.timestamp + 10;
  assert.deepEqual(verifyResponseMac(v.receipt, SIGNING_KEY, now), {
    valid: true,
    reason: "OK",
  });
});

test("the HMAC rejects a stale or future receipt", () => {
  const v = vectors.receipts[0];
  const stale = verifyResponseMac(v.receipt, SIGNING_KEY, v.receipt.timestamp + 3600);
  assert.equal(stale.valid, false);
  assert.match(stale.reason, /RESPONSE_EXPIRED/);

  const future = verifyResponseMac(v.receipt, SIGNING_KEY, v.receipt.timestamp - 600);
  assert.equal(future.valid, false);
  assert.match(future.reason, /RESPONSE_FROM_FUTURE/);
});

test("the HMAC rejects the wrong secret", () => {
  const v = vectors.receipts[0];
  const result = verifyResponseMac(v.receipt, "not-the-key", v.receipt.timestamp + 1);
  assert.equal(result.valid, false);
  assert.equal(result.reason, "SIGNATURE_MISMATCH");
});
