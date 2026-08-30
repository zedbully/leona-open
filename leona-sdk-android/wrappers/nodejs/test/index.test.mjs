import assert from "node:assert/strict";
import test from "node:test";

import { createLeonaClient, redact } from "../src/index.mjs";

const BOX_ID = "box_test_000000000000000000";

function transportFor(response = { status: 200, body: '{"evidenceOnly":true}' }) {
  const calls = [];
  return {
    calls,
    execute: async (request) => {
      calls.push(request);
      return response;
    },
  };
}

test("requires a caller-owned Leo transport", () => {
  assert.throws(
    () => createLeonaClient(),
    /Leo crypto backend transport is required/,
  );
  assert.throws(
    () => createLeonaClient({ transport: { execute: "not-a-function" } }),
    /Leo crypto backend transport is required/,
  );
});

test("client hands logical request fields to Leo transport", async () => {
  const transport = transportFor();
  const client = createLeonaClient({ transport });
  const result = await client.verdict(BOX_ID);

  assert.equal(result.evidenceOnly, true);
  assert.equal(transport.calls.length, 1);
  assert.equal(transport.calls[0].method, "POST");
  assert.equal(transport.calls[0].path, "/v1/verdict");
  assert.equal(transport.calls[0].contentType, "application/json");
  assert.deepEqual(transport.calls[0].protectedHeaders, {});
  assert.equal(transport.calls[0].body, JSON.stringify({ boxId: BOX_ID }));
});

test("all wrapper operations use the same Leo transport boundary", async () => {
  const transport = transportFor({ status: 200, body: '{"accepted":true}' });
  const client = createLeonaClient({ transport });

  await client.evidenceReport(BOX_ID);
  await client.supportBundle(BOX_ID);
  await client.submitFeedback({
    boxId: BOX_ID,
    label: "false_positive",
    customerReason: "integration smoke",
  });

  assert.deepEqual(
    transport.calls.map(({ method, path }) => `${method} ${path}`),
    [
      `GET /v1/internal/private/evidence-reports/${encodeURIComponent(BOX_ID)}`,
      `GET /v1/internal/private/evidence-reports/${encodeURIComponent(BOX_ID)}/support-bundle`,
      "POST /v1/internal/private/evidence-feedback",
    ],
  );
});

test("opened Leo HTTP errors become transport errors without business decisions", async () => {
  const client = createLeonaClient({
    transport: transportFor({ status: 401, body: '{"error":"unauthorized"}' }),
  });

  await assert.rejects(
    () => client.evidenceReport(BOX_ID),
    (error) => {
      assert.equal(error.name, "LeonaTransportError");
      assert.equal(error.status, 401);
      assert.equal(error.diagnostic, "transport_http_error");
      assert.deepEqual(error.body, { error: "unauthorized" });
      return true;
    },
  );
});

test("redacts secrets, raw identifiers, and complete BoxIds", () => {
  const output = redact({
    secretKey: "test_secret_do_not_use",
    authorization: "Bearer test_secret_do_not_use",
    nested: {
      boxId: BOX_ID,
      deviceId: "raw-device-id",
      note: `seen ${BOX_ID} in a ticket`,
    },
  });

  assert.equal(output.secretKey, "[redacted]");
  assert.equal(output.authorization, "[redacted]");
  assert.equal(output.nested.boxId, "[redacted-box-id]");
  assert.equal(output.nested.deviceId, "[redacted]");
  assert.equal(output.nested.note, "seen [redacted-box-id] in a ticket");
});

test("transport timeout is fail closed", async () => {
  const client = createLeonaClient({
    timeoutMs: 10,
    transport: { execute: () => new Promise(() => {}) },
  });

  await assert.rejects(
    () => client.verdict(BOX_ID),
    (error) => {
      assert.equal(error.name, "LeonaTransportError");
      assert.equal(error.diagnostic, "transport_error");
      return true;
    },
  );
});
