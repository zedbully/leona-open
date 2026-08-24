import assert from "node:assert/strict";
import test from "node:test";

import {
  buildSignedRequest,
  createLeonaClient,
  hmacSha256Base64Url,
  redact,
  sha256Hex,
} from "../src/index.mjs";

test("builds the shared fixed signature fixture", () => {
  const signed = buildSignedRequest({
    secretKey: "test_secret_do_not_use",
    method: "POST",
    path: "/v1/verdict",
    body: { boxId: "box_test_000000000000000000" },
    timestamp: "1700000000000",
    nonce: "nonce_for_dry_run",
  });

  assert.equal(signed.body, '{"boxId":"box_test_000000000000000000"}');
  assert.equal(
    signed.bodySha256,
    "c7aba2a73265ed90feeaa0eb8d8b35591dbc157e15ac1122b6bec17d00da430d",
  );
  assert.equal(
    signed.headers["X-Leona-Signature"],
    "xm_a5DaT482f2Nv_hewtgbB3cm43eg2-wopU4AxH928",
  );
});

test("backend signatures are bound to method and path", () => {
  const shared = {
    secretKey: "test_secret_do_not_use",
    body: { boxId: "box_test_000000000000000000" },
    timestamp: "1700000000000",
    nonce: "nonce_for_dry_run",
  };
  const verdict = buildSignedRequest({ ...shared, method: "POST", path: "/v1/verdict" });
  const report = buildSignedRequest({
    ...shared,
    method: "GET",
    path: "/v1/internal/private/evidence-reports/box_test_000000000000000000",
  });
  assert.notEqual(verdict.headers["X-Leona-Signature"], report.headers["X-Leona-Signature"]);
});

test("signing helpers are deterministic", () => {
  assert.equal(sha256Hex("body"), "230d8358dc8e8890b4c58deeb62912ee2f20357ae92a5cc861b98e68fe31acb5");
  assert.equal(hmacSha256Base64Url("secret", "text"), "L0Q2hVkpAOYZ8vOyNQw8ilc44ueia8miRNM5PDzWq9Y");
});

test("client calls verdict with signed backend-only headers", async () => {
  const calls = [];
  const client = createLeonaClient({
    baseUrl: "https://api.example.leona/",
    secretKey: "test_secret_do_not_use",
    now: () => "1700000000000",
    nonceFactory: () => "nonce_for_dry_run",
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      return new Response('{"boxIdHint":"box_...0000","evidence":[]}', { status: 200 });
    },
  });

  const result = await client.verdict("box_test_000000000000000000");
  assert.equal(result.boxIdHint, "box_...0000");
  assert.equal(calls[0].url, "https://api.example.leona/v1/verdict");
  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[0].init.headers.Authorization, "Bearer test_secret_do_not_use");
  assert.equal(calls[0].init.headers["X-Leona-Timestamp"], "1700000000000");
  assert.equal(calls[0].init.headers["X-Leona-Nonce"], "nonce_for_dry_run");
});

test("rejects remote plaintext wrapper endpoints", () => {
  assert.throws(
    () => createLeonaClient({
      baseUrl: "http://api.example.leona",
      secretKey: "test_secret_do_not_use",
    }),
    /baseUrl must use HTTPS/,
  );
});

test("redacts secrets, raw identifiers, and complete BoxIds", () => {
  const output = redact({
    secretKey: "test_secret_do_not_use",
    authorization: "Bearer test_secret_do_not_use",
    nested: {
      boxId: "01ABCDEFGHJKL1234567890",
      deviceId: "raw-device-id",
      note: "seen box_test_000000000000000000 in a ticket",
    },
  });

  assert.equal(output.secretKey, "[redacted]");
  assert.equal(output.authorization, "[redacted]");
  assert.equal(output.nested.boxId, "[redacted-box-id]");
  assert.equal(output.nested.deviceId, "[redacted]");
  assert.equal(output.nested.note, "seen [redacted-box-id] in a ticket");
});

test("http errors become transport errors without leaking the secret", async () => {
  const client = createLeonaClient({
    baseUrl: "https://api.example.leona",
    secretKey: "test_secret_do_not_use",
    fetchImpl: async () =>
      new Response('{"error":"bad secret test_secret_do_not_use"}', { status: 401 }),
  });

  await assert.rejects(
    () => client.evidenceReport("box_test_000000000000000000"),
    (error) => {
      assert.equal(error.name, "LeonaTransportError");
      assert.equal(error.status, 401);
      assert.equal(error.diagnostic, "transport_http_error");
      assert.doesNotMatch(JSON.stringify(error), /test_secret_do_not_use/);
      return true;
    },
  );
});
