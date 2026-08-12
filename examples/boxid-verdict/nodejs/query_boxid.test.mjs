import assert from "node:assert/strict";
import test from "node:test";

import { buildSignedRequest, validateEndpoint } from "./query_boxid.mjs";

test("fixed dry-run signature", () => {
  const signed = buildSignedRequest({
    secret: "test_secret_do_not_use",
    boxId: "123e4567-e89b-42d3-a456-426614174000",
    endpoint: "https://leona.xiyanshan.com/v1/verdict",
    timestamp: "1700000000000",
    nonce: "nonce_for_dry_run",
  });

  assert.equal(signed.body, '{"boxId":"123e4567-e89b-42d3-a456-426614174000"}');
  assert.equal(
    signed.bodySha256,
    "7ce622a9473ffbe7ed390c57efa3705747981e316ace1fa56000072f20ac7958",
  );
  assert.equal(
    signed.headers["X-Leona-Signature"],
    "flTDOGc3Xu5CXjzgeMWnyd1GF0O5X6VXtMbhSgsLU7Y",
  );
});

test("endpoint validation is fail closed", () => {
  for (const endpoint of [
    "file:///etc/passwd",
    "https://user:password@example.invalid/v1/verdict",
    "https://example.invalid/v1/verdict?secret=value",
    "https://example.invalid/other",
    "http://example.invalid/v1/verdict",
  ]) {
    assert.throws(() => validateEndpoint(endpoint));
  }
  const loopback = "http://127.0.0.1:18080/v1/verdict";
  assert.throws(() => validateEndpoint(loopback));
  assert.equal(validateEndpoint(loopback, { allowLoopbackHttp: true }), loopback);
});

test("dry-run representation can redact request material", () => {
  const signed = buildSignedRequest({
    secret: "test_secret_do_not_use",
    boxId: "123e4567-e89b-42d3-a456-426614174000",
    endpoint: "https://leona.xiyanshan.com/v1/verdict",
    timestamp: "1700000000000",
    nonce: "nonce_for_dry_run",
  });
  const output = JSON.stringify({
    ...signed,
    body: "[REDACTED]",
    headers: {
      ...signed.headers,
      Authorization: "Bearer [REDACTED]",
      "X-Leona-Signature": "[REDACTED]",
    },
  });
  assert.doesNotMatch(output, /test_secret_do_not_use|123e4567-e89b-42d3-a456-426614174000/);
  assert.ok(!output.includes(signed.headers["X-Leona-Signature"]));
});
