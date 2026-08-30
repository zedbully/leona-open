import assert from "node:assert/strict";
import test from "node:test";

import { createLeonaClient } from "../src/index.mjs";

const BOX_ID = "box_test_000000000000000000";

test("client completes a Leo transport integration flow", async () => {
  const seen = [];
  const transport = {
    async execute(request) {
      seen.push(request);
      if (request.method === "POST" && request.path === "/v1/verdict") {
        assert.deepEqual(JSON.parse(request.body), { boxId: BOX_ID });
        return { status: 200, body: '{"boxIdHint":"box_...0000","evidenceOnly":true}' };
      }
      if (request.method === "GET" && request.path.endsWith("/support-bundle")) {
        return { status: 200, body: '{"bundle":{"format":"leona.customer-support-bundle.v1"}}' };
      }
      if (request.method === "GET") {
        return { status: 200, body: '{"report":{"boxIdHint":"box_...0000"}}' };
      }
      assert.deepEqual(JSON.parse(request.body), {
        boxId: BOX_ID,
        label: "false_positive",
        customerReason: "integration smoke",
      });
      return { status: 200, body: '{"accepted":true}' };
    },
  };

  const client = createLeonaClient({ transport });
  assert.equal((await client.verdict(BOX_ID)).evidenceOnly, true);
  assert.equal((await client.evidenceReport(BOX_ID)).report.boxIdHint, "box_...0000");
  assert.equal(
    (await client.supportBundle(BOX_ID)).bundle.format,
    "leona.customer-support-bundle.v1",
  );
  assert.equal(
    (await client.submitFeedback({
      boxId: BOX_ID,
      label: "false_positive",
      customerReason: "integration smoke",
    })).accepted,
    true,
  );

  assert.deepEqual(
    seen.map(({ method, path }) => `${method} ${path}`),
    [
      "POST /v1/verdict",
      `GET /v1/internal/private/evidence-reports/${encodeURIComponent(BOX_ID)}`,
      `GET /v1/internal/private/evidence-reports/${encodeURIComponent(BOX_ID)}/support-bundle`,
      "POST /v1/internal/private/evidence-feedback",
    ],
  );
});
