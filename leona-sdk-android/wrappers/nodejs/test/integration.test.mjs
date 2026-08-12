import assert from "node:assert/strict";
import crypto from "node:crypto";
import { createServer } from "node:http";
import test from "node:test";

import { createLeonaClient, hmacSha256Base64Url, sha256Hex } from "../src/index.mjs";

const SECRET = "test_secret_do_not_use";
const BOX_ID = "box_test_000000000000000000";

test("client completes signed mock HTTP integration flow", async () => {
  const seen = [];
  const server = createServer(async (req, res) => {
    try {
      const body = await readBody(req);
      verifySignedRequest(req, body);
      seen.push({ method: req.method, url: req.url, body });

      if (req.method === "POST" && req.url === "/v1/verdict") {
        assert.deepEqual(JSON.parse(body), { boxId: BOX_ID });
        writeJson(res, { boxIdHint: "box_...0000", evidenceOnly: true });
        return;
      }
      if (req.method === "GET" && req.url === `/v1/internal/private/evidence-reports/${BOX_ID}`) {
        writeJson(res, { report: { boxIdHint: "box_...0000" } });
        return;
      }
      if (
        req.method === "GET" &&
        req.url === `/v1/internal/private/evidence-reports/${BOX_ID}/support-bundle`
      ) {
        writeJson(res, { bundle: { format: "leona.customer-support-bundle.v1" } });
        return;
      }
      if (req.method === "POST" && req.url === "/v1/internal/private/evidence-feedback") {
        assert.deepEqual(JSON.parse(body), {
          boxId: BOX_ID,
          label: "false_positive",
          customerReason: "integration smoke",
        });
        writeJson(res, { accepted: true });
        return;
      }

      res.writeHead(404, { "Content-Type": "application/json" });
      res.end('{"error":"not found"}');
    } catch (error) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: error.message }));
    }
  });

  await listen(server);
  try {
    const address = server.address();
    const client = createLeonaClient({
      baseUrl: `http://127.0.0.1:${address.port}`,
      secretKey: SECRET,
      now: () => "1700000000000",
      nonceFactory: () => "nonce_for_dry_run",
    });

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
  } finally {
    await close(server);
  }

  assert.deepEqual(
    seen.map((request) => `${request.method} ${request.url}`),
    [
      "POST /v1/verdict",
      `GET /v1/internal/private/evidence-reports/${BOX_ID}`,
      `GET /v1/internal/private/evidence-reports/${BOX_ID}/support-bundle`,
      "POST /v1/internal/private/evidence-feedback",
    ],
  );
});

function verifySignedRequest(req, body) {
  assert.equal(req.headers.authorization, `Bearer ${SECRET}`);
  assert.equal(req.headers["content-type"], "application/json");
  assert.equal(req.headers["x-leona-timestamp"], "1700000000000");
  assert.equal(req.headers["x-leona-nonce"], "nonce_for_dry_run");

  const bodyHash = sha256Hex(body);
  assert.equal(bodyHash, crypto.createHash("sha256").update(body).digest("hex"));
  assert.equal(
    req.headers["x-leona-signature"],
    hmacSha256Base64Url(
      SECRET,
      `backend-v2\n${req.method}\n${req.url}\n1700000000000\nnonce_for_dry_run\n${bodyHash}`,
    ),
  );
}

function writeJson(res, payload) {
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify(payload));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}
