import crypto from "node:crypto";
import { pathToFileURL } from "node:url";

const DEFAULT_ENDPOINT = "https://leona.xiyanshan.com/v1/verdict";

function requireEnv(name) {
  const value = process.env[name];
  if (!value || value.trim() === "") {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value.trim();
}

export function buildSignedRequest({ secret, boxId, endpoint, timestamp, nonce }) {
  const body = JSON.stringify({ boxId });
  const bodySha256 = crypto.createHash("sha256").update(body).digest("hex");
  const signingText = `${timestamp}\n${nonce}\n${bodySha256}`;
  const signature = crypto
    .createHmac("sha256", secret)
    .update(signingText)
    .digest("base64url");
  return {
    endpoint,
    body,
    bodySha256,
    headers: {
      "Authorization": `Bearer ${secret}`,
      "Content-Type": "application/json",
      "X-Leona-Timestamp": timestamp,
      "X-Leona-Nonce": nonce,
      "X-Leona-Signature": signature,
    },
  };
}

export function validateEndpoint(endpoint, { allowLoopbackHttp = false } = {}) {
  let parsed;
  try {
    parsed = new URL(endpoint);
  } catch {
    throw new Error("LEONA_ENDPOINT must be an absolute /v1/verdict URL");
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== "/v1/verdict") {
    throw new Error("LEONA_ENDPOINT must not contain credentials, query, fragment, or another path");
  }
  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  const loopback = ["localhost", "127.0.0.1", "::1"].includes(hostname);
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && loopback && allowLoopbackHttp)) {
    throw new Error("LEONA_ENDPOINT must use HTTPS (or explicit loopback HTTP for local tests)");
  }
  return endpoint;
}

async function main() {
  const secret = requireEnv("LEONA_SECRET_KEY");
  const boxId = requireEnv("BOX_ID");
  const endpoint = validateEndpoint(process.env.LEONA_ENDPOINT || DEFAULT_ENDPOINT, {
    allowLoopbackHttp: process.env.LEONA_ALLOW_LOOPBACK_HTTP === "1",
  });
  const timestamp = process.env.LEONA_TIMESTAMP || Date.now().toString();
  const nonce = process.env.LEONA_NONCE || crypto.randomBytes(16).toString("base64url");
  const signed = buildSignedRequest({ secret, boxId, endpoint, timestamp, nonce });

  if (process.env.LEONA_DRY_RUN === "1") {
    console.log(JSON.stringify({
      ...signed,
      body: "[REDACTED]",
      headers: {
        ...signed.headers,
        Authorization: "Bearer [REDACTED]",
        "X-Leona-Signature": "[REDACTED]",
      },
    }, null, 2));
    return;
  }

  const response = await fetch(endpoint, {
    method: "POST",
    headers: signed.headers,
    body: signed.body,
    redirect: "manual",
  });

  const text = await response.text();
  if (!response.ok) {
    throw new Error(`Leona query failed: HTTP ${response.status}\n${text}`);
  }
  console.log(text);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
