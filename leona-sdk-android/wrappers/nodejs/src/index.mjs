import crypto from "node:crypto";

const DEFAULT_TIMEOUT_MS = 5000;
const BOX_ID_PATTERN = /\b(?:01[A-Z0-9]{10,}|box_[A-Za-z0-9_-]{8,})\b/g;
const SENSITIVE_KEY_PATTERN =
  /(authorization|secret|token|signature|credential|deviceid|installid|androidid|serial|rawboxid|rawappkey|appkeysecret)/i;

export class LeonaTransportError extends Error {
  constructor(message, { status, body, diagnostic } = {}) {
    super(message);
    this.name = "LeonaTransportError";
    this.status = status;
    this.body = body;
    this.diagnostic = diagnostic;
  }
}

export function sha256Hex(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

export function hmacSha256Base64Url(secretKey, text) {
  return crypto.createHmac("sha256", secretKey).update(text).digest("base64url");
}

export function randomNonce(bytes = 16) {
  return crypto.randomBytes(bytes).toString("base64url");
}

export function buildSignedRequest({ secretKey, method, path, body = "", timestamp, nonce }) {
  const requestBody = typeof body === "string" ? body : JSON.stringify(body);
  const bodySha256 = sha256Hex(requestBody);
  const normalizedMethod = method.toUpperCase();
  const signingText = `backend-v2\n${normalizedMethod}\n${path}\n${timestamp}\n${nonce}\n${bodySha256}`;
  return {
    method: normalizedMethod,
    path,
    body: requestBody,
    bodySha256,
    headers: {
      Authorization: `Bearer ${secretKey}`,
      "Content-Type": "application/json",
      "X-Leona-Timestamp": timestamp,
      "X-Leona-Nonce": nonce,
      "X-Leona-Signature": hmacSha256Base64Url(secretKey, signingText),
    },
  };
}

export function redact(value) {
  if (value == null) return value;
  if (typeof value === "string") return value.replace(BOX_ID_PATTERN, "[redacted-box-id]");
  if (Array.isArray(value)) return value.map((item) => redact(item));
  if (typeof value !== "object") return value;

  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [
      key,
      SENSITIVE_KEY_PATTERN.test(key) ? "[redacted]" : redact(item),
    ]),
  );
}

export function createLeonaClient({
  baseUrl,
  secretKey,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  fetchImpl = globalThis.fetch,
  now = () => Date.now().toString(),
  nonceFactory = randomNonce,
} = {}) {
  if (!baseUrl || typeof baseUrl !== "string") {
    throw new TypeError("baseUrl is required");
  }
  if (!secretKey || typeof secretKey !== "string") {
    throw new TypeError("secretKey is required");
  }
  if (typeof fetchImpl !== "function") {
    throw new TypeError("fetch implementation is required");
  }

  const root = validateBaseUrl(baseUrl);

  async function request(method, path, payload) {
    const hasBody = payload !== undefined;
    const signed = buildSignedRequest({
      secretKey,
      method,
      path,
      body: hasBody ? payload : "",
      timestamp: now(),
      nonce: nonceFactory(),
    });
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetchImpl(`${root}${path}`, {
        method,
        headers: signed.headers,
        body: hasBody ? signed.body : undefined,
        signal: controller.signal,
      });
      const text = await response.text();
      const parsed = parseJsonOrText(redactSecretValue(text, secretKey));
      if (!response.ok) {
        throw new LeonaTransportError(`Leona request failed: HTTP ${response.status}`, {
          status: response.status,
          body: redact(parsed),
          diagnostic: "transport_http_error",
        });
      }
      return parsed;
    } catch (error) {
      if (error instanceof LeonaTransportError) throw error;
      throw new LeonaTransportError(`Leona request failed: ${redactSecretValue(redact(error.message), secretKey)}`, {
        diagnostic: error.name === "AbortError" ? "transport_timeout" : "transport_error",
      });
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    verdict(boxId) {
      return request("POST", "/v1/verdict", { boxId });
    },
    evidenceReport(boxId) {
      return request("GET", `/v1/internal/private/evidence-reports/${encodeURIComponent(boxId)}`);
    },
    supportBundle(boxId) {
      return request(
        "GET",
        `/v1/internal/private/evidence-reports/${encodeURIComponent(boxId)}/support-bundle`,
      );
    },
    submitFeedback(input) {
      return request("POST", "/v1/internal/private/evidence-feedback", input);
    },
    redact,
  };
}

function validateBaseUrl(value) {
  const normalized = value.trim().replace(/\/+$/, "");
  let url;
  try {
    url = new URL(normalized);
  } catch (error) {
    throw new TypeError("baseUrl must be a valid absolute URL");
  }

  const https = url.protocol === "https:";
  const loopbackHttp = url.protocol === "http:" && isLoopbackHost(url.hostname);
  if (!url.hostname) {
    throw new TypeError("baseUrl must include a host");
  }
  if (!https && !loopbackHttp) {
    throw new TypeError(
      "baseUrl must use HTTPS; HTTP is only allowed for loopback test endpoints",
    );
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new TypeError(
      "baseUrl must not contain user-info, query, or fragment components",
    );
  }
  return normalized;
}

function isLoopbackHost(hostname) {
  return hostname === "127.0.0.1" || hostname.toLowerCase() === "localhost" ||
    hostname === "::1" || hostname === "[::1]";
}

function parseJsonOrText(text) {
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function redactSecretValue(text, secretKey) {
  if (!text || !secretKey) return text;
  return String(text).split(secretKey).join("[redacted-secret]");
}
