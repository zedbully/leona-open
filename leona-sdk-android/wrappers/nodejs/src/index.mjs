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

/**
 * Construct an evidence-only client around a caller-owned Leo transport.
 * The transport must seal every logical field/body with Leo, use HTTPS for
 * its outer exchange, and open/authenticate the response before returning it.
 * There is intentionally no fetch, SecretKey, HMAC, or plaintext fallback in
 * this public wrapper.
 */
export function createLeonaClient({
  transport,
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  if (!transport || typeof transport.execute !== "function") {
    throw new TypeError("Leo crypto backend transport is required");
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
    throw new TypeError("timeoutMs must be a positive safe integer");
  }

  async function request(method, path, payload) {
    const hasBody = payload !== undefined;
    const body = hasBody ? JSON.stringify(payload) : "";
    let response;
    try {
      response = await withTimeout(
        transport.execute({
          method,
          path,
          contentType: "application/json",
          protectedHeaders: {},
          body,
        }),
        timeoutMs,
      );
    } catch (error) {
      if (error instanceof LeonaTransportError) throw error;
      throw new LeonaTransportError(
        `Leona request failed: ${redactSecretValue(error?.message || String(error), "")}`,
        { diagnostic: error?.name === "AbortError" ? "transport_timeout" : "transport_error" },
      );
    }

    if (!response || !Number.isInteger(response.status)) {
      throw new LeonaTransportError("Leona transport returned an invalid response", {
        diagnostic: "transport_protocol_error",
      });
    }
    const text = await responseBodyText(response.body);
    const parsed = parseJsonOrText(text);
    if (response.status < 200 || response.status >= 300) {
      throw new LeonaTransportError(`Leona request failed after authenticated Leo response: HTTP ${response.status}`, {
        status: response.status,
        body: redact(parsed),
        diagnostic: "transport_http_error",
      });
    }
    return parsed;
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

async function withTimeout(promise, timeoutMs) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("Leo transport timeout")), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function responseBodyText(body) {
  if (body == null) return "";
  if (typeof body === "string") return body;
  if (body instanceof Uint8Array) return new TextDecoder().decode(body);
  return String(body);
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
