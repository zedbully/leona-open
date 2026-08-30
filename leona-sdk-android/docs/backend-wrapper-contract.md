# Leona Backend Wrapper Contract

This contract defines the public-safe shape for customer backend wrappers. It is
for server-side code only. Android SDKs collect and report evidence; customer
backends own all final business decisions.

## Scope

Wrappers may help a customer backend:

- delegate Leona API requests to the paired Leo crypto provider
- query a BoxId evidence report through `/v1/verdict`
- fetch customer evidence reports or support bundles when the private customer
  API is enabled for that tenant
- submit customer feedback labels
- redact Leona values before logs, support tickets, or analytics export

Wrappers must not:

- run inside an Android app
- embed tenant SecretKey, provider credential, token, or real AppKey secret
- output business `allow`, `reject`, `block`, or `deny` decisions
- persist full BoxIds, raw device IDs, install IDs, serials, Android IDs, raw
  build fingerprints, or provider tokens by default
- create a direct HTTP client or a plaintext/HMAC-only fallback

## Shared Leo transport boundary

All backend wrapper requests must go through the external Leo provider. The
provider owns key/bootstrap material, assertion generation, field/body sealing,
HTTPS exchange, replay protection, and authenticated response opening. The
public wrappers pass only a logical request to a caller-owned transport and do
not create an alternate wire protocol.

The logical request includes the HTTP method, logical API path, content type,
protected application headers, and body. The provider must protect all of
these fields as required by the paired Leo contract; the outer HTTP request
must contain only the Leo envelope and routing metadata. The response returned
to the wrapper must already be authenticated and opened by Leo.

The Android SDK uses the same rule through `LeonaCryptoChannel`. The Java
wrapper exposes `LeonaServerClient.LeoCryptoBackendTransport`, and the Node.js
wrapper requires `transport.execute(...)`. Missing provider material is a
fail-closed configuration error, not a reason to send JSON or HMAC-only HTTP.

## Priority A: Node.js Wrapper

Suggested API:

```ts
type LeonaClientOptions = {
  transport: LeoCryptoBackendTransport;
  timeoutMs?: number;
};

type FeedbackLabel =
  | "fraud"
  | "not_fraud"
  | "false_positive"
  | "false_negative"
  | "unknown";

type FeedbackInput = {
  boxId?: string;
  boxIdHash?: string;
  canonicalHash?: string;
  label: FeedbackLabel;
  customerReason?: string;
  businessRecordRef?: string;
  source?: string;
};

export function createLeonaClient(options: LeonaClientOptions): {
  verdict(boxId: string): Promise<unknown>;
  evidenceReport(boxId: string): Promise<unknown>;
  supportBundle(boxId: string): Promise<unknown>;
  submitFeedback(input: FeedbackInput): Promise<unknown>;
  redact(value: unknown): unknown;
};
```

Minimum tests:

- missing Leo transport is rejected before any network operation
- logical method/path/body are handed to the Leo transport
- SecretKey is never included in thrown errors or logs
- `redact()` removes full BoxId and raw device identifiers
- HTTP 401/403/clock-skew responses are surfaced as transport errors, not
  device risk conclusions

## Priority B: Java/Kotlin Server Wrapper

Suggested API:

```kotlin
data class LeonaClientConfig(
    val transport: LeoCryptoBackendTransport,
    val timeoutMillis: Long = 5000,
)

interface LeonaClient {
    fun verdict(boxId: String): LeonaResponse
    fun evidenceReport(boxId: String): LeonaResponse
    fun supportBundle(boxId: String): LeonaResponse
    fun submitFeedback(input: FeedbackInput): LeonaResponse
}
```

Implementation requirements:

- no Android dependency; this is a server library
- no direct HTTP client; the caller-owned Leo transport owns HTTPS and wire
  encryption
- DTOs should keep unknown fields to avoid breaking on server-side report
  extension
- logs must use redacted hints or hashes only
- customer application code must make its own business decision after reading
  the evidence response

Minimum tests:

- missing Leo transport is rejected
- logical requests never bypass the Leo transport
- timeout propagation
- 401/403 redacted error handling
- unknown JSON fields preserved or ignored safely
- redaction of BoxId, device ID, install ID, token, and SecretKey

## Priority C: Go Wrapper

Go can follow the same API after Node.js and Java/Kotlin unless a pilot
customer requires it earlier.

## API Surface Mapping

| Wrapper method | Leona API | Credential | Notes |
| --- | --- | --- | --- |
| `verdict(boxId)` | `POST /v1/verdict` | Leo provider configuration | Evidence report compatibility path; no Leona business decision |
| `evidenceReport(boxId)` | `GET /v1/internal/private/evidence-reports/{boxId}` | Leo provider configuration | Enabled only for customer API deployments |
| `supportBundle(boxId)` | `GET /v1/internal/private/evidence-reports/{boxId}/support-bundle` | Leo provider configuration | Versioned redacted export |
| `submitFeedback(input)` | `POST /v1/internal/private/evidence-feedback` | Leo provider configuration | Stores customer truth labels using hashes/hints |

## Public-Safe Example Rules

Examples may use placeholders:

- `leoCryptoBackendTransport`
- `<BOX_ID_FROM_APP>`
- `box_hash_example`

Examples must not include:

- real endpoint credentials
- real tenant SecretKey or AppKey secret
- complete BoxId
- raw device/install identifier
- Play Integrity/OEM provider token
- private deployment host or SSH path

## Acceptance Before Publishing Wrappers

- wrapper unit tests pass
- redaction tests pass
- examples compile or run without real credentials
- README states evidence-only semantics
- package does not depend on private Leona server implementation
- package does not move final business decisions into the SDK or wrapper

## Current Skeletons

- Node.js: `leona-sdk-android/wrappers/nodejs/`
- Java: `leona-sdk-android/wrappers/java/`
- verification: `leona-sdk-android/scripts/verify-backend-wrapper-skeletons.sh`
