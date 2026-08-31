# Android LPCARR01 protected payload carrier V1

Classification: `CANDIDATE_ONLY / SUPPORT_ONLY / NON_ADMIT`.

The SDK builds a **request-only** `LPCARR01` body from the already strict
`leona.evidence.v1.EvidenceIngestRequest` Protobuf bytes. The body is intended
to be passed as the opaque application body to the caller-owned Leo
authenticated channel. `SecureChannel.uploadProtectedLogicalPayload` encodes
that carrier once and hands those exact whole-body bytes to the existing Leo
request path. It does not create provider receipts or make a client-side
business decision from a server verdict.

`Leona.sense()` follows this path: it maps the bounded identity snapshot and
native observation summary into the strict typed ingest model, encodes the
Protobuf once, and supplies the canonical handoff to this request-only carrier.
The typed route omits identity-derived ad-hoc protected headers; hash-only
fingerprint commitments and opaque install/session references are carried in
the authenticated body. Local observations are unverified evidence (`RAW`),
while hash commitments are `REDACTED`; no raw Android ID, package/build/model
text, native bytes, or finding message is serialized.

## Exact layout

- Header: ASCII `LPCARR01` (8 bytes), version `1` (u8), field count `5` (u8),
  reserved `0` (u16), network byte order.
- Five TLVs in exact order `1,2,3,4,5`; each is
  `tag:u8 | flags:u8=0 | reserved:u16=0 | length:u32 | value`.
- Tag values are `LEONA_PROTOBUF`, `leona.evidence.v1`,
  `leona.evidence.v1.EvidenceIngestRequest`, the exact 32-byte
  FileDescriptorSet SHA-256, and the exact Protobuf bytes.
- Payload length is `1..131072` bytes; this profile's carrier limit is
  `131226` bytes. Length conversion, offsets, and slicing are checked before
  allocation. Unknown, duplicate, reordered, omitted, reserved, flagged,
  truncated, trailing, descriptor-mismatched, empty, oversized, or malformed
  values fail closed with a typed result.

The frozen 339-byte carrier is byte-for-byte equal to the Rust/API golden:
`c568be45ad673497265fb4634eaa9767ed76383cb67c52a4e8aef64aaead4bd3`.

## Security and integration boundary

Descriptor fields are inside the authenticated body; they are not clear HTTP
headers. The SDK does not add or remove wire headers before the exact Crypto
contract is frozen. Only the existing Leo media type framing remains in scope.
Under the frozen amended outer-header contract, OkHttp's automatic `User-Agent`
and exactly one `Accept-Encoding: gzip` are transport-tolerated,
non-authenticated, and not
carrier metadata. This module does not add, remove, or normalize either header.
They are request negotiation only; an SDK caller cannot use them to carry
application metadata. Cookies and `Set-Cookie` remain forbidden: this client
uses an explicit `CookieJar.NO_COOKIES` jar and a caller client with
injected/non-empty cookie state must fail closed. Any response `Content-Encoding` value,
including `identity`, is rejected before the OkHttp bridge can decompress or
rewrite the body. The response requires one exact media-type `Content-Type`, at
most one bounded decimal `Content-Length` matching the raw body byte count,
and no `Set-Cookie`; actual bytes are independently bounded before Leo opens
the authenticated response. Raw compressed-response interoperability is
therefore forbidden, not a deferred verification assumption.

The optional Leo provider and authenticated carrier are not present in this
candidate. Therefore actual seal/runtime interoperability remains
`EXTERNAL_BLOCKED`; the typed handoff must not fall back to JSON, plaintext,
custom cryptography, or invented `X-Leona-*`/`X-Leo-*` headers. LPCARR01 V1 must
not be reused for responses. Provider-tamper requires a formal provider KAT and
is intentionally not simulated by constructing an authenticated receipt in
these Android tests.

Android codec/parser tests execute the frozen 23-vector corpus and exact
cross-language golden. These are host/JVM contract evidence only; API23-36
provider/device/runtime/release admission remains open.

Only the canonical private handoff and `ExternalBlocked` variants are
externally reachable through the current SDK. The descriptor/empty/oversize/
internal encoder-failure cases are covered by direct carrier unit tests; the
SecureChannel failure-injection test is explicitly a synthetic test seam, not
an externally constructible handoff.

## Response boundary

`LPCARR01` is request-only. A typed `sense()` response must instead be the
authenticated-open body `LPRESP01` and is parsed by the separate
`LeonaProtectedResponseCarrierV1` decoder. Its descriptor is
`leona.evidence.response.v1.EvidenceIngestResponse` with descriptor SHA-256
`01ca791bcbd4e7727da47e8d0351538c32e4f40394927676372a4d8d23ca6e73`, and its
Protobuf payload cap is 65,536 bytes. The response binds both the exact logical
request ID and SHA-256 of the complete LPCARR01 body. The only accepted
collection status is `ACCEPTED`; the SDK exposes a neutral compatibility view
(`evidence_collected` / `business_defined`) and never evaluates risk or policy.
Malformed, legacy JSON, missing, or unbound response bodies fail closed without
retry. The response fixtures are host/JVM contract evidence only; authenticated
Leo response sealing and runtime/provider interoperability remain
`EXTERNAL_BLOCKED`.
