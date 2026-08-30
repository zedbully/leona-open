# Android LPCARR01 protected payload carrier V1

Classification: `CANDIDATE_ONLY / SUPPORT_ONLY / NON_ADMIT`.

The SDK builds a **request-only** `LPCARR01` body from the already strict
`leona.evidence.v1.EvidenceIngestRequest` Protobuf bytes. The body is intended
to be passed as the opaque application body to the caller-owned Leo
authenticated channel. This module does not seal/open Leo envelopes, create
provider receipts, or make a network request.

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
contract is frozen. Only the existing Leo media type framing remains in scope;
OkHttp's automatic `User-Agent` and `Accept-Encoding: gzip` are external
transport interoperability blockers to record, not headers this module
controls. A non-empty caller `CookieJar` is likewise forbidden and must fail
closed; this module does not add, strip, or normalize cookies.

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
