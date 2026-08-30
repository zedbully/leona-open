# Android V1 evidence protobuf (candidate)

This document records the Android-side, evidence-only encoding boundary. It is a
support artifact, not an Android runtime or release-admission claim.

## Frozen API input

The source is copied byte-for-byte from the accepted API workspace:

- `src/main/proto/leona/evidence/v1/ingest.proto`
  SHA-256 `e93b2c21f55db26f0179be7d18e35ea2a5005786f8e43e3a6027ddf59b9268a3`
- `src/main/resources/leona/evidence/v1/ingest.pb` (the admitted
  `FileDescriptorSet`) SHA-256
  `1056487dea69e58894f48aea6d04a528e1e2aaf543fc708deb7cec007aaf8703`
- `src/test/resources/leona/evidence/v1/valid-ingest.bin` (golden bytes)
  SHA-256 `b372aee07b4372234bcdfa102bbbd05e1f7e68d1d15b6a2f9164bde4af89d1da`

Bindings are generated, never hand-written, with `libprotoc 29.4` and
`--java_out=lite`. The generated package is `io.leonasec.proto.v1`; the checked-in
`sdk/src/main/proto/leona/evidence/v1/codegen-manifest.json` records the exact
source, descriptor, golden, protoc, runtime, and generated-source digests.

## Encoding contract

`LeonaEvidenceProtobufCodec` validates the closed schema, reserved/unknown
fields, canonical wire varints, singular/oneof cardinality, enum values, UTF-8,
and bounded lengths before parsing. The application payload cap is 128 KiB;
max and max+1 cases are tested. This profile intentionally uses smaller bounds inside the wire envelope (1,024 entries, 512-byte keys, 4 KiB strings, and 16 KiB byte values) and rejects values beyond them. There is no JSON or plaintext retry.

The codec returns a typed `LeonaProtectedLogicalPayloadHandoff` containing the
bytes and four logical descriptor values (`payloadCodec`, `payloadSchema`,
`messageType`, and the 32-byte descriptor digest). These values are not clear
HTTP headers. The existing `SecureChannel` accepts this typed handoff but returns
`protected_payload_carrier_unavailable` before request construction because the
exact Leo protected-metadata carrier/receipt is not yet admitted. No provider
wire or custom metadata encoding is guessed.

The Android SDK reports evidence and opaque install/session references only; the
server owns identity/risk/verdict decisions. Outer HTTP metadata remains the Leo
authenticated channel's media type; no `X-Leona-*` or `X-Leo-*` clear headers are
added by this lane.

## Runtime and supply chain

The direct runtime dependency is
`com.google.protobuf:protobuf-javalite:4.29.4` (Apache-2.0), with SHA-256
`622f9ddfd99e8391efb5b2be5cb149dacaba1104905635eecf6ceac8e43e122e` and
1,069,282 bytes. Its POM SHA-256 is
`240c2b66f9a1e4691d2b7de06344e40c80b12ee3fecf992a48b7f9dea8d6a24a`.
Gradle dependency verification records these digests and the transitive BOM /
parent metadata. Consumer R8 rules retain generated lite bindings.

The library is compiled with the existing API 23 floor; API 23 provider
compatibility and the API 23--36 device matrix are **NOT_RUN/BLOCKED** pending
the formal Leo provider contract. This host/JVM evidence does not prove
Keystore/provider behavior, and no provider plaintext capacity is asserted.

Status: `CANDIDATE_ONLY / NOT_INTEGRATED / NON_ADMIT`.
