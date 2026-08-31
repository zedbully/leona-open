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
HTTP headers. `Leona.sense()` maps the bounded local snapshot into this model,
encodes it once, and passes the canonical handoff to the request-only LPCARR01
carrier before calling the existing Leo authenticated upload boundary. If the
mapper, codec, carrier, or Leo provider is unavailable, the call fails with a
typed error before HTTP and never retries with the legacy raw body, JSON, or
plaintext. No provider wire or custom metadata encoding is guessed.

The mapper emits only fixed registry observations plus opaque install/session
references and hash-only fingerprint commitments. Local observations are
`RAW`; hash commitments are `REDACTED`; `VERIFIED` is reserved for facts
authenticated by a provider or server. Device IDs, package/build/model text,
native payload bytes, and finding messages are not serialized. Identity-derived
ad-hoc protected headers are omitted on this typed path; descriptor values stay
inside LPCARR01.

The host test `Leona.runTypedSense` seam exercises the same mapper/codec call
chain with a recording uploader; it is internal test support, not a public
payload-construction API. Leo provider seal/runtime and Android device
execution remain separate evidence gates.

The Android SDK reports evidence and opaque install/session references only; the
server owns identity/risk/verdict decisions. Tenant/app/environment is a
protected scope declaration for server validation, never a client authorization
or policy authority. Outer HTTP metadata remains the Leo
authenticated channel's media type; no `X-Leona-*` or `X-Leo-*` clear headers are
added by this lane.

## Strict typed response

The typed `Leona.sense()` path accepts only the response-only `LPRESP01` carrier
after `LeonaCryptoTransport.openResponse` succeeds. The frozen response source
and fixtures are copied byte-for-byte:

- `src/main/proto/leona/evidence/response/v1/response.proto` SHA-256
  `90b2f2753c3cdf9e86d3690ec5e37c3de15873267bcb0b1b26f5a4091918619c`
- `src/main/resources/leona/evidence/response/v1/response.pb` SHA-256
  `01ca791bcbd4e7727da47e8d0351538c32e4f40394927676372a4d8d23ca6e73`
- `src/test/resources/leona/evidence/response/v1/valid-response.bin` SHA-256
  `38c53d6f2635ba836853d45f5fc20f27ed9eae7fe047e63c398ca933a6bbc8a1`
- frozen response carrier SHA-256
  `34a10a47d1334621089bc9614f892703bf63b4ca178e74c611fe7e49b7dc43ac`

`LeonaProtectedResponseCarrierV1` is response-only and enforces the five
ascending TLVs, exact response descriptor, checked lengths, and a 64 KiB
Protobuf cap. `LeonaEvidenceResponseProtobufCodec` rejects unknown/reserved or
duplicate fields, non-minimal varints, wrong wire types, invalid UTF-8/enums,
malformed opaque identifiers, expired lifetimes, and request-id/full-carrier
digest mismatches. No typed response JSON parser is reachable from this path;
legacy JSON parsing remains only on the historical `upload()` compatibility
method and is not called by `sense()`.

Successful typed responses produce the neutral compatibility view
`decision=evidence_collected`, `action=business_defined`, with no client risk
score/tags. BoxId and server install/canonical identifiers are accepted only
from this authenticated response. Any malformed, missing, provider, or network
condition fails closed without a second operation or a JSON/plaintext/legacy
retry. Formal provider response sealing and live interoperability remain
`EXTERNAL_BLOCKED`; the checked-in response envelope fixture is
`TEST_ONLY_BYTE_LAYOUT_NOT_CRYPTOGRAPHY`.

## Runtime and supply chain

The direct runtime dependency is
`com.google.protobuf:protobuf-javalite:4.29.4` (Apache-2.0), with SHA-256
`622f9ddfd99e8391efb5b2be5cb149dacaba1104905635eecf6ceac8e43e122e` and
1,069,282 bytes. Its POM SHA-256 is
`240c2b66f9a1e4691d2b7de06344e40c80b12ee3fecf992a48b7f9dea8d6a24a`.
Gradle dependency verification records these digests and the transitive BOM /
parent metadata. A CycloneDX component record is checked in at
`sdk/src/main/proto/leona/evidence/v1/sbom.json`. Consumer R8 rules retain generated
lite bindings.

The library is compiled with the existing API 23 floor; API 23 provider
compatibility and the API 23--36 device matrix are **NOT_RUN/BLOCKED** pending
the formal Leo provider contract. This host/JVM evidence does not prove
Keystore/provider behavior, and no provider plaintext capacity is asserted.

Status: `CANDIDATE_ONLY / NOT_INTEGRATED / NON_ADMIT`.
