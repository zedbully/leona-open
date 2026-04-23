# Closed-source API crypto module

Leona Server now treats SDK-side secure channel crypto as a **closed-source backend module**:

- public modules keep only wrappers / SPI
- private implementation lives in `/Users/a/back/Game/cq/leona-server/private/api-backend`

## Public / private split

Public repo keeps:

- `ApiCryptoProvider` SPI
- `ApiCryptoProviders` loader
- wrapper classes:
  - `SdkRequestCanonicalizer`
  - `HmacVerifier`
  - `DeviceBindingVerifier`
  - `AesGcmCipher`
  - `EcdheSession`

Private module implements:

- canonical request building
- HMAC signing / verification
- AES-GCM open / seal
- X25519 ECDHE session derivation
- device binding signature verification

## Loading behavior

`/Users/a/back/Game/cq/leona-server/common/src/main/java/io/leonasec/server/common/spi/ApiCryptoProviders.java`
loads the private bootstrap class:

- `io.leonasec.server.privatebackend.PrivateApiCryptoBootstrap`

That bootstrap installs the real `ApiCryptoProvider`.

If the private module is absent, public wrappers fail fast with a clear message instead of silently falling back to weak logic.

## Test strategy

Public `common` tests use an in-test provider so unit tests can still run without exposing the real implementation.

Runtime services (`gateway`, `ingestion-service`) depend on `:private-api-backend` when present.

## Recommended production packaging

For stricter IP isolation, move `api-backend` to:

- a private artifact repository, or
- a separate private mono-repo

and keep only the SPI + wrappers in the public codebase.
