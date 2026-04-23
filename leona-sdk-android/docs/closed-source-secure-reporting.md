# Closed-source secure reporting module

Leona Android SDK now treats request encryption / decryption related logic as a **closed-source private module**:

- public SDK module: `/Users/a/back/Game/cq/leona-sdk-android/sdk`
- private module entry: `/Users/a/back/Game/cq/leona-sdk-android/private/sdk-private-core`

## Public / private split

Public `:sdk` only keeps:

- public SDK API
- tamper policy parsing / merge
- `SecureReportingEngine` SPI
- reflective loader for the private implementation

Private `:sdk-private-core` contains:

- X25519 handshake
- HKDF session derivation
- AES-GCM payload encryption
- HMAC request signing
- Android Keystore device binding
- secure session persistence

## Loading behavior

`/Users/a/back/Game/cq/leona-sdk-android/sdk/src/main/kotlin/io/leonasec/leona/internal/spi/SecureReportingEngineLoader.kt`
will try to load:

- `io.leonasec.leona.privatecore.DefaultSecureReportingEngine`

If the app does not configure `reportingEndpoint`, the SDK still works in local-only mode.

If `reportingEndpoint` + `apiKey` are configured but the private module is missing, the SDK throws a clear runtime error instead of silently downgrading.

## Non-open-source handling

`private/` is already ignored by Git, so the actual crypto implementation is not intended to be published with the public repository.

For stronger separation in production, move `sdk-private-core` into:

- a separate private repository, or
- a private Maven package

and keep the current SPI contract unchanged.
