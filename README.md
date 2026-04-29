# Leona Android Public SDK

Leona is an Android runtime security SDK. The public repository contains the Android integration SDK, the sample Android app, public build tooling, and public-safe documentation.

The authoritative security decision is not made inside the APK. Apps call `Leona.sense()` to collect and report evidence, receive an opaque `BoxId`, and send that `BoxId` to their own business backend. The business backend then queries the Leona hosted API/backend for the final verdict.

## Public Repository Rule

This GitHub repository intentionally keeps only the Android public integration SDK code.

- Open source: Android SDK public API, Android sample app, Gradle build, SDK tests, public-safe docs, CI for the public AAR.
- Not open source: Leona hosted API/backend implementation, private detector catalog, private native runtime, risk weights, tenant policy, internal ops, production deployment, secrets, and closed-source tooling.
- Directory names are kept for orientation, but closed-source directories contain only README placeholders explaining why the code is absent.

This split is deliberate. Publishing backend decision logic or high-value detector rules would weaken the security model by giving attackers the implementation they need to bypass the system.

## Usage Model

Customers can fully use Leona in their APK through the public Android SDK, but the open-source SDK must be configured with a Leona API key and Leona hosted endpoints.

```text
Android app + Leona SDK
    |
    | sense()
    v
Leona API/backend
    |
    | BoxId
    v
Customer app -> customer backend -> Leona verdict API -> customer decision
```

Client apps should not make final security decisions from local signals. The client only collects evidence and reports it. Final allow/challenge/deny/honeypot decisions belong on the server side.

## Repository Layout

```text
.
├── leona-sdk-android/   # Public Android SDK, sample app, Gradle build, SDK tests
├── leona-server/        # Placeholder only; backend implementation is closed source
├── demo-backend/        # Placeholder only; hosted/customer backend examples are closed source
├── leona/               # Placeholder only; internal CLI/tooling is closed source
├── scripts/             # Placeholder only; internal release/ops scripts are closed source
├── docs/                # Public-safe boundary and integration notes
└── .github/workflows/   # Public Android SDK CI
```

## Android Quick Start

```kotlin
Leona.init(
    context = this,
    config = LeonaConfig.Builder()
        .apiKey("your-leona-api-key")
        .reportingEndpoint("https://api.example.leona/v1")
        .build()
)

val boxId = Leona.sense()
```

Send `boxId` to your business backend. Your backend queries the Leona verdict API and applies your product policy.

## Build Public SDK

```bash
cd leona-sdk-android
./gradlew :sdk:testDebugUnitTest :sdk:assembleRelease --no-daemon
```

AAR output:

```text
leona-sdk-android/sdk/build/outputs/aar/sdk-release.aar
```

## CI

The public GitHub workflow builds only the Android public SDK:

- `:sdk:lint` as advisory
- `:sdk:testDebugUnitTest`
- `:sdk:assembleDebug`
- `:sdk:assembleRelease`
- native source sanity as advisory

Nightly CI runs the same public SDK checks. It does not run private backend, demo backend, or closed-source alpha-closure flows.

## Closed-Source Areas

The following areas are intentionally absent from public code:

- Leona hosted API/backend implementation
- `/v1/verdict` production decision policy
- private native detector catalog and private JNI bridge
- private risk scoring weights and tenant rollout policy
- production config, keys, KMS/Vault wiring, dashboards, and internal ops
- internal release, sync, and deployment automation

See [docs/open-source-policy.md](docs/open-source-policy.md) for the public/private boundary.
