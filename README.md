# Leona Public SDK

Leona is a runtime evidence collection SDK. The public repository contains the
released Android integration SDK, the sample Android app, public build tooling,
public-safe documentation, and a v0.4.0 iOS public-safe scaffold/extension track
when present.

The authoritative business decision is not made inside the APK or by Leona's
default SDK policy. Apps call `Leona.sense()` to collect and report evidence,
receive an opaque `BoxId`, and send that `BoxId` to their own business backend.
The business backend queries the Leona hosted API/backend for environment
evidence and provenance, then applies the customer's own product policy.

## Public Repository Rule

This GitHub repository intentionally keeps only public integration SDK code and
public-safe examples.

- Open source: Android SDK public API, Android sample app, Gradle build, SDK tests, iOS public scaffold when present, public-safe docs, CI for public SDK artifacts.
- Not open source: Leona hosted API/backend implementation, private detector catalog, private native runtime, risk weights, tenant policy, internal ops, production deployment, secrets, and closed-source tooling.
- Directory names are kept for orientation, but closed-source directories contain only README placeholders explaining why the code is absent.

This split is deliberate. Publishing backend evidence-processing internals or high-value detector rules would weaken the security model by giving attackers the implementation they need to bypass the system.

## Usage Model

Customers can fully use Leona in their APK through the public Android SDK, but the open-source SDK must be configured with a Leona API key, customer Leo-protected endpoints, and the paired external channel provider.

```text
Android app + Leona SDK
    |
    | sense()
    v
Leona API/backend
    |
    | BoxId
    v
Customer app -> customer backend -> Leona evidence API -> customer decision
```

Client apps should not make final security decisions from local signals. The
client only collects evidence and reports it. Leona provides evidence and
provenance; allow, challenge, deny, honeypot, or other product actions belong to
the customer business policy.

## Repository Layout

```text
.
├── leona-sdk-android/   # Public Android SDK, sample app, Gradle build, SDK tests
├── leona-sdk-ios/       # v0.4 public-safe iOS SDK scaffold and sample app
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
        .reportingEndpoint("https://leona.xiyanshan.com")
        .build()
)

val boxId = Leona.sense()
```

Send `boxId` to your business backend. Your backend queries the Leona verdict API and applies your product policy.

## Android SDK Dependency

For `v0.4.0`, the automated Maven channel is GitHub Packages:

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven("https://maven.pkg.github.com/zedbully/leona-open") {
            credentials {
                username = providers.gradleProperty("gpr.user")
                    .orElse(providers.environmentVariable("GITHUB_ACTOR"))
                    .orNull
                password = providers.gradleProperty("gpr.key")
                    .orElse(providers.environmentVariable("GITHUB_TOKEN"))
                    .orNull
            }
        }
    }
}
```

```kotlin
dependencies {
    implementation("io.leonasec:leona-sdk-android:0.4.0")
}
```

GitHub Release AAR + `.sha256` files remain the fallback path for teams that do
not want to configure GitHub Packages credentials in Gradle.

Post-release consumption smoke:

```bash
cd leona-sdk-android
./scripts/verify-v0.2-public-consumption.sh
```

Without package credentials, this verifies the public GitHub Release AAR
fallback and `.sha256`. To also verify GitHub Packages remote Gradle resolution,
set `LEONA_GITHUB_PACKAGES_TOKEN` or `GITHUB_TOKEN` to a token with
`read:packages`.

`v0.4.0` keeps the evidence-only SDK contract and adds Device Evidence Graph
release gates, Android matrix readiness checks, customer evidence report
contracts, feedback-loop gates, release evidence-pack validation, and stricter
public release review wrappers. Real custom ROM/GSI/unlocked-device samples,
external emulator samples, and real Play Integrity/OEM provider smoke remain
tracked as external-input follow-ups.

## Backend: Exchange BoxId for Device Evidence

The Android app must never call the evidence query API directly. It forwards
the opaque `BoxId` to your backend. The backend must use its caller-owned Leo
transport for the complete request and response; this repository provides no
JSON, plaintext, or HMAC-only query path.

```text
Android app
  -> Leona.sense() through LeonaCryptoChannel -> BoxId
  -> your login/payment/API request carries BoxId
  -> your backend passes a logical /v1/verdict request to its Leo transport
  -> Leo authenticates/opens the response
  -> your backend receives evidence and applies its own business policy
```

The customer-owned Leo transport is responsible for provider bootstrap,
protected headers/body, HTTPS, replay protection, and authenticated response
opening. Use `LeonaCryptoServerTransport` from the public Java wrapper or the
equivalent Node.js `transport.execute(...)` contract. Provider credentials,
server keys, and the actual Leo server SDK stay outside the APK and this public
repository. A missing transport is a configuration error and must stop before
any network request.

Typical backend flow with cache:

```text
1. Android app calls Leona.sense() during login/payment/high-value action.
2. App sends the opaque BoxId in the customer API request.
3. Customer backend checks whether this business record already has a cached
   Leona evidence report.
4. On cache miss, backend sends the logical verdict request through its Leo transport.
5. Backend persists the first successful report with its own record id,
   response status, query time, deviceFingerprint, canonicalDeviceId, events,
   provenance, and policyExplanation.
6. Backend applies customer-owned business policy from the cached evidence.
7. Later retries or audits read the cached report because the BoxId has already
   been consumed by the successful /v1/verdict call.
```

Important response fields:

- `deviceFingerprint`: Leona device fingerprint identifier.
- `canonicalDeviceId`: stable app-scoped Leona device id, usually prefixed with `L`.
- `events`: collected device/environment evidence events.
- `authoritativeRiskTags`: tags derived from authoritative server/native evidence.
- `telemetryRiskTags`: low-trust telemetry kept for explanation/debugging.
- `riskTagsBySource`: source breakdown such as `native_payload`, `server_policy`, `client_header`.
- `provenance` and `policyExplanation`: why the evidence report looks the way it does.

`/v1/verdict` is single-use. After a successful query, the BoxId is consumed;
subsequent calls return `410 LEONA_BOX_ALREADY_USED`. Cache the returned report
inside your own business order/login/risk record if you need to read it again.

Leona returns evidence. Your backend decides whether to allow, challenge, deny,
honeypot, or take any other product action.

## Customer Integration Checklist

- Get a Leona AppKey for the Android SDK and provision the paired Leo provider
  separately for the backend.
- Configure the APK with AppKey and a Leo-protected HTTPS endpoint only; never
  package backend provider material.
- Call `Leona.sense()` at the protected business moment and send the opaque BoxId to your backend.
- Include the BoxId in a backend-owned login/order/payment/risk request field.
- Send backend `/v1/verdict` and customer API calls through the Leo transport;
  do not add a JSON, plaintext, or HMAC-only fallback.
- Cache the first successful verdict response with your own business record because BoxId is single-use.
- Handle `410 LEONA_BOX_ALREADY_USED` through your cache/idempotency path.
- Log auth/signature/time/network/server failures separately so integration issues are diagnosable.
- Keep final allow/challenge/deny/manual-review actions in your own backend policy.

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

Nightly CI runs the same public SDK checks. It does not run the customer-owned
Leo provider/server verifier or closed-source alpha-closure flows.

## Closed-Source Areas

The following areas are intentionally absent from public code:

- Leona hosted API/backend implementation
- hosted `/v1/verdict` evidence/provenance policy and production operations
- private native detector catalog and private JNI bridge
- private risk scoring weights and tenant rollout policy
- production config, keys, KMS/Vault wiring, dashboards, and internal ops
- internal release, sync, and deployment automation

See [docs/open-source-policy.md](docs/open-source-policy.md) for the public/private boundary.
