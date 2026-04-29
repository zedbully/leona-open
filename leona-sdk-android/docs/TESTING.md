# Leona Android SDK Public Testing

This document describes the public validation path for the Android SDK. The
open source repository does not include Leona backend internals, private
detector catalogs, tenant risk policy, or release automation.

## Build Gate

Run the public SDK checks from `leona-sdk-android`:

```bash
./gradlew :sdk:testDebugUnitTest :sdk:assembleRelease --no-configuration-cache
```

Optional sample app build against Leona hosted endpoints:

```bash
LEONA_API_KEY=<appKey> \
LEONA_REPORTING_ENDPOINT=https://<leona-api> \
LEONA_CLOUD_CONFIG_ENDPOINT=https://<leona-config-api>/v1/mobile-config \
./scripts/run-live-sample.sh
```

`LEONA_API_KEY` and `LEONA_REPORTING_ENDPOINT` are required for the public
sample path. The client collects signals and uploads them; authoritative
verdicts are produced by Leona API/backend.

## Device Smoke Test

1. Install the sample app built with hosted Leona configuration.
2. Tap **Run sense()**.
3. Confirm a BoxId is returned.
4. Query verdict data through the configured Leona/customer backend endpoint.

The expected clean-device result is not a client-side allow/deny decision. A
clean device should upload normally and leave final policy evaluation to the
server.

## Emulator And Tooling Checks

Use devices and tooling that you own or are explicitly allowed to test.

- Android Studio emulator, MuMu, LDPlayer, Nox, BlueStacks, and Genymotion
  should produce emulator-related signals for server-side evaluation.
- Frida, Xposed/LSPosed, Magisk/KernelSU, and Unidbg tests should produce
  signal evidence when present.
- False positives on retail, non-rooted devices should be reported with
  device model, build fingerprint, Android version, and exported diagnostic
  payload.

The public SDK is intentionally signal-oriented. Do not add public APIs that
return a local trust verdict.

## CI

GitHub Actions runs the public Android SDK build and unit-test gate. Internal
backend, private runtime, and tenant policy validation are closed-source for
security reasons and run outside this public repository.
