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

`LEONA_CLOUD_CONFIG_ENDPOINT` must use HTTPS to be trusted. HTTP/LAN endpoints
are still useful for local upload or verdict testing, but the SDK ignores
cleartext cloud config responses so an unauthenticated control-plane response
cannot change collection policy. The SDK does not persist canonical device
identity from mobile-config responses; canonical identity comes from the secure
reporting server path.

Do not build server-side verdict secrets into the sample APK. Direct `/v1/verdict`
signature verification belongs in a host-side script or your backend; the sample
app only sends the BoxId and low-trust demo context to the configured demo
backend.

The sample app's logcat automation is a debug-only field-test helper. It only
runs when the debug APK is built with `LEONA_E2E_TOKEN` and the launch intent
provides the same token; release builds and normal launches ignore that path.
The sample release build also rejects debug/test-only Gradle properties such as
`LEONA_API_KEY`, `LEONA_E2E_TOKEN`, and fake attestation modes so those values
cannot be embedded into a distributable APK by accident.

For cloud-device validation on WeTest, use `docs/wetest-matrix-runbook.md`.
Release/non-debug sample APKs are suitable for package posture checks, while
debug/staging APKs are reserved for controlled logcat E2E collection.

Before a release candidate spends more time on WeTest, run the public static
clean-OEM ledger gate from `leona-sdk-android`:

```bash
./scripts/verify-clean-oem-ledger.sh
```

This check only reads `docs/wetest-matrix-runbook.md`. It confirms the tested
ledger has at least six passing mainstream clean-OEM brand families, pass rows
use redacted BoxId hints or hashes, and pass-row notes do not contain the
release-gate false-positive family terms.

To validate an already-installed debug sample without reinstalling it or reading
the UI, run the installed-sample logcat smoke test:

```bash
ADB_SERIAL=<device-or-emulator-serial> \
LEONA_E2E_TOKEN=<token-built-into-the-installed-debug-apk> \
./scripts/run-installed-sample-logcat-smoke.sh
```

The script starts the existing app with the authorized debug intent, reads
structured `LeonaE2E` logcat chunks, and writes decoded artifacts under
`/tmp/leona-installed-sample-logcat-smoke-*`. It intentionally fails when
multiple devices are connected and `ADB_SERIAL` is omitted. By default it
force-stops the sample process before launch and clears the device logcat buffer
so old events cannot be mistaken for the current run. Set
`LEONA_SKIP_FORCE_STOP=1` or `LEONA_SKIP_LOGCAT_CLEAR=1` when you need a gentler
diagnostic pass.

## Device Smoke Test

1. Install the sample app built with hosted Leona configuration.
2. Tap **Run sense()**.
3. Confirm a BoxId is returned.
4. Query verdict data through the configured Leona/customer backend endpoint.

The expected clean-device result is not a client-side allow/deny decision. A
clean device should upload normally and leave final policy evaluation to the
server.

## Hosted API Diagnostics

The public hosted upload path (`POST /v1/sense/public`) uses `X-Leona-App-Key`
tenant authentication and does not require a client-side HMAC timestamp. A
missing or invalid AppKey should return a structured `401` response with
`LEONA_AUTH_MISSING` or `LEONA_AUTH_INVALID`; it must not surface as a generic
HTTP 500 to the SDK.

The signed private upload path (`POST /v1/sense`) still requires timestamp,
nonce, signature, and session headers. Timestamp parsing or clock-window
failures should return `401 LEONA_TIMESTAMP_SKEW`, while missing signed headers
should return `401 LEONA_AUTH_MISSING`. SDK diagnostics classify these cases as
`timestamp_skew` or `auth_failed`; generic 5xx responses are classified as
`server_5xx` and should not trigger timestamp-skew retry behavior unless the
server explicitly returns a timestamp-skew marker.

Clock handling has two separate contracts:

- Public hosted reporting (`/v1/sense/public`) does not ask the APK to sign the
  upload with the device wall clock. This path is designed for the public AAR
  and should be validated through AppKey authentication, network timeout, and
  server 5xx diagnostics. `serverTimeMillis` and `serverClockOffsetMillis` are
  not public hosted response fields in `v0.2.0`.
- Private signed reporting (`/v1/sense`) can receive `serverTimeMillis` during
  handshake. The SDK derives `serverClockOffsetMillis` as
  `serverTimeMillis - currentDeviceTimeMillis`, persists it with the session,
  and signs later uploads with the corrected timestamp. If the server returns a
  clear timestamp-skew error, the SDK may discard the old session, refresh the
  handshake, and retry once.

`timestamp_skew` is a transport/authentication diagnostic. It is not evidence
that the device is rooted, hooked, emulated, or otherwise risky. Record it in
logs and retry/fallback handling, but do not turn it into a business verdict or
device-risk tag.

For the Android 10 realme-style clock-offset regression, run the direct
cloudTest wrapper instead of tapping the UI:

```bash
LEONA_APK=/path/to/sample-app-cloudTest.apk \
ANDROID_SERIAL=<device-or-wetest-adb-serial> \
LEONA_CLOUD_TEST_TOKEN=<token-built-into-cloudTest-apk> \
./scripts/run-clock-skew-regression.sh
```

The script records host/device wall-clock offset, runs `sense()` through the
cloudTest receiver, redacts BoxIds in shareable artifacts, and classifies
failures as `timestamp_skew`, `network_timeout`, `auth_failed`, `server_5xx`, or
`no_boxid`.

## Clean Physical Device Notes

The public sample path normally installs `sample-app-debug.apk` over ADB. On a
clean retail device this can still produce server-side tags such as
`debug.app_debuggable`, `debug.adb_enabled`, `debug.developer_options_enabled`,
and `install.sideload_or_unknown`.

These tags mean the test package or install route is debug-like, not that the
device is rooted or hooked:

- `debug.app_debuggable` means the installed APK has Android's debuggable app
  flag set. This is expected for the sample debug package built by
  `./scripts/run-live-sample.sh`.
- `install.sideload_or_unknown` means Android did not report a trusted store
  installer package, or the app was installed via ADB/manual sideload. This is
  expected for local field testing.
- `tamper.installer.missing` means Android reported no usable installer package
  name. In WeTest, ADB, and manual sideload runs this is installation-route
  evidence, not proof that the APK was modified.
- `debug.adb_enabled` / `debug.developer_options_enabled` mean the device is in
  a developer-test posture. They are high-value evidence for the server, but
  the SDK still only reports evidence and returns a BoxId.
- `runtime.mapping.*` entries are `/proc/self/maps` facts such as deleted,
  anonymous, or memfd executable mappings. They are useful context for runtime
  analysis, but they only become Hook/Frida-style evidence when accompanied by
  specific hook, injection, trampoline, package, or library findings.

For a stricter clean-device baseline, install a non-debug/release build through
the same route your production app will use, then run `sense()` and query the
server verdict for that new BoxId. If you turn off Developer options or ADB
after an earlier run, run `sense()` again and use the newly returned BoxId; old
BoxIds keep the evidence captured at the time they were minted.

When testing against a backend on your LAN, use an address reachable from the
phone, such as `http://192.168.x.y:<port>`. `localhost` and `127.0.0.1` from
inside the app refer to the Android device itself, not your development
machine. Use HTTPS for cloud config validation; otherwise only the upload and
verdict paths should be expected to work.

## Emulator And Tooling Checks

Use devices and tooling that you own or are explicitly allowed to test.

- For a repeatable field-testing template and a matrix you can fill in as you
  validate multiple emulator vendors, see `docs/emulator-matrix.md`.
- For custom AOSP, community ROMs, GSI, and bootloader-unlocked devices, see
  `docs/rom-matrix.md` and start with the read-only
  `scripts/collect-device-posture.sh` posture collector.
- For WeTest cloud-device and non-debug release package posture collection, see
  `docs/wetest-matrix-runbook.md`.
- Android Studio emulator, MuMu, LDPlayer, Nox, BlueStacks, and Genymotion
  should produce emulator-related signals for server-side evaluation.
- Frida, Xposed/LSPosed, Magisk/KernelSU, and Unidbg tests should produce
  signal evidence when present.
- False positives on retail, non-rooted devices should be reported with
  device model, fingerprint hash or redacted fingerprint evidence, Android
  version, and exported diagnostic payload.

The public SDK is intentionally signal-oriented. Do not add public APIs that
return a local trust verdict.

## CI

GitHub Actions runs the public Android SDK build and unit-test gate in
`.github/workflows/android.yml`. The separately triggered
`.github/workflows/android-cloud-runtime.yml` builds one ephemeral `cloudTest`
APK and exercises direct `sense()` plus public-hosted reporting on API 23 and
API 36 GitHub-managed plain AOSP/no-GMS AVDs. The app reaches the host-only
fixture through temporary `adb reverse` using a strict loopback endpoint; the
SDK's HTTPS/loopback transport boundary is not relaxed. It publishes only
redacted import, fixture receipt, provenance, and verifier summaries; the APK,
AppKey, cloud-test token, raw BoxId, and raw device identifiers are not
artifacts.

The hosted AVD result is boundary runtime evidence only. It is not the complete
API 23-36 runtime matrix, physical/OEM or real attestation evidence, a customer
backend decision, or commercial admission. Internal backend, private runtime,
and tenant policy validation remain closed-source and run outside this public
repository.

To bind a downloaded artifact into matrix readiness, set
`LEONA_GITHUB_HOSTED_RUNTIME_ROOT` to its `leona-github-cloud-runtime`
directory and run `scripts/verify-v0.4-android-matrix-readiness.sh`. The gate
reruns the evidence verifier; it does not count this hosted boundary as a
physical/OEM full-matrix sample.
