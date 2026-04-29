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

Do not build server-side verdict secrets into the sample APK. Direct `/v1/verdict`
signature verification belongs in a host-side script or your backend; the sample
app only sends the BoxId and low-trust demo context to the configured demo
backend.

The sample app's logcat automation is a debug-only field-test helper. It only
runs when the debug APK is built with `LEONA_E2E_TOKEN` and the launch intent
provides the same token; release builds and normal launches ignore that path.

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
- `debug.adb_enabled` / `debug.developer_options_enabled` mean the device is in
  a developer-test posture. They are high-value evidence for the server, but
  the SDK still only reports evidence and returns a BoxId.

For a stricter clean-device baseline, install a non-debug/release build through
the same route your production app will use, then run `sense()` and query the
server verdict for that new BoxId. If you turn off Developer options or ADB
after an earlier run, run `sense()` again and use the newly returned BoxId; old
BoxIds keep the evidence captured at the time they were minted.

When testing against a backend on your LAN, use an address reachable from the
phone, such as `http://192.168.x.y:<port>`. `localhost` and `127.0.0.1` from
inside the app refer to the Android device itself, not your development
machine.

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
