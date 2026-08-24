# Emulator Matrix (Public SDK)

This document is a **field-testing template** for collecting repeatable emulator
evidence with the **Leona Android public SDK**.

The SDK only **collects and reports evidence** and returns an opaque `boxId`.
Product actions must stay outside the client and use server-side evidence/policy.

## What to capture

For each emulator (or "cloud phone") sample, capture:

- Host OS + emulator vendor/version
- Android version + ABI
- ADB serial hash or an opaque local target label (for repro; never the raw serial)
- A redacted `boxId` hint or hash from the sample app
- Server-side evidence tags for that `boxId` (if available)
- Exported diagnostic artifacts (logcat and/or support bundle)

## Recommended workflow

1. Build/install the sample app (debug) on the target emulator/device.
2. Run `sense()` and capture a redacted hint or hash for the returned `boxId`.
3. Run a **non-destructive** logcat smoke if the app is already installed:
   - `./scripts/run-installed-sample-logcat-smoke.sh`
4. Optionally run the full emulator E2E script when reinstall/uninstall is OK:
   - `./scripts/run-emulator-e2e.sh`
5. Record outcomes in the table below.

## Matrix template

Copy/paste a new row per sample:

| Sample | Vendor/version | Android/ABI | ADB serial hash / target label | Install path | boxId hint/hash | Server evidence summary | Evidence highlights | Artifacts path | Notes |
|---|---|---|---|---|---|---|---|---|---|
| MuMu | MuMu connected through ADB TCP | Android 12 / arm64-v8a | `target-hash:<sha256-prefix>` | Installed debug sample | redacted hint / record hash in private artifact | `environment.emulator.detected` evidence present | `nemud.*`, `nemu*` services, MuMu binary, QEMU/hypervisor style evidence; posture control reported `user/release-keys`, no root manager packages | private artifact reference omitted | Keep vendor-spoofing evidence separate from ROM/build evidence. |
| Android Studio Emulator | AVD `sdk_gphone64_arm64` / ranchu | Android 14 / arm64-v8a | `target-label:android-studio-a14` | Installed debug sample | redacted hint / record hash in private artifact | Emulator evidence present; compatibility risk fields remain server-side evidence labels | `env.emulator.avd.ranchu`, `env.emulator.avd.sdk_gphone`, synthetic ARM CPU profile, QEMU boot/kernel flags; posture control reported `userdebug/dev-keys`, no root manager packages | private artifact reference omitted | Logcat E2E export confirmed raw canonical/deviceId/installId and local endpoints are redacted. |
| LDPlayer |  |  |  |  |  |  |  |  |  |
| Nox |  |  |  |  |  |  |  |  |  |
| BlueStacks |  |  |  |  |  |  |  |  |  |
| Genymotion |  |  |  |  |  |  |  |  |  |
| Cloud phone |  |  |  |  |  |  |  |  |  |

## Non-destructive logcat smoke (installed sample)

This path does not uninstall/reinstall the APK. It launches the already
installed debug sample and parses structured `LeonaE2E` logcat output.

```bash
cd leona-sdk-android
ADB_SERIAL=<device-or-emulator-serial> \
LEONA_E2E_TOKEN=<token-built-into-the-installed-debug-apk> \
./scripts/run-installed-sample-logcat-smoke.sh
```

Artifacts are written under `/tmp/leona-installed-sample-logcat-smoke-*`.

## Full emulator E2E (may reinstall)

When it is OK to reinstall/uninstall and reset the sample app state:

```bash
cd leona-sdk-android
ADB_SERIAL=<device-or-emulator-serial> \
LEONA_API_KEY=<appKey> \
LEONA_REPORTING_ENDPOINT=https://<leona-api> \
LEONA_CLOUD_CONFIG_ENDPOINT=https://<leona-config-api>/v1/mobile-config \
./scripts/run-emulator-e2e.sh
```

Do not embed or ship server-side verdict secrets in the APK. Host-side scripts
or your backend should hold any secrets needed to query or verify `/v1/verdict`.
