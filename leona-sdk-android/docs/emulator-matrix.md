# Emulator Matrix (Public SDK)

This document is a **field-testing template** for collecting repeatable emulator
evidence with the **Leona Android public SDK**.

The SDK only **collects and reports evidence** and returns a `boxId`. **Final
business decisions must be made by the server verdict**.

## What to capture

For each emulator (or “cloud phone”) sample, capture:

- Host OS + emulator vendor/version
- Android version + ABI
- ADB serial (for repro)
- A `boxId` from the sample app
- Server verdict tags for that `boxId` (if available)
- Exported diagnostic artifacts (logcat and/or support bundle)

## Recommended workflow

1. Build/install the sample app (debug) on the target emulator/device.
2. Run `sense()` and capture the returned `boxId`.
3. Run a **non-destructive** logcat smoke if the app is already installed:
   - `./scripts/run-installed-sample-logcat-smoke.sh`
4. Optionally run the full emulator E2E script when reinstall/uninstall is OK:
   - `./scripts/run-emulator-e2e.sh`
5. Record outcomes in the table below.

## Matrix template

Copy/paste a new row per sample:

| Sample | Vendor/version | Android/ABI | ADB serial | Install path | boxId | Server verdict summary | Evidence highlights | Artifacts path | Notes |
|---|---|---|---|---|---|---|---|---|---|
| MuMu | MuMu connected through ADB TCP | Android 12 / arm64-v8a | `127.0.0.1:16512` | Installed debug sample | `01KQBAEJW4RR75TSFJY62Z7EE3` | `environment.emulator.detected` in sample verdict | `nemud.*`, `nemu*` services, MuMu binary, QEMU/hypervisor style evidence from prior E2E; posture control reported `user/release-keys`, no root manager packages | `/tmp/leona-posture-mumu-20260430-next/device-posture.json` | Keep vendor-spoofing evidence separate from ROM/build evidence. |
| Android Studio Emulator | AVD `sdk_gphone64_arm64` / ranchu | Android 14 / arm64-v8a | `emulator-5554` | Installed debug sample | `01KQFNYMG5K016BDPV36TC4GGQ` | `environment.emulator`, `environment.emulator.detected`, `environment.emulator.native`, `environment.risky`, `risk.critical` | `env.emulator.avd.ranchu`, `env.emulator.avd.sdk_gphone`, synthetic ARM CPU profile, QEMU boot/kernel flags; posture control reported `userdebug/dev-keys`, no root manager packages | `/tmp/leona-emulator5554-redaction-check-20260430-appside3/events.json`; posture `/tmp/leona-posture-ase-20260430-next/device-posture.json` | Logcat E2E export confirmed raw canonical/deviceId/installId and local endpoints are redacted. |
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
