# ROM And Bootloader Matrix (Public SDK)

This document is a field-testing matrix for custom AOSP, custom ROM, GSI, and
bootloader-unlocked Android devices.

The Leona Android SDK only collects and reports evidence. It must not make a
local allow/deny decision for custom ROM, root, bootloader, or emulator posture.
Final business decisions belong to the server verdict.

## Scope

Use this matrix to separate ROM and bootloader facts from emulator, root, hook,
and debug evidence:

- custom AOSP-like builds
- community ROMs such as LineageOS, crDroid, PixelExperience, GrapheneOS, CalyxOS
- GSI / DSU images
- bootloader unlocked / verified boot orange state
- rooted custom ROMs with Magisk, KernelSU, APatch, or similar managers
- clean OEM devices used as false-positive controls

The matrix is about repeatable evidence, not policy. A custom ROM may be allowed
for one tenant and blocked or challenged for another tenant.

## Read-Only Posture Collection

Run the posture collector before any destructive test. It does not install APKs,
uninstall APKs, clear app data, reboot the device, or require root.

```bash
cd leona-sdk-android
ADB_SERIAL=<device-serial> ./scripts/collect-device-posture.sh
```

When exactly one Android device is connected, `ADB_SERIAL` may be omitted. If
multiple devices are connected, the script fails and prints only serial hashes.

The collector writes:

- `/tmp/leona-device-posture-*/device-posture.json`
- `/tmp/leona-device-posture-*/device-posture.env`

The output is redacted by default:

- no full ADB serial
- no full Android ID
- no full build fingerprint / vendor fingerprint / boot image fingerprint
- no full bootloader version
- no full root-manager package name

Hashes are short SHA-256 prefixes for correlation only. They are not stable
identity contracts and must not be used as authoritative device IDs.

## Optional Installed-Sample Smoke

If a debug sample APK is already installed and was built with `LEONA_E2E_TOKEN`,
run the non-destructive logcat smoke after collecting posture:

```bash
cd leona-sdk-android
ADB_SERIAL=<device-serial> \
LEONA_E2E_TOKEN=<token-built-into-the-installed-debug-apk> \
./scripts/run-installed-sample-logcat-smoke.sh
```

This smoke starts the already-installed sample and reads structured `LeonaE2E`
logcat output. It does not reinstall the APK or clear app data. Use it to attach
BoxId, server verdict, and SDK diagnostic evidence to the posture report.

A future `run-rom-matrix-smoke.sh` wrapper should stay simple: call
`collect-device-posture.sh`, optionally call `run-installed-sample-logcat-smoke.sh`
when `LEONA_E2E_TOKEN` is set, and write a small manifest that links both
artifact directories. It should keep the same non-destructive guarantees.

## Evidence Families To Record

Record these facts exactly as evidence. Do not translate them into a client-side
verdict.

| Family | Examples | Expected source |
|---|---|---|
| verified boot | `verified_boot.orange`, `verified_boot.red`, `vbmeta.unlocked` | `ro.boot.verifiedbootstate`, `ro.boot.vbmeta.device_state` |
| bootloader state | `bootloader.unlocked` | `ro.boot.flash.locked` |
| verity | `verity.eio_or_disabled` | `ro.boot.veritymode` |
| build channel | `build.userdebug_or_eng`, `build.test_keys`, `build.dev_keys` | `ro.build.type`, `ro.build.tags` |
| GSI / Treble | `gsi.running`, `treble.enabled` | `ro.gsid.image_running`, `ro.treble.enabled` |
| ROM hints | `rom.lineage_like`, `rom.crdroid_like`, `rom.grapheneos_like`, `rom.aosp_like` | redacted build/product properties |
| root manager package | `root_manager.package_present` | `pm list packages` matched against known manager package names |
| SDK verdict path | BoxId, server tags, native finding ids | installed-sample logcat smoke or support bundle |

Root-manager package matches are summarized by family and package-name hashes,
not by raw package names.

`derivedEvidence` is intentionally scoped to ROM, bootloader, build-channel,
GSI/Treble, and root-manager posture. An empty value means no facts from those
families were found; it does not prove the device is a clean physical handset.
For emulators, cloud phones, or vendor-spoofed runtimes, attach an emulator
supplement artifact from SDK/native evidence or server verdict results.

## Matrix Template

Copy one row per device posture. Keep raw local notes outside committed docs if
they contain complete serials, Android IDs, or fingerprints.

| Sample | Device class | Android / API | ROM / build | Bootloader / VB state | GSI / Treble | Root manager summary | BoxId / verdict | Evidence highlights | Artifact path | Expected server policy | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Clean OEM physical | control |  |  |  |  |  |  |  |  | allow/challenge by tenant policy |  |
| OEM unlocked BL | bootloader unlocked |  |  |  |  |  |  |  |  | tenant-specific |  |
| LineageOS | custom ROM |  |  |  |  |  |  |  |  | tenant-specific |  |
| crDroid | custom ROM |  |  |  |  |  |  |  |  | tenant-specific |  |
| PixelExperience | custom ROM |  |  |  |  |  |  |  |  | tenant-specific |  |
| GrapheneOS | custom ROM |  |  |  |  |  |  |  |  | tenant-specific |  |
| Generic GSI | GSI |  |  |  |  |  |  |  |  | tenant-specific |  |
| Self-built AOSP | custom AOSP |  |  |  |  |  |  |  |  | tenant-specific |  |
| Magisk hide custom ROM | root-hidden custom ROM |  |  |  |  |  |  |  |  | tenant-specific |  |

## Artifact Checklist

For each row, keep a directory with:

- `device-posture.json`
- `device-posture.env`
- installed-sample smoke `events.json` and `summary.env`, if available
- a short `notes.md` describing the ROM source, install method, and known local
  modifications without complete serials, Android IDs, or fingerprints

Recommended artifact naming:

```text
rom-matrix/<date>-<sample-kind>-<serial-hash>/
```

Example:

```text
rom-matrix/20260430-lineageos-android14-a1b2c3d4e5f6a7b8/
```

## Review Questions

After each sample, answer:

- Did the SDK return a BoxId?
- Did the server verdict keep ROM/bootloader evidence separate from emulator
  evidence?
- Did root-manager evidence stay separate from ROM evidence?
- Did a clean OEM control avoid custom ROM / GSI / bootloader-unlocked facts?
- Were all exported artifacts redacted before sharing or committing?

If a custom ROM is spoofed to look like a retail OEM release, record the
remaining signals and mark the sample as a policy-training case rather than a
client-side miss. Hosted verdict and tenant policy decide how much weight to
give weak or contradictory evidence.
