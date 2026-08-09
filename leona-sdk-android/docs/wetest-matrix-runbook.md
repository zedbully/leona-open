# WeTest Release Gate And Batch Matrix Runbook

This runbook is for collecting Leona Android SDK evidence on WeTest devices while
preserving the SDK principle: the client collects evidence only. Leona returns
environment evidence and provenance; the customer business backend owns any
product action.

The current priority is the first online release. Release-gate testing is a
smaller goal than the full security matrix: prove that representative clean OEM
devices can install the non-debug sample, run `sense()`, receive a BoxId from the
online Leona API, and show concrete evidence details in the console without
false positives. Root, Magisk, hidden-environment, clone, custom ROM, and broader
emulator coverage remain post-release matrix work unless a release-gate run
uncovers a blocker.

The same plan also applies to WDB-attached WeTest sessions, standard USB ADB
devices, and other cloud-device vendors that expose an ADB-compatible serial.

## Scope

Use WeTest for these work items:

- First online release gate: validate clean OEM devices across different brands
  and Android versions, online API connectivity, BoxId persistence, console
  display, and false-positive control.
- Post-release extended matrix: validate Root, Magisk, hidden environment,
  one-click-new-device/clone, custom ROM/GSI, cloud phone, and emulator-family
  samples using the same script and row template.

The release-gate device selection must filter by brand and Android version
before starting a device. Avoid repeatedly consuming time on an already-covered
Samsung Android 12 sample unless it is needed for a regression check.

## Release Gate Matrix

| Brand / vendor | Android version | Release-gate purpose |
| --- | --- | --- |
| Xiaomi / Redmi | Android 10 or another non-Samsung version not already covered | Online `sense()` and clean OEM false-positive control |
| vivo / iQOO | Android 14 or latest available | Modern OEM posture and online API compatibility |
| HONOR / Huawei | Android 10 or available non-GMS-like device | Mainland OEM posture and installer/display behavior |
| Asus / ROG | Android 12 or available gaming-device sample | Non-mainstream OEM compatibility |

### Current first-release status

As of 2026-05-06, the first-release gate is considered complete for the
evidence-collection launch scope:

- Public endpoint health was verified through the hosted Leona API. Internal
  console/recent-box queries are private operational checks and are not part of
  the public SDK runbook.
- Clean OEM coverage includes Asus Android 12, HONOR Android 10, Xiaomi/Redmi
  Android 10, vivo Android 10, plus prior Samsung/Xiaomi Android 12 regression
  rows.
- The latest clean OEM rows did not show actual Frida, Magisk, Xposed, unidbg,
  HONEYPOT, root, or emulator findings.
- WeTest vivo/iQOO Android 14 was attempted, but the cloud device timed out
  connecting to one SCDN HTTPS node. Treat this as a post-release network/node
  retest item, not an SDK false-positive blocker.
- Root, Magisk, hidden-environment, one-click-new-device/clone, custom ROM, and
  production attestation provider coverage move to the post-release matrix.

### Tested Device Ledger

Check this table before starting a new WeTest session. Do not retest an already
covered brand/model/Android row unless the goal is an explicit regression check.

| Date | Brand | Model / marketing name | Android | Result | Output / BoxId | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-05-06 | Samsung | SM-N9760 / Galaxy SM-N9760 | 12 | pass | BoxId hint `01KQ...W81B`; `/tmp/leona-wetest-20260506-samsung-smn9760-cloudtest-auto-sense-redacted/` | Clean OEM; canonical hash recorded; authoritative events recorded; telemetry events recorded; scorer handling for `runtime.mapping.*` was fixed and redeployed. |
| 2026-05-06 | Xiaomi | M2006J10C / Redmi K30 Ultra | 12 | pass | BoxId hint `01KQ...HSYRA`; `/tmp/leona-wetest-20260506-xiaomi-m2006j10c-cloudtest-auto-sense-redacted/` | Clean OEM; canonical hash recorded; authoritative events recorded; telemetry events recorded; hosted evidence query returned neutral clean-OEM evidence. |
| 2026-05-06 | Redmi / Xiaomi | M2007J17C / Redmi Note 9 Pro 5G | 10 | pass | BoxId hint `01KQ...W459`; `/tmp/leona-wetest-redmi-note9pro-android10-cloudtest-webshell-20260506-210142/` | Clean OEM; canonical hash recorded; authoritative events recorded; telemetry events recorded; WDB unstable, webshell direct succeeded. |
| 2026-05-06 | Asus | ASUS_I003DD / ROG Phone 3 | 12 | pass | BoxId hint `01KQ...B2QN`; `/tmp/leona-wetest-asus-android12-cloudtest-coordinate-fallback-20260506-104514/` | Clean OEM; canonical hash recorded; authoritative events recorded; telemetry events recorded; hosted evidence query returned neutral clean-OEM evidence. |
| 2026-05-06 | HONOR | OXP-AN00 / Honor Play4 Pro | 10 | pass | BoxId hint `01KQ...16Y`; `/tmp/leona-wetest-honor-play4pro-android10-cloudtest-direct-x25519fix-20260506-165904/` | Clean OEM; canonical hash recorded; authoritative events recorded; telemetry events recorded; validated Android 10 X25519 fallback. |
| 2026-05-06 | vivo / iQOO | V2049A / iQOO 7 | 14 | blocked | `/tmp/leona-wetest-vivo-iqoo7-android14-cloudtest-direct-retry-20260506-211932/` | Device posture clean; app timed out to an SCDN HTTPS node. Post-release network/node retest. |
| 2026-05-07 | vivo | V2429A / vivo S20 | 15 | blocked | `/tmp/leona-wetest-vivo-v2429a-android15-20260507-0330/` | Device posture clean and app non-debug; WDB became `offline`, webshell/UI trigger did not produce BoxId. |
| 2026-05-07 | OPPO | PCAM10 / OPPO A9 | 9 | blocked | `/tmp/leona-wetest-oppo-a9-pcam10-android9-webshell-direct-20260507-035232/` | Page install stayed at waiting state; WDB became `offline`, webshell closed before prompt. Try another OPPO model before retrying PCAM10. |
| 2026-05-07 | OPPO | PDCM00 / OPPO Reno3 | 10 | pass | BoxId hint `01KQ...BTCC`; `/tmp/leona-wetest-oppo-reno3-pdcm00-android10-webshell-direct-20260507-041037/` | Clean OEM; canonical hash recorded; authoritative events recorded; telemetry events recorded; page install stayed at waiting state but package installed, webshell direct succeeded. |
| 2026-05-07 | HUAWEI | HMA-TL00 / Huawei Mate 20 | 10 | pass | BoxId hint `01KQ...BS5M`; `/tmp/leona-wetest-huawei-mate20-hmatl00-android10-webshell-direct-retry-20260507-040055/` | Clean OEM; canonical hash recorded; authoritative events recorded; telemetry events recorded; former low-trust ROM telemetry label was fixed in SDK regression. |
| 2026-05-09 | vivo | V2031A / vivo Y73s | 10 | pass | BoxId hint `01KR...9AX`; `/tmp/leona-wetest-vivo-y73s-v2031a-android10-fixed-installed-direct-20260509-030722/` | Clean OEM; canonical hash recorded; authoritative events recorded; telemetry events recorded; fixed APK SHA-256 `8580d1a571f865b1deb1e64ed5c2b088d3e35209c4cabb25385febd84b52d544` removed the navigation-key namespace signal. |
| 2026-05-09 | realme | RMX2117 / realme Q2 5G | 10 | pass | BoxId hint `01KR...N2JZ`; `/tmp/leona-wetest-realme-q2-rmx2117-android10-clockfix-webshell-20260509-050630/` | Clean OEM; canonical hash recorded; authoritative events recorded; telemetry events recorded; rebuilt cloudTest APK SHA-256 `7cab438a664ef29c1a2e1468a2ea172b1d71d3d1c51b7b1d5a265bde4ab1b157` handled timestamp-skew recovery. |

### Static Ledger Gate

Run the static ledger gate before spending time on another WeTest device:

```bash
./scripts/verify-clean-oem-ledger.sh
```

The gate reads the Tested Device Ledger above. It does not start WeTest, ADB, or
any paid device session. It requires at least six passing mainstream clean-OEM
brand families, rejects raw BoxId values, requires redacted BoxId hints or
hashes on pass rows, requires each pass row to reference an artifact directory
and canonical / authoritative / telemetry evidence recording, and fails if any
pass row contains release-gate false-positive family terms.

For the v0.4 Android environment matrix, also run:

```bash
./scripts/verify-v0.4-android-matrix-readiness.sh
```

This gate is non-destructive: it does not start WeTest, ADB, an emulator, or any
paid device session. It reads `rom-matrix.md`, `emulator-matrix.md`, and this
runbook, verifies redaction, counts already completed matrix categories, and
reports which P0-2 samples still require external devices or emulator installs.
By default, missing external samples are recorded as
`local-pass-with-external-blockers`. Set
`LEONA_REQUIRE_FULL_V04_ANDROID_MATRIX=1` when the release gate must fail until
the full v0.4 matrix is complete.

### Known False-Positive Regression Notes

- vivo Android 10 exposes `qemu.hw.mainkeys=1` / `qemu.hw.mainkeys.vivo=0` as
  physical navigation-key properties. These keys must not be treated as QEMU or
  emulator evidence. The fixed native detector no longer probes
  `qemu.hw.mainkeys`, and the host native fixture asserts that
  `env.emulator.runtime.qemu_property_namespace` is not emitted for this case.
- On vivo Android 10, page-based upgrade install can stay on the OEM installer
  prompt. For repeatable runs, uninstall the old package first, push the APK to
  `/data/local/tmp`, let the OEM installer finish, then verify the installed APK
  hash before running direct `sense()`.
- Some WeTest devices can have a badly skewed wall clock. The server must return
  handshake `serverTimeMillis`, and secure reporting must sign uploads with the
  persisted server clock offset. Do not classify timestamp-skew upload failures
  as device environment evidence.

Release-gate success requires:

- The latest `cloudTest` or release-like non-debug APK installs and starts.
- `sense()` returns a BoxId through `https://leona.xiyanshan.com/`.
- A host-side evidence query can match the BoxId and actual authoritative event
  ids, not a rule-set summary. Operator-only endpoints are not public SDK
  dependencies.
- Clean OEM samples do not show actual Frida, Magisk, Xposed, unidbg, HONEYPOT,
  emulator, or root events unless the device really exposes that evidence.
- WeTest ADB/developer-options/helper packages are labeled as harness telemetry.
- `runtime.mapping.*` rows are runtime mapping facts. Do not describe them as
  Frida, Hook, or injection unless the same record also contains a concrete
  hook/injection family event.
- `tamper.installer.missing` on WeTest, ADB, or manual sideload lanes is an
  installer-route fact. It is expected test posture evidence unless the sample
  was installed through the intended production distribution channel.
- Each row saves redacted posture and package evidence plus the queried online
  record.

## Batch Matrix

Create one row per brand, model, Android version, install lane, and environment
type. Do not collapse Root, Magisk, hidden-Magisk, clone, or cloud-debug samples
into a single "risky device" bucket; they answer different policy questions.

| Brand / vendor | Required model coverage | Environment type | Expected collection focus |
| --- | --- | --- | --- |
| Samsung | At least one Qualcomm and one Exynos/region variant when available | Clean device | Baseline OEM posture, non-debug app flags, no emulator/root/hook findings |
| vivo / OPPO / Xiaomi / Huawei / Honor | At least one retail model per available brand | Clean device | OEM-specific build, verified boot, installer posture, false-positive control |
| Any available OEM testbed | Root | `su`, root manager, writable/system posture, server provenance separation |
| Any available OEM testbed | Magisk / Magisk Delta | Magisk package/filter hits, Zygisk-related evidence, root manager state |
| Any available OEM testbed | Hidden Magisk / environment hiding | Hide/Shamiko/DenyList-like package and runtime traces, expected possible miss notes |
| WeTest cloud phone / hosted Android | One-click new device / cloned environment | Cloud/clone markers, identity reset behavior, installer/debug posture |
| WeTest remote debug session | Cloud-test debug state | Harness-only telemetry: ADB enabled, developer options, WeTest helper packages |
| Custom ROM / GSI when available | LineageOS/crDroid/PixelExperience/GrapheneOS/GSI | ROM/bootloader facts | `rom.*`, `gsi.*`, `verified_boot.*`, `bootloader.*` evidence |

Minimum completion target for the first batch:

- 2 clean OEM devices across different brands.
- 1 Root sample.
- 1 Magisk sample.
- 1 hidden-environment sample, even when the result is "not detected"; record
  the hiding method as testbed metadata, not as a client conclusion.
- 1 one-click-new-device or clone sample.
- 1 WeTest remote-debug sample documenting harness telemetry.
- 1 online API sample with BoxId and host-side Leona evidence/provenance query.

## APK Lanes

### Release / non-debug sample

Use this lane for non-debug package posture:

- Build: `./gradlew :sample-app:assembleRelease`
- Artifact: `sample-app/build/outputs/apk/release/sample-app-release-unsigned.apk`
- Lab install artifact: sign the unsigned APK with a lab key before uploading to
  WeTest.

Expected properties:

- `android:debuggable=false`
- no `LEONA_E2E_TOKEN`
- no fake attestation implementation in the release binary
- no debug API key, debug endpoint, or LAN cleartext config

This lane can prove `sideload_release` or platform-installed non-debug posture.
It does not prove trusted distribution unless the install channel is Play, OEM
store, MDM, enterprise distribution, or another trusted channel accepted by the
server policy.

### Debug / staging sample

Use this lane only for controlled E2E and logcat smoke collection. It may include
`LEONA_E2E_TOKEN`, local/staging endpoint configuration, and debug-only fake
attestation controls. Results from this lane must be labeled as debug/staging and
must not be used as clean release conclusions.

### CloudTest / online API sample

Use this lane for online API connectivity from WeTest when the APK must remain
non-debug but still point at a staging or production Leona endpoint.

- Build:

```bash
./gradlew :sample-app:assembleCloudTest \
  -PLEONA_API_KEY="$LEONA_API_KEY" \
  -PLEONA_CLOUD_TEST_TOKEN="$LEONA_CLOUD_TEST_TOKEN" \
  -PLEONA_REPORTING_ENDPOINT=https://leona.xiyanshan.com
```

Do not pass `LEONA_API_KEY` or `LEONA_REPORTING_ENDPOINT` only as shell
environment variables. The sample app reads these values from Gradle project
properties and bakes them into `BuildConfig` at build time.

- Artifact: `sample-app/build/outputs/apk/cloudTest/sample-app-cloudTest.apk`
- Required build inputs: tenant app key, cloudTest trigger token, and HTTPS reporting endpoint.
- Expected properties: `android:debuggable=false`, no debug E2E intent, no fake
  attestation mode, and no verbose native logging.

Before uploading the APK to WeTest, verify the generated `BuildConfig`:

```bash
grep -E 'LEONA_REPORTING_ENDPOINT|LEONA_API_KEY|LEONA_CLOUD_TEST_TOKEN' \
  sample-app/build/generated/source/buildConfig/cloudTest/io/leonasec/leona/sample/BuildConfig.java
```

`LEONA_REPORTING_ENDPOINT` must be the online HTTPS endpoint and
`LEONA_API_KEY` / `LEONA_CLOUD_TEST_TOKEN` must be non-empty. Redact both values
in reports.

This lane can prove "sample can report to online Leona API from a cloud device".
It still does not prove a trusted app-store distribution posture unless the
install route is policy-approved.

## One Script For Every Device

Use `scripts/run-cloud-device-collection.sh` for every ADB-compatible row in
the matrix. The only values that should vary per row are the ADB serial, APK,
output directory, and optional debug E2E token.

```bash
cd /Users/a/back/Game/cq/leona-sdk-android

LEONA_APK=/absolute/path/to/sample-app-cloudTest.apk \
ANDROID_SERIAL=<adb-or-wdb-serial> \
LEONA_COLLECTION_OUT=/tmp/leona-wetest-<date>-<brand>-<model>-<env> \
LEONA_RUN_SECONDS=25 \
./scripts/run-cloud-device-collection.sh
```

For a debug/staging E2E row, add the token that was built into that debug APK:

```bash
LEONA_APK=/absolute/path/to/sample-app-debug.apk \
ANDROID_SERIAL=<adb-or-wdb-serial> \
LEONA_E2E_TOKEN=<debug-token> \
LEONA_COLLECTION_OUT=/tmp/leona-wetest-<date>-<brand>-<model>-debug-e2e \
./scripts/run-cloud-device-collection.sh
```

When WeTest WDB assigns a local serial such as `127.0.0.1:xxxxx`, pass that value
as `ANDROID_SERIAL`. When WDB becomes unstable or `adb devices` shows the serial
as `offline`, use the WeTest webshell fallback to collect the same fields and
save them with the same filenames listed below. Mark the transport as
`wetest-webshell` in the report:

```bash
LEONA_TRANSPORT=wetest-webshell \
WETEST_WEB_SHELL_ADDR=<from-debug-status> \
WETEST_DEVICE_ID=<device-id> \
WETEST_TEST_ID=<test-id> \
WETEST_WEB_SHELL_KEY=<secret-from-debug-status> \
LEONA_APK=/absolute/path/to/sample-app-cloudTest.apk \
LEONA_COLLECTION_OUT=/tmp/leona-wetest-<date>-<brand>-<model>-webshell \
./scripts/run-cloud-device-collection.sh
```

For cloudTest rows where the APK is already installed and the goal is to prove
online reporting, prefer direct method invocation. This sends an explicit
broadcast to the `cloudTest`-only receiver, which runs inside the sample app
process and calls `Leona.sense()` without relying on UI coordinates:

```bash
LEONA_TRIGGER_SENSE=direct \
LEONA_CLOUD_TEST_TOKEN="$LEONA_CLOUD_TEST_TOKEN" \
./scripts/run-cloud-device-collection.sh
```

The collector generates a fresh per-run correlation value automatically. The
receiver persists and logs only its short SHA-256 digest, and the host parser
rejects terminal results from an earlier run. Both UUID and ULID BoxId formats
are accepted, but only a full SHA-256 of the BoxId is retained in the generated
matrix row. Do not reuse or publish the generated correlation value.

Use UI triggering only for manual UI smoke tests:

```bash
LEONA_TRIGGER_SENSE=ui \
./scripts/run-cloud-device-collection.sh
```

The UI path performs vertical swipes, tries to locate `buttonSense` by
resource-id, falls back to the configured tap coordinate, waits for the upload,
and then records the BoxId hint/hash for host-side evidence lookup. Override `LEONA_PRE_SENSE_SWIPES`,
`LEONA_SENSE_TAP_X`, `LEONA_SENSE_TAP_Y`, and `LEONA_SENSE_WAIT_SECONDS` only
when a model has a different viewport or UI scale.

On Android 10 / API 29 devices, the private secure-reporting engine must use the
SDK's X25519 fallback when the platform does not provide `XDH` /
`X25519 KeyPairGenerator`. Treat `NoSuchAlgorithmException: XDH KeyPairGenerator
not available` as a release blocker.

Never paste the WeTest webshell key, WDB token, cookies, or CSRF token into a
report or issue. Keep them only in local shell environment files with restricted
permissions.

## Collected Files

Each device row must preserve a directory with these files:

| File | Source | Required content |
| --- | --- | --- |
| `report.md` | Script/template | Human-readable row summary and conclusion |
| `device-summary.env` | Script | Brand, manufacturer, model, Android version, APK hash, serial hash only |
| `posture.env` | Script | Selected `getprop` and settings posture values |
| `risk-package-filter.txt` | Script | Filtered package names related to root/Magisk/hide/clone only |
| `logcat.leona.txt` | Script | Leona-related logcat lines, redacted if copied into reports |
| `logcat.full.txt` | Script | Local-only diagnostic evidence; do not publish externally |
| `package.txt` | Script | Installed package flags, version, requested permissions |
| `sense-result.normalized.json` | Host parser | Current-run status, configuration flags, correlation digest, and BoxId SHA-256 only |
| `sense-result-parser.log` | Host parser | Rejection reasons only; no raw BoxId, token, or error message |
| `server-verdict.json` | Host-side query | Verdict/explain response for the BoxId, if online API succeeds |
| `matrix-row.md` | Script/template | Filled report row generated from collected posture, logcat, and recent BoxID data |

`server-verdict.json` must be queried by a host-side script or operator using
tenant credentials outside the APK. Do not embed verdict secrets in sample apps.

## WeTest Collection Steps

1. Upload the selected APK and choose a device group.
2. Record device metadata before running Leona:
   - device model, manufacturer, Android version, ABI
   - install channel and package flags when WeTest exposes them
   - whether the device is real hardware, cloud phone, emulator, or custom ROM
3. Connect through WDB/ADB and run the same collection script for the row.
4. If the script cannot run because ADB is offline, use webshell fallback and
   keep the same output filenames.
5. Start the app and run `sense()` through the normal UI or host-app flow.
6. Capture logcat and app output. Do not rely on screenshot OCR as the source of
   truth.
7. Record only redacted identifiers:
   - BoxId
   - canonical hash or hint
   - verdict id
   - attestation provider/status/code
   - authoritative risk tags
   - telemetry risk tags
   - `riskTagsBySource`
8. Query the server explain endpoint for the BoxId/verdict id when available.
   This query must use tenant-scoped server credentials outside the APK.
9. Save the sample into the matrix with expected outcome and actual outcome.

## Online API Preflight

Before spending a large batch of cloud-phone time on online API samples, verify
the public endpoint from the host and one Android device:

```bash
openssl s_client -connect leona.xiyanshan.com:443 \
  -servername leona.xiyanshan.com -showcerts </dev/null
```

The SCDN or CDN edge must serve the full certificate chain. Serving only the
leaf certificate can still work in some desktop browsers, but Android devices
may fail with `Trust anchor for certification path not found`, and `sense()` will
not receive a BoxId. For the current Leona deployment, upload `fullchain.pem` to
the SCDN certificate field, not the leaf-only `cert.pem`.

Current verified state on 2026-05-06:

- Host OpenSSL shows the full chain `leona.xiyanshan.com -> Let's Encrypt E8 ->
  ISRG Root X1` and `Verify return code: 0`.
- Xiaomi Redmi `M2006J10C` / Android 12 generated online BoxId
  BoxId hint `01KQ...HSYRA` through the script auto-sense path.
- A private host-side evidence query found no emulator/root/hook findings; the
  remaining evidence was installer/test posture. The private query endpoint and
  production deployment notes are intentionally omitted from this public SDK
  runbook.

For collection-only cloud-test rows, attestation requirements are controlled by
hosted Leona tenant policy. Public SDK docs should record provider/status/code
evidence when available, but must not include production deployment switches or
internal ops procedures.

## Minimum Device Matrix

| Group | Minimum samples | Required record |
| --- | ---: | --- |
| Clean OEM real device | 2 | No emulator/root/hook tags; release/non-debug posture preferred |
| Mainland / non-GMS OEM | 1 | Real OEM bridge or staging verifier dry run |
| Custom ROM / GSI | 2 | `rom.*`, `gsi.*`, `verified_boot.*`, `bootloader.*` evidence |
| Unlocked bootloader | 1 | `bootloader.*` and verified boot state |
| Root / Magisk testbed | 1 | Root evidence without affecting clean OEM samples |
| Cloud phone | 2 | Virtualization/cloud-phone evidence and server provenance |
| Emulator family | 4 | Runtime evidence beyond brand/model strings |

## Evidence And Interpretation Rules

- The Android SDK evidence is never a final allow/block decision.
- The report conclusion is based on the Leona evidence/provenance response, not
  on local UI text or raw logcat tags.
- `riskTags` and `authoritativeRiskTags` are Leona evidence labels. Final product
  actions must come from the customer business policy. Client headers, native
  facts, and local package filters are telemetry.
- WeTest harness facts such as `adb_enabled=1`, developer options, remote input
  packages, `com.tencent.wetest.softkeyboard`, and `com.wetest.uidump` must be
  recorded as `test_harness` telemetry.
- Root, Magisk, environment hiding, clone, and cloud-phone conclusions require
  either server provenance or a clear "observed telemetry only" note.
- A clean-device row succeeds when it uploads evidence, receives a BoxId, and the
  Leona evidence report has no emulator/root/hook/tamper findings caused by the device
  itself. Debuggable APK, sideload, ADB, or WeTest harness tags must be labeled
  as test posture when present.
- A hidden-environment row can pass as a test record even when Leona does not
  detect the hiding layer, as long as the report marks it as a coverage gap and
  does not turn the absence of evidence into an allow conclusion.

## Privacy And Redaction Rules

Allowed in shared reports:

- Redacted BoxId hint or BoxId hash.
- Verdict id.
- 16-character or full SHA-256 hash of serial, Android ID, install ID,
  canonical ID, fingerprint, and APK.
- Canonical hint generated by Leona's redacted view.
- Brand, manufacturer, marketing model, Android major version, API level, build
  type/tags, verified boot state, vbmeta state, flash locked state.
- Package names from the filtered root/Magisk/hide/clone list when needed for
  detector debugging.

Never place these values in shared reports, issue comments, PR descriptions, or
public docs:

- Raw serial number, raw Android ID, raw install ID, raw device ID, raw canonical
  device ID, raw full BoxId, raw full build fingerprint, raw bootloader string.
- API keys, secret keys, verdict signing keys, `LEONA_E2E_TOKEN`, WeTest tokens,
  WDB tokens, cookies, CSRF tokens, or private endpoint credentials.
- Full unfiltered package inventory from a personal or third-party device.
- Full `logcat.full.txt` unless it has been reviewed and redacted.

If a raw value accidentally appears in a local artifact, replace the artifact
before sharing and record the row as blocked until the clean artifact exists.

## Success Conditions

A batch is successful when all of these are true:

- Every required environment type has at least one completed row, or has an
  explicit blocked row with owner and next action.
- Each completed row has `device-summary.env`, `posture.env`,
  `risk-package-filter.txt`, `logcat.leona.txt`, `package.txt`, and a filled
  `matrix-row.md`.
- Online API rows have a BoxId hint/hash plus host-side Leona
  evidence/provenance details.
- Reports separate authoritative server risk from low-trust client telemetry.
- Privacy rules are satisfied by grep or manual review before artifacts are
  shared outside the local machine.
- The work item is updated with the sample count, representative directories,
  and remaining blockers.

## Blocking Conditions

Do not mark the related work item complete when:

- the sample only uses debug APK and debug intent automation
- the APK is release but installed only through `adb install` and no trusted
  distribution conclusion is needed
- WeTest does not expose logs, BoxId, or a server query path
- the server cannot return provenance or `riskTagsBySource`
- client header telemetry is treated as authoritative server risk
- any record contains raw device id, raw install id, raw canonical id, API key,
  token, secret, endpoint secret, or unredacted fingerprint
- the environment type is self-declared but there is no testbed evidence or
  operator note proving the Root/Magisk/hide/clone setup
- WDB/ADB/webshell cannot export logs or posture files for that row
- a true OEM/staging attestation row lacks provider/status/code/provenance

## Matrix Row Template

`scripts/run-cloud-device-collection.sh` generates `matrix-row.md`
automatically. Use this template only when a platform failure prevents the
script from reaching the report stage.

```markdown
# Leona WeTest Matrix Row

- Date:
- Operator:
- Transport: WeTest WDB / WeTest webshell fallback / USB ADB / other
- Output directory:
- APK lane: release / cloudTest / debug-staging
- APK SHA-256:

## Device

- Brand:
- Manufacturer:
- Model:
- Android version / API:
- ABI:
- Environment type: clean / root / magisk / hidden-magisk / clone / cloud-debug / custom-rom / gsi / emulator
- Testbed note:
- Serial hash:
- Android ID hash:
- Fingerprint hash:

## Run

- Script command:
- Install result:
- App debuggable: yes / no / unknown
- Install channel: WeTest lab install / ADB sideload / trusted store / unknown
- Harness telemetry present: yes / no
- Harness notes:

## Leona Result

- BoxId:
- Canonical hash or hint:
- Verdict id:
- Attestation provider:
- Attestation status:
- Attestation code:
- Leona evidence status:
- Authoritative risk tags:
- Telemetry risk tags:
- riskTagsBySource summary:

## Interpretation

- Expected outcome:
- Actual outcome:
- Pass / blocked / failed:
- Reason:
- Follow-up:

## Privacy Review

- Raw serial absent: yes / no
- Raw Android ID absent: yes / no
- Raw install/device/canonical IDs absent: yes / no
- Raw fingerprint absent: yes / no
- Secrets/tokens absent: yes / no
- Full logcat reviewed before sharing: yes / no
```
