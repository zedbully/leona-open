# Leona Android SDK — Testing & Validation Plan

> Last updated for v0.1.0-alpha.1.

This document tells a QA reviewer, a security researcher, or a future
contributor **how to prove that Leona is doing what the README claims**.
Every detector listed here must have an entry showing how we verify it on
real hardware *and* how we verify it fires correctly when it should.

---

## 1. Test matrix

We validate on three categories of environment. Every release candidate
must pass on at least one entry from each column.

| Real devices (happy path) | Attacker sandboxes (should fire) | Emulators (should fire as emulator, not as attacker) |
|---|---|---|
| Pixel 6 / 7 / 8 (Android 13–15) | Rooted Pixel 5 with Magisk + Zygisk | Android Studio emulator (API 34) |
| Samsung Galaxy S22 / S23 | Pixel 5 with LSPosed module enabled | Genymotion (Android 12) |
| Xiaomi 13 / 14 | Pixel 5 running Frida 16.x | NoxPlayer (Android 9) |
| Huawei flagship (any) | Pixel 5 running Xposed on Android 7 | LDPlayer (Android 9) |
| OnePlus 11 / 12 | Unidbg host (see §5) | Samsung emulator |

At minimum you need **one real device + one rooted/Frida setup + one Unidbg
run** before cutting any tagged release.

---

## 2. Pre-flight checklist

Before running the on-device tests:

1. Build the sample app in release mode:
   ```
   ./gradlew :sample-app:assembleRelease
   ```
2. Install on the target:
   ```
   adb install -r sample-app/build/outputs/apk/release/sample-app-release.apk
   ```
3. Start `logcat` filtered to Leona:
   ```
   adb logcat -s leona
   ```
4. In the sample app, toggle **Verbose native logging** on.

---

## 3. Happy-path validation (real device, clean)

**Expected:** `Leona.sense()` returns a BoxId string. Native log emits
`leona init` and nothing alarming. The payload length is small (under 1 KB).

On a clean device, the following events are acceptable (benign):
- `environment.emulator` — must **NOT** fire.
- `environment.xposed.*` — must **NOT** fire.
- `environment.root.path_markers` — must **NOT** fire.
- `injection.ptrace.tracer_pid` — must **NOT** fire.
- `unidbg.*` — must **NOT** fire.

If any of the above fire on a stock retail device, it's a **false positive**
and blocks the release.

---

## 4. Attacker-sandbox validation

### 4.1 Frida detection

**Setup** (on a rooted Pixel 5 with Android 13):

```
adb root
adb push frida-server-16.x-android-arm64 /data/local/tmp/fs
adb shell chmod +x /data/local/tmp/fs
adb shell /data/local/tmp/fs &
```

From the host:

```
frida -U -f io.leonasec.leona.sample -l test_scripts/basic_hook.js
```

**Expected events in collection payload:**

| Event id | Required | Why |
|----------|----------|-----|
| `injection.frida.known_library` | ✅ | Library name visible in maps |
| `injection.frida.trampoline.arm64.v1` | ✅ on any hooked function | Core assembly-signature test |
| `injection.ptrace.tracer_pid` | Sometimes | Frida attaches via ptrace |

If trampoline detection does **not** fire when Frida has actively hooked a
function in the sample app, that is a **release-blocking bug**. Attach the
Frida version and a dump of `/proc/<pid>/maps` when filing the issue.

### 4.2 Xposed / LSPosed

Install LSPosed on a rooted device, enable the sample app as a module.

**Expected**: at least one of
`environment.xposed.lsposed_riru`, `environment.xposed.lsposed_zygisk`,
or `environment.xposed.filesystem` fires.

### 4.3 Magisk / KernelSU

Enable Magisk (or KernelSU) on the device without any other modifications.

**Expected**: `environment.root.path_markers` fires with `indicators`
containing `magisk_*` or `kernelsu*`.

---

## 5. Unidbg validation

### 5.1 Why Unidbg gets its own section

Unidbg is the reverse engineer's tool of choice — if our detection fails
here, attackers will extract our protocols, impersonate our clients, and
rebuild alternative clients that our BoxId pipeline cannot distinguish from
real devices.

### 5.2 Running libleona.so under Unidbg

Use the reference script bundled under `test/unidbg/` (coming with v0.1.0).
Until then, the minimal reproduction:

```java
// Pseudo-code — add in an Unidbg harness project.
AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit().build();
VM vm = emulator.createDalvikVM();
DalvikModule dm = vm.loadLibrary("leona", /*... libleona.so ...*/);
dm.callJNI_OnLoad(emulator);

// Call collect() through the native bridge and inspect the payload.
```

**Expected events in the payload:**

| Event id | Required | Notes |
|----------|----------|-------|
| `unidbg.timer.cntfrq_zero` | ✅ (default Unidbg config) | Unidbg's CNTFRQ_EL0 is 0 unless attacker patched it |
| `unidbg.timer.stuck_cntvct` | ✅ | Virtual counter barely advances during the workload |
| `unidbg.parent.non_zygote` | ✅ | Parent is `java`/JVM |
| `unidbg.proc.cpuinfo_empty` or `cpuinfo_malformed` | ✅ | Unidbg's /proc stub is partial |

All four should fire on default-configured Unidbg. An attacker can of course
patch each one away individually — that's fine. Our job is to make patching
*all* of them simultaneously expensive enough that they give up, and to
collect the patches they do make in the payload for server-side analysis.

### 5.3 Adversarial Unidbg (attacker-perfected sandbox)

If an attacker has done a serious job, timing signals may be suppressed.
Validate against this configuration too:

- Timer patched to return realistic values
- `/proc/cpuinfo` replaced with a dump from a real device
- Parent process spoofed

Even so, the combination of Frida trampoline detection (if used) plus any
remaining signal should still produce a BoxId whose server-side verdict is
non-clean.

---

## 6. Regression tests we run locally

Use the bundled closure script for the current minimum ship gate:

```bash
./scripts/verify-closure.sh
```

For a one-shot local alpha closure run, use:

```bash
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-alpha-closure.sh
```

It standardizes the exact command we currently require before device/backend
regression:

```bash
./gradlew --no-configuration-cache \
  :sdk:testDebugUnitTest \
  :sdk-private-core:assembleDebug \
  :sample-app:assembleDebug
```

For the local backend/cloud-config closure path, also run:

```bash
cd /Users/a/back/Game/cq/demo-backend
LEONA_SECRET_KEY=dev-secret go run .

# In another shell:
/Users/a/back/Game/cq/leona-sdk-android/scripts/verify-demo-cloud-config.sh
```

That smoke test verifies:

- `/v1/mobile-config` is reachable
- same fingerprint => stable `canonicalDeviceId`
- different fingerprint => different derived canonical
- `disabledSignals` and `disableCollectionWindowMs` are visible in both
  response body and headers

For a connected real device / USB device closure pass, use:

```bash
ADB_SERIAL=<device-serial> \
LEONA_API_KEY=<appKey> \
LEONA_REPORTING_ENDPOINT=http://127.0.0.1:8080 \
LEONA_FORMAL_VERDICT_BASE_URL=http://127.0.0.1:8080 \
LEONA_CLOUD_CONFIG_ENDPOINT=http://127.0.0.1:8090/v1/mobile-config \
LEONA_DEMO_BACKEND_BASE_URL=http://127.0.0.1:8090 \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-device-e2e.sh
```

That script validates:

- fresh install shows temporary `T...` device id before `sense()`
- `sense()` + cloud-config converge device id to canonical `L...`
- support bundle reflects cloud-config application
- diagnostic / transport / verdict / support-bundle canonical values align
- direct formal `/v1/verdict` response signature verifies successfully
- direct formal `/v1/verdict` returns the same canonical device id and a non-empty `deviceFingerprint`
- uninstall + reinstall still converge to the same canonical id

The script automatically installs `adb reverse tcp:8080 tcp:8080` and
`adb reverse tcp:8090 tcp:8090`, so `127.0.0.1` resolves to the developer
machine's local backend ports from the physical device.

For the compact release checklist view, see:

- `/Users/a/back/Game/cq/leona-sdk-android/docs/release-closure.md`

1. `./gradlew :sdk:testDebugUnitTest` — JVM-side invariants (payload
   scramble round-trip, BoxId equality, LeonaConfig bit encoding).
2. `./gradlew :sdk:assembleDebug :sdk:assembleRelease` — both build types
   compile for all three ABIs (`arm64-v8a`, `armeabi-v7a`, `x86_64`).
3. `./gradlew :sdk:lintRelease` — no new lint errors.

CI runs all of the above on every push (see `.github/workflows/android.yml`).

---

## 7. Release gate

A tag is blocked on any of:

- ❌ Any of §3 benign events fires on a **retail device** (false positive)
- ❌ Frida trampoline detection **misses** a live Frida hook in §4.1
- ❌ Unidbg §5.2 produces **zero** events from a default configuration
- ❌ `testDebugUnitTest` fails
- ❌ README or TESTING.md contradicts what the code actually does

Everything else is best-effort.

---

## 8. Contributing a regression

If you hit a false positive or a bypass, open an issue with:

1. Device model + Android version + kernel version
2. Whether root is present and how (Magisk / KernelSU / other)
3. Attack tool + version (Frida 16.2.x, LSPosed 1.9.x, etc.)
4. Captured payload (run sample app in `verboseNativeLogging=true` mode and
   attach the logcat output)
5. Expected event id, actual event id (or missing)

We aim to fix confirmed false positives within a patch release.
