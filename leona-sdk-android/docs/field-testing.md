# Field-Testing Leona

How to verify the SDK actually detects what the README claims, using real
attacker tooling. **Everything below assumes a test device you own or have
explicit permission to analyse** — never run adversarial tooling against
third-party apps.

---

## 1. Prerequisites

| Item | Why |
|------|-----|
| USB debug Android device (arm64) | Real-world validation |
| Android Studio + NDK r26+ | To build the sample app |
| `adb` on PATH | Device interaction |
| `frida` + `frida-server` | Injection detection test |
| `Unidbg` source checkout | Emulation detection test |
| (optional) rooted test device with Magisk | Root indicator test |

---

## 2. Build and install the sample app

```bash
cd leona-sdk-android
LEONA_API_KEY=<appKey> \
LEONA_REPORTING_ENDPOINT=https://<leona-api> \
./scripts/run-live-sample.sh
adb shell am start -n io.leonasec.leona.sample/.MainActivity
```

`run-live-sample.sh` builds the sample debug APK by default. If you are using a
Leona/customer backend running on your development machine, set
`LEONA_REPORTING_ENDPOINT` to an address the phone can reach on the LAN, for
example `http://192.168.x.y:<port>`. Do not use `localhost` or `127.0.0.1` for
physical-device testing unless the backend is actually running on the phone.

Tap **Run sense()**. You should see a BoxId appear. A successful result
confirms:

- `libleona.so` loaded
- JNI boundary works
- Native detectors ran without crashing
- the SDK uploaded to the configured Leona API/backend

The repository also contains an internal device E2E script that reads structured
results from `LeonaE2E` logcat events instead of scraping UI text. That path is
debug-only and requires a per-run `LEONA_E2E_TOKEN`, so a normal launcher intent
or release build will not trigger the automation.

### 2.1 Clean-device debug and sideload signals

On a clean physical device, a sample debug install can still produce
`debug.app_debuggable`, `debug.adb_enabled`,
`debug.developer_options_enabled`, and `install.sideload_or_unknown` in the
server verdict or diagnostic output.

- `debug.app_debuggable`: the APK was built with Android's debuggable flag.
  This is expected for `sample-app-debug.apk`.
- `install.sideload_or_unknown`: Android reported no trusted installer, or the
  package came from ADB/manual sideload. This is expected when installing the
  sample locally.
- `debug.adb_enabled` and `debug.developer_options_enabled`: the device is in a
  developer-test posture. They are evidence for the server; the client does not
  make the final allow/deny decision.

To verify the release/non-debug baseline, install a non-debug build through the
same channel you expect in production, then run `sense()` and query the server
verdict for the returned BoxId. If you disable Developer options or ADB after a
debug run, run `sense()` again and use the new BoxId; an older BoxId represents
the environment at the time it was minted.

---

## 3. Injection detection: Frida

### 3.1 Preparation

Download a matching `frida-server` binary for your device's architecture
from https://github.com/frida/frida/releases. Push, make executable, run as
root on the device:

```bash
adb push frida-server-16.x.y-android-arm64 /data/local/tmp/frida-server
adb shell "su -c 'chmod +x /data/local/tmp/frida-server && /data/local/tmp/frida-server &'"
```

### 3.2 Attach and re-sense

While `frida-server` is running:

```bash
frida -U -l tools/noop-hook.js io.leonasec.leona.sample
```

Re-tap **Run sense()** in the app. Check `logcat` with `verboseNativeLogging`
enabled in `LeonaConfig`:

```bash
adb logcat -s leona:V
```

Expected in the payload (check via the sample app's **Debug payload** button):

- `injection.frida.known_library` (frida-agent loaded into process)
- `injection.frida.trampoline.arm64.v1` or `.arm64.adrp.v1` (if your hook
  script rewrote any function prologues — the `noop-hook.js` does not
  rewrite by default; use `tools/rewrite-hook.js` to force trampolines)

### 3.3 What "good" looks like

The **trampoline** finding is the acid test. If you install a hook and only
the library-name finding appears, the sample isn't exercising a hooked
function path — not an SDK miss.

---

## 4. Emulator detection

### 4.1 AVD (Android Studio emulator)

Start any AVD image, install the sample, tap **Run sense()**. Expect:

- `env.emulator.avd.*` finding (Goldfish / Ranchu)
- `env.emulator.avd.qemu_pipe` file finding

### 4.2 Genymotion

Install the sample into a Genymotion instance. Expect:

- `env.emulator.genymotion.manufacturer`
- `env.emulator.genymotion.genyd_socket`
- `env.emulator.genymotion.vbox86`

### 4.3 LDPlayer / NoxPlayer / MuMu / BlueStacks

Each should trigger its dedicated model/manufacturer props plus a socket/
lib-level marker if applicable. Run on each to confirm your workload's
coverage.

---

## 5. Root and Xposed

### 5.1 Magisk

A stock rooted device (no Magisk Hide) must produce at least:

- `env.root.magisk.sbin_hidden` (if `/sbin/.magisk` reachable from app)
- `env.root.magisk.data_adb`

With Magisk Hide + Shamiko enabled, most file-based checks will be empty —
this is expected. Real defense against a hiding Magisk setup lives in
Leona's hosted backend via behavioural signals; this SDK is only responsible for
the path-level breadcrumbs.

### 5.2 LSPosed

Install LSPosed via Magisk Manager, enable for the sample app. Expect:

- `env.xposed.lsposed.zygisk_module`
- `env.xposed.lsposed.daemon_dir`
- `env.xposed.mapped_library` with path containing `liblspd.so`

---

## 6. Unidbg emulation

Running the SDK's `.so` under Unidbg requires a small Java harness because
Unidbg needs to load the library via its own VM. Reference harness:

```java
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.memory.Memory;

import java.io.File;

public class LeonaUnidbgHarness {
    public static void main(String[] args) {
        AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit()
            .setProcessName("io.leonasec.leona.sample")
            .build();

        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));

        VM vm = emulator.createDalvikVM(new File("sample-app/build/outputs/apk/debug/sample-app-debug.apk"));
        vm.loadLibrary("leona", true).callJNI_OnLoad(emulator);

        // Now invoke NativeBridge.collect() and capture the returned payload.
        // Because the sample app's sense() wraps upload, just call collect()
        // directly via the JNI harness: see test/unidbg_collect_harness.java
        // for a complete example (alpha.2).
    }
}
```

Expected findings:

- `unidbg.timer.cntfrq_zero` (default Unidbg reports CNTFRQ_EL0 = 0)
- `unidbg.timer.stuck_cntvct` (counter stays at zero across the workload)
- `unidbg.parent.non_zygote` (parent comm = `java`)
- `unidbg.proc.cpuinfo_empty` or `cpuinfo_malformed`

Any of these four constitutes a pass. **All four** is our target. A patched
Unidbg that spoofs one or two signals is the realistic adversary; the SDK
should still produce at least one.

---

## 7. Triage a false positive

If a **retail, non-rooted** device produces any `env.root.*`, `env.xposed.*`,
or `unidbg.*` event:

1. Note the exact event id.
2. Dump `/proc/self/maps` from the sample app (add an **Export maps** button
   when running verbose).
3. Note the device fingerprint: `getprop ro.product.model`, `ro.build.tags`,
   `ro.hardware`, `ro.product.manufacturer`.
4. File an issue using the bug report template with the above attached.

We budget a patch release for confirmed false positives within 2 weeks.

---

## 8. Triage a false negative

If a rooted / hooked / Unidbg'd setup produces **no** relevant events:

1. Enable `LeonaConfig.Builder().verboseNativeLogging(true)` in the sample.
2. Run `adb logcat -s leona:V` before invoking `sense()`.
3. Confirm the native library loaded (`leona init, flags=…`) and every
   detector executed at least once.
4. Capture the memory map and environment snapshot.
5. File an issue with attack tool + version and captured artefacts.

A reliable false negative is a release-blocking bug.
