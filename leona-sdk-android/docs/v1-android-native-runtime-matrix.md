# Android project-native runtime matrix (W6)

`run-native-runtime-matrix.py` is a bounded, redacted smoke runner for the
project-owned `libleona.so` only. For each selected API 23--36 AVD (and its
configured ABI from the allowlist) it installs the frozen sample/debug and SDK
androidTest APKs, runs
`NativeRuntimeSmokeTest`, and records API, ABI, candidate hashes, bounded
payload size/hash, runtime page size, and cleanup status. The test calls native
load, init, and collect directly; it does not call `Leona.sense()`, open a
reporting channel, send HTTP, or make a business/risk decision.

Source commit/tree identity is derived from a clean checked-out Git worktree;
dirty or malformed worktrees are rejected, and caller-supplied identity is
rejected when it disagrees. APK package and
instrumentation metadata are read from the built artifacts before any emulator
is touched. AVDs already running are classified `NOT_RUN` (`avd-busy-existing-instance`)
and are never reused or mutated; each executed lane starts an owned emulator on
an OS-probed free port. Logcat is cleared before instrumentation and only
bounded Leona/native marker or crash lines are persisted.

The native smoke marker carries the runtime page size obtained through Android
`Os.sysconf`; shell properties are only a diagnostic observation. Missing or
non-power-of-two page-size evidence fails closed.

Logcat clear has at most one retry for a transient old-API adb race; a second
failure marks the cell `FAIL`.

Source and artifact hashes are recorded as separate observations. The runner
marks their relationship `UNVERIFIED` unless a same-invocation build receipt
proves provenance; matching Git and APK hashes alone are not a build claim.

Before any AVD is started, the AAR, sample APK, and SDK androidTest APK are
opened as ZIPs. Every allowlisted ABI must contain exactly one
`libleona.so`, with the same hash in all three artifacts. The executed runtime
artifact is explicitly the `androidTest` APK; the sample APK is installed only
as the consumer-package parity target. The current instrumentation manifest
target is the test package itself (`io.leonasec.leona.test`), and any other
relationship fails closed.

The matrix distinguishes:

- `PROJECT_NATIVE_RUNTIME`: project-owned JNI load/init/collect evidence.
- `LEO_PROVIDER_RUNTIME_NOT_RUN`: no Leo provider artifact or provider
  interoperability is included in this gate.
- `NOT_RUN`/`MISSING`: an API image, ABI target, or boot was unavailable; an
  adjacent API is never substituted.

Any exact allowlisted ABI (`arm64-v8a`, `x86_64`, or `armeabi-v7a`) selected for
a cell can produce a native-runtime `PASS`; the configured ABI and runtime ABI
must match. A missing executable target remains `NOT_RUN`. Candidate/APK hash drift, API/ABI
mismatch, stale/missing smoke markers, native load/crash markers, mixed
candidates, unsupported targets, page-size failure, cleanup failure, duplicate
API selections, and raw serial/AVD/BoxId/token fields fail closed.

Raw emulator output is held only in a mode-0600 temporary file outside the
final evidence tree, then reduced to reconstructed marker/failure categories
and removed. Final instrumentation/install/logcat/emulator files are bounded
and sanitized; the normalized summary and `SHA256SUMS` contain hashes and
status only. A matrix result is `CANDIDATE_ONLY`/`SUPPORT_ONLY` and
does not establish Android release admission, Leo provider acceptance, device
fingerprint stability, network success, or commercial admission.
