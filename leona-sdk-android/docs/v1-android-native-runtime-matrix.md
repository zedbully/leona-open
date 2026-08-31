# Android project-native runtime matrix (W6)

`run-native-runtime-matrix.py` is a bounded, redacted smoke runner for the
project-owned `libleona.so` only. For each selected API 23--36 AVD it installs
the frozen sample/debug and SDK androidTest APKs, runs
`NativeRuntimeSmokeTest`, and records API, ABI, candidate hashes, bounded
payload size/hash, and cleanup status. The test calls native load, init, and
collect directly; it does not call `Leona.sense()`, open a reporting channel,
send HTTP, or make a business/risk decision.

The matrix distinguishes:

- `PROJECT_NATIVE_RUNTIME`: project-owned JNI load/init/collect evidence.
- `LEO_PROVIDER_RUNTIME_NOT_RUN`: no Leo provider artifact or provider
  interoperability is included in this gate.
- `NOT_RUN`/`MISSING`: an API image, ABI target, or boot was unavailable; an
  adjacent API is never substituted.

Only an exact arm64-v8a AVD selected for a cell can produce a native-runtime
`PASS`. armeabi-v7a and x86_64 remain `NOT_RUN` unless an executable target is
explicitly discovered and exercised. Candidate/APK hash drift, API/ABI
mismatch, stale/missing smoke markers, native load/crash markers, mixed
candidates, unsupported targets, and raw serial/BoxId/token fields fail closed.

The runner writes raw emulator/instrumentation logs only to a mode-0700 output
directory with mode-0600 files. The normalized summary and `SHA256SUMS` contain
hashes and status only. A matrix result is `CANDIDATE_ONLY`/`SUPPORT_ONLY` and
does not establish Android release admission, Leo provider acceptance, device
fingerprint stability, network success, or commercial admission.
