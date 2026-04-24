# Leona Android SDK — Release Closure Gate

This is the practical ship checklist for the current alpha closure phase.

## 0. One-shot local closure

Run:

```bash
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-alpha-closure.sh
```

Default behavior:

- runs the static build gate
- starts local demo-backend on `127.0.0.1:18090`
- runs cloud-config smoke
- writes:
  - `/tmp/leona-alpha-closure-*/report.json`
  - `/tmp/leona-alpha-closure-*/report.md`

GitHub Actions also exposes the same path via
`/Users/a/back/Game/cq/leona-sdk-android/.github/workflows/android.yml`
using `workflow_dispatch -> run_alpha_closure=true`.

Optional:

```bash
RUN_EMULATOR_E2E=1 LEONA_API_KEY=<appKey> \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-alpha-closure.sh

RUN_DEVICE_E2E=1 ADB_SERIAL=<device-serial> LEONA_API_KEY=<appKey> \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-alpha-closure.sh
```

## 1. Static build gate

Run:

```bash
/Users/a/back/Game/cq/leona-sdk-android/scripts/verify-closure.sh
```

Required result:

- `:sdk:testDebugUnitTest` green
- `:sdk-private-core:assembleDebug` green
- `:sample-app:assembleDebug` green

## 2. Local backend / cloud-config gate

Start demo backend:

```bash
cd /Users/a/back/Game/cq/demo-backend
LEONA_SECRET_KEY=dev-secret go run .
```

Then run:

```bash
/Users/a/back/Game/cq/leona-sdk-android/scripts/verify-demo-cloud-config.sh
```

Required result:

- `/v1/mobile-config` reachable
- same fingerprint => same canonical device id
- different fingerprint => different canonical device id
- disabled signals + collection window visible in headers and body

## 3. Emulator E2E gate

Run:

```bash
LEONA_API_KEY=<appKey> \
LEONA_REPORTING_ENDPOINT=http://10.0.2.2:8080 \
LEONA_CLOUD_CONFIG_ENDPOINT=http://10.0.2.2:8090/v1/mobile-config \
LEONA_DEMO_BACKEND_BASE_URL=http://10.0.2.2:8090 \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-e2e.sh
```

Required result:

- `sense()` succeeds
- `deviceId` converges to `L...`
- support bundle shows cloud-config applied
- diagnostic / transport / verdict / support bundle canonical values align

## 4. Physical-device E2E gate

Run:

```bash
ADB_SERIAL=<device-serial> \
LEONA_API_KEY=<appKey> \
LEONA_REPORTING_ENDPOINT=http://127.0.0.1:8080 \
LEONA_CLOUD_CONFIG_ENDPOINT=http://127.0.0.1:8090/v1/mobile-config \
LEONA_DEMO_BACKEND_BASE_URL=http://127.0.0.1:8090 \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-device-e2e.sh
```

Artifacts:

- report JSON: `/tmp/leona-device-e2e-*/report.json`
- report Markdown: `/tmp/leona-device-e2e-*/report.md`

Required result:

- before `sense()`, device id is `T...`
- after `sense()`, device id is `L...`
- consistency report says `aligned=true`
- uninstall + reinstall still converge to the same canonical device id

## 5. Manual release stop conditions

Do not cut a release if any of these is true:

- stock retail device triggers root / xposed / unidbg style findings
- canonical device id flips unexpectedly across reinstall on the same app/device
- support bundle lacks cloud-config evidence when cloud-config is enabled
- verdict / transport / diagnostics disagree on canonical device id
- parity tests detect config/policy/parser/integrity drift
