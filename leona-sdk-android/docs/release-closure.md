# Leona Android SDK — Release Closure Gate

This is the practical ship checklist for the current alpha closure phase.

## 0. One-shot local closure

Run:

```bash
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-alpha-closure.sh
```

Default behavior:

- runs the static build gate
- starts local demo-backend on an isolated random localhost port
- uses an isolated demo canonical store under the closure output directory
- runs cloud-config smoke
- writes:
  - `/tmp/leona-alpha-closure-*/report.json`
  - `/tmp/leona-alpha-closure-*/report.md`
  - `/tmp/leona-alpha-closure-*/demo-cloud-store.json`

GitHub Actions also exposes the same path via
`/Users/a/back/Game/cq/leona-sdk-android/.github/workflows/android.yml`
using `workflow_dispatch -> run_alpha_closure=true`.

Hosted attestation-summary regression is exposed separately via
`workflow_dispatch -> run_live_attestation_e2e=true`.
The hosted job defaults to `debug_fake`; set repo variable
`LEONA_E2E_ATTESTATION_MODE=oem_debug_fake` when the target backend has the
private OEM verifier path enabled.

Optional:

```bash
RUN_ATTESTATION_E2E=1 LEONA_API_KEY=<appKey> \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-alpha-closure.sh

RUN_EMULATOR_E2E=1 LEONA_API_KEY=<appKey> \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-alpha-closure.sh

RUN_DEVICE_E2E=1 ADB_SERIAL=<device-serial> LEONA_API_KEY=<appKey> \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-alpha-closure.sh
```

If local `leona-server` is already running on `127.0.0.1:8080` / `:8083`,
you can let the SDK scripts auto-create a fresh AppKey through local
`admin-service` and use the formal handshake path without manually copying a
credential:

```bash
RUN_EMULATOR_E2E=1 \
LEONA_AUTO_CREATE_LOCAL_SERVER_APP_KEY=1 \
LEONA_ADMIN_BASE_URL=http://127.0.0.1:8083 \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-alpha-closure.sh

RUN_DEVICE_E2E=1 \
ADB_SERIAL=<device-serial> \
LEONA_AUTO_CREATE_LOCAL_SERVER_APP_KEY=1 \
LEONA_ADMIN_BASE_URL=http://127.0.0.1:8083 \
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
DEMO_CLOUD_STORE_PATH=/tmp/leona-demo-cloud-store.json \
LEONA_SECRET_KEY=dev-secret go run .
```

Then run:

```bash
/Users/a/back/Game/cq/leona-sdk-android/scripts/verify-demo-cloud-config.sh
```

Required result:

- `/v1/mobile-config` reachable
- same `tenant + app + fingerprint` => same canonical device id
- different fingerprint => different canonical device id
- different tenant => different canonical device id
- different app => different canonical device id
- provided canonical id is echoed and backfilled to device/install fallback lookup
- disabled signals + collection window visible in headers and body

## 3. Attestation summary E2E gate

Run:

```bash
LEONA_API_KEY=<appKey> \
LEONA_HOST_BASE_URL=http://127.0.0.1:8080 \
LEONA_REPORTING_ENDPOINT=http://10.0.2.2:8080 \
LEONA_SAMPLE_ATTESTATION_MODE=debug_fake \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-attestation-e2e.sh
```

Artifacts:

- `/tmp/leona-attestation-e2e-*/handshake-response.json`
- `/tmp/leona-attestation-e2e-*/attestation-e2e-report.json`

Required result:

- server `/v1/handshake` returns `deviceBindingStatus`
- server `/v1/handshake` returns structured `attestation`
- Android `transportSummary` shows the same provider / status / code
- Android `supportBundleSummary` shows the same provider / status / code
- Android raw `transportJson` / `supportBundleJson` exactly match server handshake attestation summary

## 4. Emulator E2E gate

Run:

```bash
LEONA_AUTO_CREATE_LOCAL_SERVER_APP_KEY=1 \
LEONA_ADMIN_BASE_URL=http://127.0.0.1:8083 \
LEONA_REPORTING_ENDPOINT=http://10.0.2.2:8080 \
LEONA_CLOUD_CONFIG_ENDPOINT=http://10.0.2.2:8090/v1/mobile-config \
LEONA_DEMO_BACKEND_BASE_URL=http://10.0.2.2:8090 \
LEONA_SAMPLE_ATTESTATION_MODE=oem_debug_fake \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-e2e.sh
```

Required result:

- `sense()` succeeds
- `deviceId` converges to `L...`
- support bundle shows cloud-config applied
- transport shows `bindingPresent=true` and `lastHandshakeError=-`
- verdict echoes the same `canonical=L...`

## 5. Physical-device E2E gate

Run:

```bash
ADB_SERIAL=<device-serial> \
LEONA_AUTO_CREATE_LOCAL_SERVER_APP_KEY=1 \
LEONA_ADMIN_BASE_URL=http://127.0.0.1:8083 \
LEONA_REPORTING_ENDPOINT=http://127.0.0.1:8080 \
LEONA_FORMAL_VERDICT_BASE_URL=http://127.0.0.1:8080 \
LEONA_CLOUD_CONFIG_ENDPOINT=http://127.0.0.1:8090/v1/mobile-config \
LEONA_DEMO_BACKEND_BASE_URL=http://127.0.0.1:8090 \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-device-e2e.sh
```

Artifacts:

- report JSON: `/tmp/leona-device-e2e-*/report.json`
- report Markdown: `/tmp/leona-device-e2e-*/report.md`
- per-cycle JSON: `/tmp/leona-device-e2e-*/first-report.json`, `/tmp/leona-device-e2e-*/second-report.json`
- per-surface JSON dumps: `first-*.json`, `second-*.json`

Required result:

- before `sense()`, device id is `T...`
- after `sense()`, device id is `L...`
- consistency report says `aligned=true`
- diagnostic / transport / support-bundle / verdict raw JSON all converge to the same canonical device id
- direct formal `/v1/verdict` response signature verifies successfully
- direct formal `/v1/verdict` returns the same canonical device id and a non-empty `deviceFingerprint`
- support bundle raw JSON contains cloud-config evidence (`cloudConfigFetchedAtMillis`, `cloudConfigRaw`, `effectiveDisabledSignals`)
- uninstall + reinstall still converge to the same canonical device id

Optional clean-retail regression gate:

```bash
LEONA_EXPECT_CLEAN_DEVICE=1 \
ADB_SERIAL=<device-serial> \
LEONA_AUTO_CREATE_LOCAL_SERVER_APP_KEY=1 \
LEONA_ADMIN_BASE_URL=http://127.0.0.1:8083 \
LEONA_REPORTING_ENDPOINT=http://127.0.0.1:8080 \
LEONA_FORMAL_VERDICT_BASE_URL=http://127.0.0.1:8080 \
LEONA_CLOUD_CONFIG_ENDPOINT=http://127.0.0.1:8090/v1/mobile-config \
LEONA_DEMO_BACKEND_BASE_URL=http://127.0.0.1:8090 \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-device-e2e.sh
```

When enabled, the gate also fails if local/server/native risk surfaces contain retail-hostile indicators such as root / magisk / xposed / frida / unidbg style hits.

## 6. 收口策略

Alpha 收口按三层执行：

1. **代码冻结面**
   - 只允许修复 false-positive、canonical 漂移、cloud-config 解析漂移
   - 暂停新增信号和新增 native 检测项
2. **环境验证面**
   - 至少保留 1 台 retail 真机 + 1 台 root/Frida 验证机
   - 每次候选包都跑 `run-alpha-closure.sh`
   - 发版前补跑一次 `run-device-e2e.sh`
3. **线上灰度面**
   - 先给 sample tenant / internal app 放量
   - 观察 canonical 稳定率、sense 成功率、误报率
   - 仅在 support bundle / verdict / diagnostic 三面一致时扩大流量

## 7. Manual release stop conditions

Do not cut a release if any of these is true:

- stock retail device triggers root / xposed / unidbg style findings
- canonical device id flips unexpectedly across reinstall on the same app/device
- support bundle lacks cloud-config evidence when cloud-config is enabled
- handshake / transport / support bundle attestation summaries disagree
- verdict / transport / diagnostics disagree on canonical device id
- parity tests detect config/policy/parser/integrity drift
- tenant/app scoped cloud-config requests collapse onto the same canonical id unexpectedly
