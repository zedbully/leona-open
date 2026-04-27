# Leona 本地执行命令总览

> 更新时间: 2026-04-27
> 用途：把当前项目最常用的本地命令集中到一页，方便直接执行。

---

## 1. leona-server Gradle

```bash
cd /Users/a/back/Game/cq/leona-server
./scripts/gradlew-java21.sh test
./scripts/gradlew-java21.sh build
```

---

## 2. 启动 server 栈

本地 `local` profile 如需额外 Spring 配置，可从以下示例模板复制：

```bash
cp /Users/a/back/Game/cq/leona-server/admin-service/src/main/resources/application-local.example.yml \
   /Users/a/back/Game/cq/leona-server/admin-service/src/main/resources/application-local.yml
```

```bash
cd /Users/a/back/Game/cq/leona-server/deploy/docker-compose
docker compose up -d --build
```

健康检查：

```bash
cd /Users/a/back/Game/cq/leona-server/deploy/docker-compose
for p in 8080 8081 8082 8083 8084; do
  echo "===== :$p ====="
  curl -sS http://localhost:$p/actuator/health
  echo
  echo
done
```

---

## 3. 启动 demo backend

```bash
cd /Users/a/back/Game/cq/demo-backend
GOCACHE=/Users/a/back/Game/cq/.gocache \
LEONA_BASE_URL=http://localhost:8080 \
LEONA_SECRET_KEY=<secretKey> \
go run .
```

---

## 3.1 本地 / 线上数据同步

执行包：

- `/Users/a/back/Game/cq/scripts/sync-online-data-preflight.sh`
- `/Users/a/back/Game/cq/scripts/sync-online-data-to-local.sh`
- `/Users/a/back/Game/cq/scripts/run-online-sync.sh`
- `/Users/a/back/Game/cq/docs/online-data-sync-runbook.md`
- `/Users/a/back/Game/cq/docs/examples/online-sync.env.example`
- `/Users/a/back/Game/cq/.env.local-sync.example`

默认是 dry-run，不会改本地数据：

```bash
cp /Users/a/back/Game/cq/.env.local-sync.example /Users/a/back/Game/cq/.env.local-sync
SYNC_MODE=preflight /Users/a/back/Game/cq/scripts/run-online-sync.sh
SYNC_MODE=dry-run /Users/a/back/Game/cq/scripts/run-online-sync.sh
```

真正执行时，显式传：

```bash
SYNC_MODE=apply /Users/a/back/Game/cq/scripts/run-online-sync.sh
```

---

## 4. Android 构建环境

```bash
export JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
export ANDROID_SDK_ROOT=/Users/a/Library/Android/sdk
export GRADLE_USER_HOME=/Users/a/back/Game/cq/.gradle-home
```

---

## 5. 构建 Android AAR + sample app

```bash
cd /Users/a/back/Game/cq/leona-sdk-android
./gradlew :sdk:testDebugUnitTest :sdk:assembleRelease :sample-app:assembleDebug \
  --no-daemon --no-configuration-cache --stacktrace
```

产物：

```bash
/Users/a/back/Game/cq/leona-sdk-android/sdk/build/outputs/aar/sdk-release.aar
/Users/a/back/Game/cq/leona-sdk-android/sample-app/build/outputs/apk/debug/sample-app-debug.apk
```

---

## 6. 模拟器启动

当前已验证可用：

- AVD：`leona-api34`
- emulator：`/opt/homebrew/share/android-commandlinetools/emulator/emulator`

后台启动示例：

```bash
ANDROID_SDK_ROOT=/opt/homebrew/share/android-commandlinetools \
nohup /opt/homebrew/share/android-commandlinetools/emulator/emulator @leona-api34 \
  -no-snapshot -no-boot-anim -gpu swiftshader_indirect -no-audio -no-window \
  >/tmp/leona-emulator.log 2>&1 &
```

检查：

```bash
adb devices -l
adb -s emulator-5554 shell getprop sys.boot_completed
```

---

## 7. 构建 / 安装真实联调版 sample app

```bash
LEONA_API_KEY=<appKey> \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-live-sample.sh
```

默认行为：

- 有 adb 设备：自动 `installDebug`
- 无 adb 设备：自动 `assembleDebug`

默认 endpoint：

- `LEONA_REPORTING_ENDPOINT=http://10.0.2.2:8080`
- `LEONA_DEMO_BACKEND_BASE_URL=http://10.0.2.2:8090`

---

## 8. 一键执行模拟器 E2E 自动化

```bash
LEONA_API_KEY=<appKey> \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-e2e.sh
```

本地 formal server 全链路推荐命令：

```bash
LEONA_AUTO_CREATE_LOCAL_SERVER_APP_KEY=1 \
LEONA_ADMIN_BASE_URL=http://127.0.0.1:8083 \
LEONA_REPORTING_ENDPOINT=http://10.0.2.2:8080 \
LEONA_FORMAL_VERDICT_BASE_URL=http://127.0.0.1:8080 \
LEONA_CLOUD_CONFIG_ENDPOINT=http://10.0.2.2:8090/v1/mobile-config \
LEONA_DEMO_BACKEND_BASE_URL=http://10.0.2.2:8090 \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-e2e.sh
```

脚本会自动：

1. 等待 `emulator-5554` 完成启动
2. 安装最新 sample app debug 包
3. 启动 app 并点击 `Run sense()`
4. 轮询 UI dump 提取 `BoxId`
5. 点击 `Query demo verdict`
6. 再 mint 一个新 BoxId，直接调用 formal `/v1/verdict`
7. 校验 formal verdict response signature、`canonicalDeviceId`、`deviceFingerprint`
8. 输出最终 `decision / risk / score` 以及 formal verdict 摘要
9. 保存截图、XML 与 JSON 到 `OUTPUT_DIR`

已验证样例：

- 执行日期：2026-04-27
- UI / demo verdict BoxId：`01KQ792YC06BAEHG4WQZH308WX`
- formal `/v1/verdict` BoxId：`01KQ794PAP1N9SXQVQ501B1075`
- canonical：`L8a5d40fa9aa6a9ebd14101ef9b62c5b`
- Verdict：`decision=deny` / `risk=CRITICAL` / `score=100`
- 输出目录：`/tmp/leona-e2e-20260427-185131`

---

## 9. 一键执行 attestation 摘要回归

用于验证：

- server `/v1/handshake` 是否返回 `deviceBindingStatus + attestation`
- Android sample 的 `transport / support bundle` 是否透传同一份摘要

```bash
LEONA_API_KEY=<appKey> \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-attestation-e2e.sh
```

默认参数：

- host handshake 校验：`http://127.0.0.1:8080`
- emulator sample endpoint：`http://10.0.2.2:8080`
- attestation mode：`debug_fake`

输出目录示例：

- `/tmp/leona-attestation-e2e-20260425-000000`

关键产物：

- `handshake-response.json`
- `attestation-e2e-report.json`

---

## 9.1 一键执行真机 attestation 摘要回归

用于验证：

- 真机通过 `adb reverse` 访问本地 `:8080`
- server `/v1/handshake` 返回 `deviceBindingStatus + attestation`
- Android sample 的 `transport / support bundle` 透传同一份摘要

```bash
ADB_SERIAL=<device-serial> \
LEONA_API_KEY=<appKey> \
LEONA_SAMPLE_ATTESTATION_MODE=debug_fake \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-device-attestation-e2e.sh
```

OEM debug 模式：

```bash
ADB_SERIAL=<device-serial> \
LEONA_API_KEY=<appKey> \
LEONA_SAMPLE_ATTESTATION_MODE=oem_debug_fake \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-device-attestation-e2e.sh
```

参考：

- `/Users/a/back/Game/cq/docs/physical-attestation-runbook.md`
- `/Users/a/back/Game/cq/docs/device-attestation-record-template.md`

---

## 10. 本地真实联调结果参考

- 联调留档：`/Users/a/back/Game/cq/docs/demo-record-2026-04-23.md`
- attestation 摘要专项留档：`/Users/a/back/Game/cq/docs/attestation-record-2026-04-25.md`
- mainland OEM 留档：`/Users/a/back/Game/cq/docs/mainland-attestation-record-2026-04-25.md`
- 真机 attestation 执行包：`/Users/a/back/Game/cq/docs/physical-attestation-runbook.md`
- Alpha release notes：`/Users/a/back/Game/cq/docs/alpha-release-notes.md`
- 观测留档：`/Users/a/back/Game/cq/docs/observability-record-2026-04-23.md`
- CI E2E 说明：`/Users/a/back/Game/cq/docs/ci-e2e-setup.md`

---

## 11. 联调完成后要做什么

1. 更新 `/Users/a/back/Game/cq/docs/acceptance-checklist.md`
2. 更新 `/Users/a/back/Game/cq/docs/final-acceptance-summary.md`
3. 如果是新的设备/场景，再补一份新的 demo / attestation record
