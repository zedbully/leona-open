# Leona 本地执行命令总览

> 更新时间: 2026-04-24
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

脚本会自动：

1. 等待 `emulator-5554` 完成启动
2. 安装最新 sample app debug 包
3. 启动 app 并点击 `Run sense()`
4. 轮询 UI dump 提取 `BoxId`
5. 点击 `Query demo verdict`
6. 输出最终 `decision / risk / score`
7. 保存截图与 XML 到 `OUTPUT_DIR`

已验证样例：

- 执行日期：2026-04-23
- BoxId：`01KPV5E417A7467GRBRMQXYF30`
- Verdict：`decision=deny` / `risk=CRITICAL` / `score=100`
- 输出目录：`/tmp/leona-e2e-20260423-015719`

---

## 9. 本地真实联调结果参考

- 联调留档：`/Users/a/back/Game/cq/docs/demo-record-2026-04-23.md`
- Alpha release notes：`/Users/a/back/Game/cq/docs/alpha-release-notes.md`
- 观测留档：`/Users/a/back/Game/cq/docs/observability-record-2026-04-23.md`
- CI E2E 说明：`/Users/a/back/Game/cq/docs/ci-e2e-setup.md`

---

## 10. 联调完成后要做什么

1. 更新 `/Users/a/back/Game/cq/docs/acceptance-checklist.md`
2. 更新 `/Users/a/back/Game/cq/docs/final-acceptance-summary.md`
3. 如果是新的设备/场景，再补一份新的 demo record
