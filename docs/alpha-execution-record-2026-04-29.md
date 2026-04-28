# Leona Alpha 执行记录（2026-04-29）

> 时间：2026-04-29  
> 目的：按 Alpha 开发计划执行一轮发布阻塞项验证，并记录当前可交付证据与受环境限制的剩余项。

---

## 1. Git 工作区

执行：

```bash
git status --short --branch
```

结果：

- 当前分支：`main`
- 状态：clean
- 备注：本轮执行开始前已提交 alpha 开发计划与 E2E 文档修正

---

## 2. Release Preflight

执行：

```bash
/Users/a/back/Game/cq/scripts/release-preflight.sh --strict leona-sdk-android leona-server
```

结果：**PASS**

确认项：

- `leona-sdk-android` 工作区 clean
- `leona-server` 工作区 clean
- cached diff 为空
- 未发现 tracked private 文件
- 未发现 staged private 文件
- private ignore rule 存在
- 未发现可疑本地文件
- strict failures：`0`

---

## 3. Public-only 构建复验

### Android public-only

执行方式：

- 临时移走 `/Users/a/back/Game/cq/leona-sdk-android/private`
- 构建完成后恢复原目录

命令：

```bash
cd /Users/a/back/Game/cq/leona-sdk-android
./gradlew :sdk:assembleDebug :sample-app:assembleDebug --no-daemon --no-configuration-cache
```

结果：**PASS**

确认项：

- `:sdk:assembleDebug` 通过
- `:sample-app:assembleDebug` 通过
- public fallback 在没有 Android private core 时仍可构建

### Server public-only

执行方式：

- 临时移走 `/Users/a/back/Game/cq/leona-server/private`
- 构建完成后恢复原目录

命令：

```bash
cd /Users/a/back/Game/cq/leona-server
./scripts/gradlew-java21.sh :common:classes :ingestion-service:classes :worker-event-persister:classes --no-daemon --no-configuration-cache
```

结果：**PASS**

确认项：

- `:common:classes` 通过
- `:ingestion-service:classes` 通过
- `:worker-event-persister:classes` 通过
- public server 在没有 private backend 时仍可构建

---

## 4. Private 模块复验

执行：

```bash
cd /Users/a/back/Game/cq
./scripts/verify-private-modules.sh
```

结果：**PASS**

确认产物：

- Android private lib：
  `/Users/a/back/Game/cq/leona-sdk-android/private/sdk-private-core/build/intermediates/merged_native_libs/debug/mergeDebugNativeLibs/out/lib/arm64-v8a/libleona_private.so`
- Sample merged OSS lib：
  `/Users/a/back/Game/cq/leona-sdk-android/sample-app/build/intermediates/merged_native_libs/debug/mergeDebugNativeLibs/out/lib/arm64-v8a/libleona.so`
- Sample merged private lib：
  `/Users/a/back/Game/cq/leona-sdk-android/sample-app/build/intermediates/merged_native_libs/debug/mergeDebugNativeLibs/out/lib/arm64-v8a/libleona_private.so`
- Server private jar：
  `/Users/a/back/Game/cq/leona-server/private/api-backend/build/libs/private-api-backend-0.1.0-alpha.1.jar`

补充说明：

- Gradle 在 native strip 阶段输出了 unable to strip 提示，但任务整体 `BUILD SUCCESSFUL`，一键验收脚本最终通过。

---

## 5. 本地服务健康检查

检查结果：

- `http://127.0.0.1:8080/actuator/health`：`UP`
- `http://127.0.0.1:8081/actuator/health`：`UP`
- `http://127.0.0.1:8082/actuator/health`：`UP`
- `http://127.0.0.1:8083/actuator/health`：`UP`
- `http://127.0.0.1:8084/actuator/health`：`UP`
- `http://127.0.0.1:8090/health`：`ok=true`

---

## 6. Device E2E 执行记录

当前 ADB 设备：

```text
emulator-5554 device
```

未发现 USB 物理真机。因此本轮只作为 device E2E 脚本与本地闭环验证，不记为物理真机留档。

执行脚本：

```bash
ADB_SERIAL=emulator-5554 \
LEONA_AUTO_CREATE_LOCAL_SERVER_APP_KEY=1 \
LEONA_ADMIN_BASE_URL=http://127.0.0.1:8083 \
LEONA_REPORTING_ENDPOINT=http://127.0.0.1:8080 \
LEONA_FORMAL_VERDICT_BASE_URL=http://127.0.0.1:8080 \
LEONA_CLOUD_CONFIG_ENDPOINT=http://127.0.0.1:8090/v1/mobile-config \
LEONA_DEMO_BACKEND_BASE_URL=http://127.0.0.1:8090 \
LEONA_SAMPLE_ATTESTATION_MODE=oem_debug_fake \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-device-e2e.sh
```

结果：**PASS**

确认项：

- local server app key 自动创建流程通过
- sample app 构建与安装通过
- 两轮 reinstall 后 canonical device id 稳定
- formal verdict 校验通过
- UI 自动化与 artifact capture 通过

本次 canonical：

```text
Lb18efaedf98b14c0f0f8f97653fd3c1
```

产物目录：

```text
/tmp/leona-device-e2e-20260429-052846
```

安全说明：

- 本记录不保存本地自动生成的 app key / secret。

---

## 7. 当前阻塞与结论

### 已关闭

- release preflight strict
- Android public-only 构建复验
- Server public-only 构建复验
- private module split 一键复验
- device E2E 脚本本地闭环验证

### 仍受环境阻塞

- USB 物理真机 E2E 留档：当前 ADB 只发现 `emulator-5554`
- GitHub live E2E 首跑：仍需在真实 GitHub 仓库配置 secrets / variables 后执行

### Alpha 判断

> 截至 2026-04-29，Alpha P0 自动化与构建阻塞项已完成一轮真实复验；物理真机留档因当前环境无 USB 真机暂记为 blocked，不应混入模拟器结果。

