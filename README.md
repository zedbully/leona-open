# Leona

Leona 是一个面向 Android 的运行时安全 alpha 项目，核心架构是：

```text
Android SDK -> Leona Server -> BoxId -> 客户业务后端 -> Verdict
```

客户端只拿到不透明的 `BoxId`。真正的风险判定、签名校验、风控动作在服务端完成，避免把 `isRooted()` / `isTampered()` 这类可被 patch 的判断暴露给 APK。

当前公开仓库是 Leona 的 open-source shell，包含可构建、可演示、可接入的公开边界。高价值 detector catalog、私有风控策略、生产密钥与内部运维能力应继续放在 private core / private backend 中，不进入公开仓库。

## 当前版本

- Public alpha tag: `v0.1.0-alpha.1`
- GitHub: [zedbully/leona-open](https://github.com/zedbully/leona-open)
- 更新时间: 2026-04-29
- 当前状态: Android SDK + Server + Demo Backend 已在本地模拟器和 MuMu 上跑通完整闭环；MuMu 已验证原理级模拟器证据上报与服务端 `environment.emulator.detected` 判定标签；CLI 仍是 placeholder。
- 当前工作项入口: [`docs/work-items.md`](docs/work-items.md)

## 仓库结构

```text
.
├── leona-sdk-android/   # Android SDK、sample app、E2E 脚本、Android CI workflow
├── leona-server/        # gateway / ingestion / query / admin / worker 服务
├── demo-backend/        # 客户业务后端的最小示例
├── leona/               # CLI skeleton
├── docs/                # 状态、验收、接入、发布、runbook
└── scripts/             # release preflight、本地/线上数据同步等脚本
```

## 完整功能点

### 1. Android SDK

- Public API
  - `Leona.init(context, config)`
  - `Leona.sense()`
  - `Leona.senseAsync(callback)`
  - `Leona.getDeviceId()`
  - `Leona.getDiagnosticSnapshot()`
  - `Leona.getLastServerVerdict()`
  - `BoxId`
  - `LeonaConfig`
  - `Honeypot`
  - `quickCheck()` decoy API
- BoxId 模型
  - app 调用 `sense()` 后只获得不透明 `BoxId`
  - app 把 `BoxId` 带给自己的业务后端
  - 业务后端调用 Leona `/v1/verdict` 获得服务端 verdict
  - `BoxId` 按 single-use 语义设计，不应反复查询同一个 `BoxId`
- 安全传输
  - handshake / sense / verdict 主链路
  - X25519、HKDF、AES-GCM、HMAC 相关实现
  - timestamp / nonce / replay guard
  - verdict response signature 校验链路
- 设备身份
  - 本地临时 ID: `T...`
  - 服务端 canonical ID: `L...`
  - cloud-config 与 server verdict 可推动 `T... -> L...` 收敛
  - diagnostic / transport / support bundle / verdict 多 surface 对齐校验
- Cloud config
  - 支持 `LEONA_CLOUD_CONFIG_ENDPOINT`
  - 支持 `disabledSignals`
  - 支持 `disableCollectionWindowMs`
  - 支持 tenant / app / fingerprint 维度的 canonical device store 演示链路
- 运行时风险采集
  - Java/Kotlin 层身份与设备上下文采集
  - JNI / C++ native payload 采集
  - native risk tags / finding ids / highest severity 摘要
  - Frida / ptrace / trampoline、emulator、root / Magisk / KernelSU / Riru、Xposed / LSPosed / EdXposed、Unidbg 等检测族的公开 fallback 面
  - 模拟器原理级 native 证据：hypervisor/QEMU、guest control service、guest metadata、CPU 虚拟化、virtio/9p 共享挂载、QEMU NAT 网段、设备身份伪装与运行时矛盾
- Tamper baseline
  - package name
  - installer allowlist
  - signing certificate / signing lineage
  - APK / split APK / signing block
  - native library / ELF section / ELF export
  - AndroidManifest entry
  - resources.arsc / resource inventory / resource entry
  - DEX file / DEX section / method hash
  - permission / component / provider / intent-filter / uses-feature / uses-sdk / uses-library 等 manifest 语义基线
- Attestation
  - Play Integrity / debug fake 演示模式
  - `AttestationProvider` 插拔点
  - Mainland / 非 GMS 路径支持 `oem_debug_fake` / `oem_bridge`
  - server 侧可把 `oem_attestation` 路由到 private verifier
  - transport summary 与 support bundle summary 可透传 attestation 摘要
- Sample app
  - 可通过 Gradle property 注入 app key、tenant、endpoint
  - 支持本地 server / demo backend 联调
  - 支持 debug fake / OEM debug fake attestation 模式
  - 支持一键构建、安装、模拟器 E2E、真机 E2E
- Private runtime 边界
  - public `NativeRuntime` 保留 fallback runtime
  - private 版本可通过 `sdk-private-core` 与 `libleona_private.so` 扩展
  - 高价值 native detector 与私有 JNI bridge 不进入公开仓库

### 2. Leona Server

- 多服务结构
  - `gateway`
  - `ingestion-service`
  - `query-service`
  - `admin-service`
  - `worker-event-persister`
  - `common`
- API
  - `POST /v1/handshake`
  - `POST /v1/sense`
  - `POST /v1/verdict`
  - tenant / key 管理接口: create、create-key、rotate、revoke
  - actuator health / info / prometheus
- 协议与安全
  - app key / tenant 归属
  - HMAC 校验
  - timestamp 校验
  - nonce replay guard
  - Redis key lookup
  - AES-GCM 解密
  - TLV payload 解析
  - BoxId 生成、claim、过期与 single-use
  - verdict 响应签名
- 数据链路
  - Redis verdict cache
  - PostgreSQL 持久化
  - Kafka parsed events
  - worker 风险评分
  - query-service verdict 查询
- Admin 能力
  - tenant 创建
  - app key 创建、吊销、轮换
  - private-only internal ops endpoint bridge
- Observability
  - Micrometer / actuator
  - Prometheus scrape
  - Prometheus alert rules
  - Grafana datasource / dashboard provisioning
  - Kafdrop 本地 Kafka UI
- Tamper baseline 配置
  - `LEONA_HANDSHAKE_TAMPER_BASELINE_PATH`
  - `LEONA_HANDSHAKE_TAMPER_BASELINE_JSON`
  - 启动时 schema 校验
  - `/actuator/info` 输出 sanitized `handshakeTamperBaseline`
- Private backend 边界
  - public server 保留协议、fallback scorer、桥接点
  - private backend 可承载真实风险权重、tenant / stage / deployment-profile 策略、internal ops
  - private 风控配置不进入公开仓库

### 3. Demo Backend

- 模拟客户业务后端
- 接收 Android sample 传来的 `BoxId`
- 调用 Leona `/v1/verdict`
- 校验 verdict response signature
- 返回 sample app 可展示的 `decision / riskLevel / riskScore`
- 提供本地 `/v1/mobile-config`
- 提供 canonical device store 演示

### 4. CLI

- `leona` CLI 已有命令骨架
- `version` 可用
- `scan` / `rules list` 仍是 placeholder
- 当前主线不是 CLI scanner，而是 Android runtime SDK + server verdict pipeline

### 5. 文档与自动化

- 本地执行入口: `docs/local-runbook.md`
- 文档索引: `docs/README.md`
- 总体验收: `docs/final-acceptance-summary.md`
- release closure gate: `leona-sdk-android/docs/release-closure.md`
- Mainland / 非 GMS: `docs/mainland-closeout-summary.md`
- GitHub manual live emulator / attestation workflow: `leona-sdk-android/.github/workflows/android.yml`
- 本地/线上数据同步执行包: `docs/online-data-sync-runbook.md`

## 接入步骤

### 1. 准备环境

推荐环境：

- JDK 21
- Android SDK API 34
- Android NDK `26.3.11579264`
- Docker Desktop / Docker Compose
- Go 1.22+
- `adb`

本地常用环境变量：

```bash
export JAVA_HOME=$(/usr/libexec/java_home -v 21)
export ANDROID_SDK_ROOT=/Users/a/Library/Android/sdk
export GRADLE_USER_HOME=/Users/a/back/Game/cq/.gradle-home
```

### 2. 启动 Leona Server 本地栈

```bash
cd /Users/a/back/Game/cq/leona-server/deploy/docker-compose
docker compose up -d --build
```

健康检查：

```bash
for p in 8080 8081 8082 8083 8084; do
  echo "===== :$p ====="
  curl -sS http://localhost:$p/actuator/health
  echo
done
```

默认端口：

| Port | Service |
|---|---|
| `8080` | gateway |
| `8081` | ingestion-service |
| `8082` | query-service |
| `8083` | admin-service |
| `8084` | worker-event-persister |
| `9000` | Kafdrop |
| `9090` | Prometheus |
| `3000` | Grafana |

### 3. 获取 tenant / app key / secret key

本地联调最省事的方式是让脚本通过 `admin-service` 自动创建 app key：

```bash
LEONA_AUTO_CREATE_LOCAL_SERVER_APP_KEY=1 \
LEONA_ADMIN_BASE_URL=http://127.0.0.1:8083 \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-live-sample.sh
```

如果要手动管理 key，使用 admin-service 的 tenant / key 管理接口。业务后端需要保存：

- `tenantId`
- `appKey`
- `secretKey`

### 4. 启动 Demo Backend

```bash
cd /Users/a/back/Game/cq/demo-backend
GOCACHE=/Users/a/back/Game/cq/.gocache \
LEONA_BASE_URL=http://localhost:8080 \
LEONA_SECRET_KEY=<secretKey> \
go run .
```

检查：

```bash
curl http://localhost:8090/health
```

### 5. Android App 接入 SDK

当前仓库内 sample 使用源码模块依赖：

```kotlin
dependencies {
    implementation(project(":sdk"))
}
```

如果接入外部 App，可以先构建 AAR：

```bash
cd /Users/a/back/Game/cq/leona-sdk-android
./gradlew :sdk:assembleRelease --no-daemon --no-configuration-cache --stacktrace
```

产物：

```text
/Users/a/back/Game/cq/leona-sdk-android/sdk/build/outputs/aar/sdk-release.aar
```

App 初始化示例：

```kotlin
class App : Application() {
    override fun onCreate() {
        super.onCreate()

        Leona.init(
            this,
            LeonaConfig.Builder()
                .apiKey("<appKey>")
                .tenantId("<tenantId>")
                .reportingEndpoint("https://<your-leona-gateway>")
                .cloudConfigEndpoint("https://<your-demo-or-policy-backend>/v1/mobile-config")
                .appId("your-android-app")
                .region(LeonaRegion.APAC)
                .expectedPackageName("com.example.app")
                .allowedInstallerPackages("com.android.vending")
                .allowedSigningCertSha256("<release-signing-cert-sha256>")
                .build(),
        )
    }
}
```

业务流程示例：

```kotlin
val boxId = Leona.sense()

// 把 boxId.value 放进你自己的业务请求。
// 不要在客户端根据本地检测结果做最终 allow / deny。
yourBackendApi.login(
    username = username,
    password = password,
    leonaBoxId = boxId.value,
)
```

### 6. 业务后端接入 verdict

你的业务后端收到 `BoxId` 后调用 Leona gateway：

```bash
curl -X POST http://localhost:8080/v1/verdict \
  -H "Content-Type: application/json" \
  -H "X-Leona-App-Key: <appKey>" \
  -d '{"boxId":"<boxId>"}'
```

业务后端必须做：

- 校验 Leona verdict response signature
- 按 `decision / riskLevel / riskScore / riskTags` 决定 allow、challenge、deny 或 honeypot
- 只把业务需要的安全结果返回给 App
- 不把 Leona 私有策略、secret key、签名密钥下发到客户端

`demo-backend` 已提供最小参考实现。

### 7. 构建并安装 sample app

模拟器使用 `10.0.2.2` 访问宿主机：

```bash
LEONA_API_KEY=<appKey> \
LEONA_REPORTING_ENDPOINT=http://10.0.2.2:8080 \
LEONA_CLOUD_CONFIG_ENDPOINT=http://10.0.2.2:8090/v1/mobile-config \
LEONA_DEMO_BACKEND_BASE_URL=http://10.0.2.2:8090 \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-live-sample.sh
```

真机不要使用 `10.0.2.2`。可使用 `adb reverse` 或电脑局域网 IP。

### 8. 接入 attestation

Play Integrity / GMS 环境：

```bash
LEONA_SAMPLE_ATTESTATION_MODE=debug_fake \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-attestation-e2e.sh
```

Mainland / 非 GMS 路径：

```bash
LEONA_SAMPLE_ATTESTATION_MODE=oem_debug_fake \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-attestation-e2e.sh
```

生产化 OEM 接入需要：

- Android 侧实现真实 `AttestationProvider`
- server 侧实现 private OEM verifier
- 配置 trust anchor / provider allowlist
- 补至少一条 staging E2E 留档

## 测试步骤

### 1. Shell 脚本语法检查

```bash
cd /Users/a/back/Game/cq
for f in $(git diff --name-only origin/main..HEAD | grep -E '\.sh$' || true); do
  bash -n "$f"
done
```

也可以检查全部常用脚本：

```bash
cd /Users/a/back/Game/cq
bash -n leona-sdk-android/scripts/run-alpha-closure.sh
bash -n leona-sdk-android/scripts/run-emulator-e2e.sh
bash -n leona-sdk-android/scripts/run-emulator-attestation-e2e.sh
bash -n leona-sdk-android/scripts/run-device-e2e.sh
bash -n leona-sdk-android/scripts/run-device-attestation-e2e.sh
bash -n scripts/run-online-sync.sh
```

### 2. Android SDK 单元测试

```bash
cd /Users/a/back/Game/cq/leona-sdk-android
export JAVA_HOME=$(/usr/libexec/java_home -v 21)
export ANDROID_SDK_ROOT=/Users/a/Library/Android/sdk
export GRADLE_USER_HOME=/Users/a/back/Game/cq/.gradle-home

./gradlew :sdk:testDebugUnitTest --no-daemon --stacktrace
```

### 3. Android AAR 与 sample 构建

```bash
cd /Users/a/back/Game/cq/leona-sdk-android
./gradlew :sdk:testDebugUnitTest :sdk:assembleRelease :sample-app:assembleDebug \
  --no-daemon --no-configuration-cache --stacktrace
```

### 4. Server 单元测试

```bash
cd /Users/a/back/Game/cq/leona-server
export JAVA_HOME=$(/usr/libexec/java_home -v 21)
export GRADLE_USER_HOME=/Users/a/back/Game/cq/.gradle-home

./gradlew test --no-daemon --stacktrace
```

如果本机默认 Java 与 Gradle 不兼容，使用仓库脚本：

```bash
cd /Users/a/back/Game/cq/leona-server
./scripts/gradlew-java21.sh test
```

### 5. 本地 server 栈 smoke test

```bash
cd /Users/a/back/Game/cq/leona-server/deploy/docker-compose
docker compose up -d --build

curl http://localhost:8080/actuator/health
curl http://localhost:8081/actuator/health
curl http://localhost:8082/actuator/health
curl http://localhost:8083/actuator/health
curl http://localhost:8084/actuator/health
```

Handshake smoke:

```bash
curl -X POST http://localhost:8080/v1/handshake \
  -H "Content-Type: application/json" \
  -H "X-Leona-App-Key: lk_dev_sample" \
  -d '{
    "clientPublicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "installId": "dev-install-1",
    "sdkVersion": "0.1.0-alpha.1"
  }'
```

### 6. Demo backend smoke test

```bash
cd /Users/a/back/Game/cq/demo-backend
GOCACHE=/Users/a/back/Game/cq/.gocache \
LEONA_BASE_URL=http://localhost:8080 \
LEONA_SECRET_KEY=<secretKey> \
go run .
```

另开一个终端：

```bash
curl http://localhost:8090/health
curl http://localhost:8090/v1/mobile-config \
  -H 'X-Leona-Tenant: sample-tenant' \
  -H 'X-Leona-App-Id: sample-app' \
  -H 'X-Leona-Device-Id: Tdevice-1' \
  -H 'X-Leona-Install-Id: install-1' \
  -H 'X-Leona-Fingerprint: fingerprint-1'
```

### 7. 一键 alpha closure

```bash
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-alpha-closure.sh
```

可选打开更多 E2E：

```bash
RUN_ATTESTATION_E2E=1 LEONA_API_KEY=<appKey> \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-alpha-closure.sh

RUN_EMULATOR_E2E=1 LEONA_AUTO_CREATE_LOCAL_SERVER_APP_KEY=1 \
LEONA_ADMIN_BASE_URL=http://127.0.0.1:8083 \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-alpha-closure.sh
```

输出：

```text
/tmp/leona-alpha-closure-*/report.json
/tmp/leona-alpha-closure-*/report.md
```

### 8. 模拟器完整 E2E

前置：

- server 栈已启动
- demo backend 已启动
- Android emulator 已启动并能被 `adb devices` 看到

执行：

```bash
LEONA_AUTO_CREATE_LOCAL_SERVER_APP_KEY=1 \
LEONA_ADMIN_BASE_URL=http://127.0.0.1:8083 \
LEONA_REPORTING_ENDPOINT=http://10.0.2.2:8080 \
LEONA_FORMAL_VERDICT_BASE_URL=http://127.0.0.1:8080 \
LEONA_CLOUD_CONFIG_ENDPOINT=http://10.0.2.2:8090/v1/mobile-config \
LEONA_DEMO_BACKEND_BASE_URL=http://10.0.2.2:8090 \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-e2e.sh
```

脚本会验证：

- 安装 sample app
- 点击 `Run sense()`
- 提取 UI/demo `BoxId`
- 查询 demo verdict
- mint 新 `BoxId` 并直接调用 formal `/v1/verdict`
- 校验 verdict response signature
- 校验 `canonicalDeviceId`
- 校验 `deviceFingerprint`
- 校验 diagnostic / transport / verdict / support bundle canonical 对齐
- 保存截图、XML、JSON artifact

最近一次本地通过记录：

- 日期: 2026-04-27
- UI/demo BoxId: `01KQ792YC06BAEHG4WQZH308WX`
- formal `/v1/verdict` BoxId: `01KQ794PAP1N9SXQVQ501B1075`
- canonical: `L8a5d40fa9aa6a9ebd14101ef9b62c5b`
- verdict: `decision=deny`, `risk=CRITICAL`, `score=100`
- artifact: `/tmp/leona-e2e-20260427-185131`

### 9. Attestation 摘要 E2E

```bash
LEONA_API_KEY=<appKey> \
LEONA_HOST_BASE_URL=http://127.0.0.1:8080 \
LEONA_REPORTING_ENDPOINT=http://10.0.2.2:8080 \
LEONA_SAMPLE_ATTESTATION_MODE=debug_fake \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-attestation-e2e.sh
```

验证点：

- `/v1/handshake` 返回 `deviceBindingStatus`
- `/v1/handshake` 返回 structured `attestation`
- Android transport summary 显示同一 provider / status / code
- Android support bundle summary 显示同一 provider / status / code
- raw transport / support bundle JSON 与 server handshake attestation 摘要一致

最近一次本地通过记录：

- 日期: 2026-04-25
- mode: `debug_fake`
- BoxId: `01KQ04NPATG3KP1S1526KXX3M3`
- provider: `play_integrity`
- status: `play_integrity/MEETS_DEVICE_INTEGRITY`
- code: `PLAY_INTEGRITY_VERIFIED`
- artifact: `/tmp/leona-attestation-e2e-20260425-002000`

### 10. 真机 E2E

真机 attestation：

```bash
ADB_SERIAL=<device-serial> \
LEONA_API_KEY=<appKey> \
LEONA_SAMPLE_ATTESTATION_MODE=debug_fake \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-device-attestation-e2e.sh
```

真机完整 device E2E：

```bash
ADB_SERIAL=<device-serial> \
LEONA_AUTO_CREATE_LOCAL_SERVER_APP_KEY=1 \
LEONA_ADMIN_BASE_URL=http://127.0.0.1:8083 \
LEONA_REPORTING_ENDPOINT=http://127.0.0.1:8080 \
LEONA_CLOUD_CONFIG_ENDPOINT=http://127.0.0.1:8090/v1/mobile-config \
LEONA_DEMO_BACKEND_BASE_URL=http://127.0.0.1:8090 \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-device-e2e.sh
```

干净零售机回归：

```bash
LEONA_EXPECT_CLEAN_DEVICE=1 \
ADB_SERIAL=<device-serial> \
LEONA_AUTO_CREATE_LOCAL_SERVER_APP_KEY=1 \
LEONA_ADMIN_BASE_URL=http://127.0.0.1:8083 \
LEONA_REPORTING_ENDPOINT=http://127.0.0.1:8080 \
LEONA_CLOUD_CONFIG_ENDPOINT=http://127.0.0.1:8090/v1/mobile-config \
LEONA_DEMO_BACKEND_BASE_URL=http://127.0.0.1:8090 \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-device-e2e.sh
```

### 11. GitHub Actions live E2E

Workflow:

```text
leona-sdk-android/.github/workflows/android.yml
```

需要配置 secrets / variables：

- `LEONA_E2E_API_KEY`
- `LEONA_E2E_SECRET_KEY`
- `LEONA_E2E_REPORTING_ENDPOINT`
- `LEONA_E2E_FORMAL_VERDICT_BASE_URL`
- `LEONA_E2E_CLOUD_CONFIG_ENDPOINT`
- `LEONA_E2E_DEMO_BACKEND_BASE_URL`

手动触发：

- `workflow_dispatch`
- `run_live_e2e=true`
- `run_live_attestation_e2e=true`
- `run_alpha_closure=true`

### 12. Release preflight

```bash
cd /Users/a/back/Game/cq
/Users/a/back/Game/cq/scripts/release-preflight.sh --strict leona-sdk-android leona-server
```

发布前停止条件：

- 干净零售机误报 root / xposed / unidbg / frida
- 同一 app/device reinstall 后 canonical device id 异常漂移
- cloud-config 启用但 support bundle 缺少证据
- handshake / transport / support bundle attestation 摘要不一致
- verdict / transport / diagnostics canonical 不一致
- public 仓库误带 private 实现、密钥、生产配置

## 当前已知限制

- 公开仓库是 shell / sample / docs / fallback runtime，不承诺包含生产级高价值 detection 规则。
- CLI scanner 仍是 placeholder，不是当前 alpha 主交付。
- 真机留档与首次 GitHub live E2E 仍是增强项，需要目标环境配置后补证据。
- Mainland / 非 GMS 的 public route 已打通，但真 OEM provider、server verifier、trust anchor、allowlist 属于 private 生产化工作。
- 后续新增 detector、heuristic、生产风控策略默认进入 private core / private backend。

## 关键文档

- `docs/README.md`
- `docs/current-status.md`
- `docs/local-runbook.md`
- `docs/final-acceptance-summary.md`
- `docs/open-vs-private-final-matrix.md`
- `docs/mainland-closeout-summary.md`
- `leona-sdk-android/README.md`
- `leona-sdk-android/docs/release-closure.md`
- `leona-server/README.md`
- `demo-backend/README.md`

## License

Apache License 2.0.
