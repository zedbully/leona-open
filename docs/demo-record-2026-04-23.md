# Leona 模拟器真联调留档（2026-04-23）

> 日期：2026-04-23
> 环境：`/Users/a/back/Game/cq`
> 目的：留档一次真实的 sample app → server → demo backend → verdict 联调结果

---

## 1. 运行环境

### Android

- AVD 名称：`leona-api34`
- 系统镜像：`system-images;android-34;google_apis;arm64-v8a`
- emulator 二进制：`/opt/homebrew/share/android-commandlinetools/emulator/emulator`
- 设备：`emulator-5554`

### Server / Backend

- gateway：`http://localhost:8080`
- ingestion-service：`http://localhost:8081`
- query-service：`http://localhost:8082`
- admin-service：`http://localhost:8083`
- worker-event-persister：`http://localhost:8084`
- demo-backend：`http://localhost:8090`

### Android sample app BuildConfig

- `LEONA_API_KEY=lk_live_app_SiHCmESWBDBP2Bi5SpGkKekU`
- `LEONA_REPORTING_ENDPOINT=http://10.0.2.2:8080`
- `LEONA_DEMO_BACKEND_BASE_URL=http://10.0.2.2:8090`

---

## 2. 本次真实执行结果

### 2.1 sample app 成功安装到模拟器

执行方式：

```bash
LEONA_API_KEY=lk_live_app_SiHCmESWBDBP2Bi5SpGkKekU \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-live-sample.sh
```

结果：

- 自动识别到 `adb` 设备，执行 `:sample-app:installDebug`
- 安装成功到 `emulator-5554`

### 2.2 `sense()` 真实成功

sample app 页面真实显示：

- `BoxId: 01KPV4XEW0A2FNF6WD63D1ZA7D`

同时 Redis 中存在真实 Box 记录，说明：

- handshake 成功
- `/v1/sense` 成功
- ingestion 已解密并解析 payload
- Redis 热路径写入成功
- Kafka 发布成功
- worker 已消费并补充评分信息

### 2.3 `Query demo verdict` 真实成功

sample app 页面真实显示：

```text
decision=deny
risk=CRITICAL
score=100
```

这说明：

- sample app 成功把 `BoxId` 发给 demo backend
- demo backend 成功调用 server-side `/v1/verdict`
- query-service 成功返回 verdict
- 页面已真实展示最终结果

### 2.4 BoxId single-use 语义真实生效

对同一个 BoxId 再次请求 demo backend，返回：

- HTTP `410`
- `LEONA_BOX_ALREADY_USED`

说明：

- query-service 的单次消费语义真实生效

### 2.5 同日自动化 E2E 脚本复验成功

执行方式：

```bash
LEONA_API_KEY=lk_live_app_SiHCmESWBDBP2Bi5SpGkKekU \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-e2e.sh
```

自动化结果：

- 输出目录：`/tmp/leona-e2e-20260423-015719`
- BoxId：`01KPV5E417A7467GRBRMQXYF30`
- 页面 verdict：

```text
decision=deny
risk=CRITICAL
score=100
```

补充验证：

- 自动化完成后再次调用 `POST /demo/verdict`
- demo-backend 返回上游 `HTTP 410 LEONA_BOX_ALREADY_USED` 的包装错误
- 说明自动化链路下 single-use 语义同样真实生效

---

## 3. 本轮真实发现并已修复的问题

### 已修复 1：Android X25519 兼容性

现象：

- `sense()` 在模拟器上报：`X25519 KeyPairGenerator not available`

修复：

- `/Users/a/back/Game/cq/leona-sdk-android/sdk/src/main/kotlin/io/leonasec/leona/internal/crypto/X25519KeyPair.kt`
- 增加 `X25519` → `XDH` 兼容回退
- 远端公钥改用 `X509EncodedKeySpec`（RFC 8410 SPKI）构造

### 已修复 2：sample app 明文 HTTP 本地联调限制

现象：

- Android 14 阻止访问 `http://10.0.2.2:8080`

修复：

- `/Users/a/back/Game/cq/leona-sdk-android/sample-app/src/main/AndroidManifest.xml`
- 为 sample app 开启 `android:usesCleartextTraffic="true"`

### 已修复 3：ingestion-service Kafka producer 配置错误

现象：

- `/v1/sense` 返回 HTTP `500`
- 根因：启用了 idempotence，但 `acks` 配置为 `1`

修复：

- `/Users/a/back/Game/cq/leona-server/ingestion-service/src/main/resources/application.yml`
- `acks: "1"` → `acks: "all"`

### 已修复 4：native event category 映射不完整

现象：

- `frida.*` / `env.*` 事件在服务端被落成 `OTHER`

修复：

- `/Users/a/back/Game/cq/leona-sdk-android/sdk/src/main/cpp/report/collector.cpp`
- 补齐前缀映射：
  - `frida.` → `INJECTION`
  - `env.` → `ENVIRONMENT`
  - `honeypot.` → `HONEYPOT_TRIPPED`
  - `network.` → `NETWORK`

---

## 4. 证据文件

本地截图：

- 首页：`/tmp/leona-e2e/01-home.png`
- `sense()` 通过后：`/tmp/leona-e2e/08-after-sense-success.png`
- 最终 verdict 页面：`/tmp/leona-e2e/10-final-verdict.png`

本地 UI dump：

- `/tmp/leona-e2e/window_dump_after_sense_success.xml`
- `/tmp/leona-e2e/final_verdict.xml`

自动化复验产物：

- `/tmp/leona-e2e-20260423-015719/home.png`
- `/tmp/leona-e2e-20260423-015719/sense-state.xml`
- `/tmp/leona-e2e-20260423-015719/verdict-state.xml`
- `/tmp/leona-e2e-20260423-015719/final.png`

---

## 5. 结论

结论：

> **Leona 已在 Android 模拟器上真实跑通 sample app → handshake → sense → Redis/Kafka/worker → demo backend → verdict 的完整闭环。**

当前仍未完成的内容主要是：

- 真机留档（当前已有模拟器留档）
- 模拟器 E2E 纳入 CI（增强项）
