# Leona 私有模块拆分方案

> 更新时间：2026-04-24
> 目标：把 **核心检测内容** 和 **API 后台** 从公开仓库边界中拆出去，保留开源外壳与可演示能力。

---

## 1. 拆分目标

当前建议的边界：

### 公开部分

- SDK public API
- sample app
- 对接文档
- CI / E2E 脚手架
- 最小 demo / runbook / observability 文档

### 私有部分

- Android 核心检测 runtime
- Android 敏感 machine-code signatures / 特征库
- 更敏感的 native 特征库 / 指纹 / 对抗逻辑
- API 后台实际业务部署模块
- 私有配置、密钥、内网环境接入

---

## 2. Android 核心检测模块拆分

当前已完成的最小模块化接入点：

- public SDK 通过 `NativeRuntime` 接口访问检测 runtime
- 默认实现：
  - `/Users/a/back/Game/cq/leona-sdk-android/sdk/src/main/kotlin/io/leonasec/leona/internal/runtime/OssNativeRuntime.kt`
- 运行时会优先尝试加载：
  - `io.leonasec.leona.privatecore.PrivateNativeRuntime`
- Frida machine-code signature catalog 已迁到私有头文件：
  - `/Users/a/back/Game/cq/leona-sdk-android/private/sdk-private-core/src/main/cpp/private_frida_signatures_catalog.h`
- public fallback catalog 仅保留空实现：
  - `/Users/a/back/Game/cq/leona-sdk-android/sdk/src/main/cpp/detection/frida_signatures_catalog.h`
- 更多敏感 detector catalog / heuristics 已迁到私有头文件：
  - `/Users/a/back/Game/cq/leona-sdk-android/private/sdk-private-core/src/main/cpp/private_injection_catalog.h`
  - `/Users/a/back/Game/cq/leona-sdk-android/private/sdk-private-core/src/main/cpp/private_tamper_catalog.h`
  - `/Users/a/back/Game/cq/leona-sdk-android/private/sdk-private-core/src/main/cpp/private_environment_catalog.h`
  - `/Users/a/back/Game/cq/leona-sdk-android/private/sdk-private-core/src/main/cpp/private_root_catalog.h`
  - `/Users/a/back/Game/cq/leona-sdk-android/private/sdk-private-core/src/main/cpp/private_xposed_catalog.h`
  - `/Users/a/back/Game/cq/leona-sdk-android/private/sdk-private-core/src/main/cpp/private_unidbg_heuristics.h`
- 对应 public fallback 已保留弱化 / 空实现：
  - `/Users/a/back/Game/cq/leona-sdk-android/sdk/src/main/cpp/detection/injection_catalog.h`
  - `/Users/a/back/Game/cq/leona-sdk-android/sdk/src/main/cpp/detection/tamper_catalog.h`
  - `/Users/a/back/Game/cq/leona-sdk-android/sdk/src/main/cpp/detection/environment_catalog.h`
  - `/Users/a/back/Game/cq/leona-sdk-android/sdk/src/main/cpp/detection/root_catalog.h`
  - `/Users/a/back/Game/cq/leona-sdk-android/sdk/src/main/cpp/detection/xposed_catalog.h`
  - `/Users/a/back/Game/cq/leona-sdk-android/sdk/src/main/cpp/detection/unidbg_heuristics.h`

这意味着：

- 开源仓库可以继续用 OSS runtime 构建
- 私有仓库只需额外提供一个 Android library，并实现 `NativeRuntime`
- 不需要改 public API

### 私有 Android 模块推荐路径

本地推荐放在：

- `/Users/a/back/Game/cq/leona-sdk-android/private/sdk-private-core`

当前仓库已支持：

- 若该目录存在，则自动 include `:sdk-private-core`
- sample app 会自动 `implementation(project(":sdk-private-core"))`
- public `sdk` 产出 OSS `libleona.so`
- private module 会单独产出 `libleona_private.so`
- `PrivateNativeRuntime` 当前会优先尝试加载私有 native library：
  - `libleona_private.so`
  - 加载失败时回退到 OSS `libleona.so`
- `PrivateNativeRuntime` 现已绑定独立 private JNI 入口，而不再复用 OSS JNI 类名

因此内部联调时可以直接把私有 runtime 打包进 sample app。

---

## 3. API 后台模块拆分

当前建议把真正不对外开放的 API 后台能力单独放在：

- `/Users/a/back/Game/cq/leona-server/private/api-backend`

当前仓库已支持：

- 若该目录存在，则自动 include `:private-api-backend`
- `private/` 已加入 `.gitignore`
- common API crypto 已支持通过私有 bootstrap 安装实现
- ingestion-service / worker-event-persister 已支持可选私有 risk scoring 实现
- 公共 rule-based scorer 已支持可选私有 risk policy
- private backend 当前可提供：
  - `io.leonasec.server.privatebackend.PrivateApiCryptoBootstrap`
  - `io.leonasec.server.privatebackend.PrivateRiskScoringEngine`
  - `io.leonasec.server.privatebackend.PrivateRiskScorePolicy`

推荐做法：

1. 公共协议 / 公共模型继续保留在 `common`
2. 私有仓库承载：
   - 真实部署配置
   - 私有 controller / internal admin 能力
   - 更敏感的规则 / 指纹 / 风险策略
   - 生产化集成（KMS / Vault / 私网依赖）

---

## 4. 当前状态

已经完成：

- Android core runtime 已有私有替换接口
- Android repo 已支持可选私有模块目录
- server repo 已支持可选私有 backend 模块目录
- `private/` 目录默认不进入公开仓库
- tamper / injection / Frida / environment / root / xposed / unidbg 的敏感规则表已支持 private 优先加载
- Android private core 当前已可编译，并已完成一次真实构建验证：
  - `:sdk-private-core:compileDebugKotlin`
  - `:sdk-private-core:assembleDebug`
  - `:sdk:assembleDebug`
  - `:sample-app:assembleDebug`
- `libleona_private.so` 已真实产出并被 sample app 合并打包
- server private backend 当前已可编译，并已完成一次真实构建验证：
  - `:common:classes`
  - `:ingestion-service:classes`
  - `:worker-event-persister:classes`
  - `:private-api-backend:classes`
- private backend 已开始承载真实私有策略：
  - stricter private risk score policy
  - private sensitive event pattern escalation
- private backend 已进一步升级为 private-only context-aware config 边界：
  - tenant-aware strict / relaxed override
  - ingestion / worker stage-aware strictness
  - deployment profile / env driven tuning
- admin-service 已支持 private backend 注入 private-only internal ops endpoint
- 一键验收脚本已补：
  - `/Users/a/back/Game/cq/scripts/verify-private-modules.sh`

当前 private backend 支持的私有配置入口：

- `LEONA_PRIVATE_RISK_CONFIG_PATH`
- `LEONA_PRIVATE_RISK_PROFILE`
- `LEONA_PRIVATE_RISK_DEFAULT_STRICTNESS`
- `LEONA_PRIVATE_RISK_STRICT_TENANTS`
- `LEONA_PRIVATE_RISK_RELAXED_TENANTS`
- `LEONA_PRIVATE_RISK_FEATURE_TENANTS`
- `LEONA_PRIVATE_INTERNAL_OPS_ENABLED`

以上配置也支持对应的 JVM system properties：

- `leona.private.risk.config-path`
- `leona.private.risk.profile`
- `leona.private.risk.default-strictness`
- `leona.private.risk.strict-tenants`
- `leona.private.risk.relaxed-tenants`
- `leona.private.risk.feature-tenants`
- `leona.private.internal-ops.enabled`

private risk config file 现已支持：

- profile / defaultStrictness
- strictTenants / relaxedTenants / featureTenants
- tenantOverrides
  - `ingestionStrictness`
  - `workerStrictness`
  - `privateSignalsEnabled`

这意味着 private backend 已不只是“类名占位”，而是已经具备：

- env / JVM property 驱动的部署调优
- private JSON 配置文件驱动的 tenant 级策略分流
- 私有特征开关与 tenant allowlist 隔离能力

当前 private-only internal ops 能力已开始落入 private backend：

- `GET /v1/internal/private/backend/status`
- `GET /v1/internal/private/backend/readiness`
- `GET /v1/internal/private/backend/crypto`
- `GET /v1/internal/private/risk/config`
- `GET /v1/internal/private/risk/config/capabilities`
- `GET /v1/internal/private/risk/config/sources`
- `GET /v1/internal/private/risk/config/overrides`
- `GET /v1/internal/private/risk/simulate/scenarios`
- `GET /v1/internal/private/risk/simulate/{scenarioId}`
- `GET /v1/internal/private/risk/config/tenants/{tenantId}`
- `GET /v1/internal/private/risk/explain/tenants/{tenantId}`
- `GET /v1/internal/private/risk/rollout`
- `GET /v1/internal/private/risk/rollout/inventory`
- `GET /v1/internal/private/risk/rollout/tenants/{tenantId}`

并且已增加显式开关：

- 只有当 `LEONA_PRIVATE_INTERNAL_OPS_ENABLED=true` 时才会注册这些 endpoint

public admin-service 只保留可选 bridge，不公开私有 controller 具体实现。

当前 rollout / feature gate 运维视图可回答：

- 当前 feature scope 是全量放开还是 allowlist
- 当前有多少 tenant override 显式开启 / 关闭 private signal
- 某个 tenant 的 private signal 最终是否生效
- 生效来源是全局默认、feature allowlist，还是 tenant override

当前 config source / explain 视图还可回答：

- profile / strictness / tenant list / feature allowlist / override 分别来自哪里
  - default
  - file
  - environment
  - system property
- 某个 tenant 的 ingestion / worker strictness 最终来源
- 某个 tenant 的 private signal 开关最终来源

当前 backend readiness / crypto explain 视图还可回答：

- private bootstrap class 是否存在
- crypto provider 是否已安装
- AES-GCM / ECDHE 自检是否通过
- private risk policy / engine 是否能正常构造
- 当前 crypto provider 类名与算法声明

当前 inventory 视图还可回答：

- 当前有哪些 tenant override 被配置
- 每个 override 的 ingestion / worker strictness
- 每个 override 是否显式控制 private signal
- 当前 rollout allowlist 中有哪些 tenant

当前 capability inventory 视图还可回答：

- baseline / elevated / strict 三档阈值与权重
- 各 severity 的权重分布
- 各 category 的 boost 分布
- 当前私有 escalation 前缀族
- 当前 immediate-critical 规则族

当前 simulation / dry-run 视图还可回答：

- 预置风险场景有哪些
- 某个场景在指定 tenant / stage 下的最终 risk level / score
- 当前 strictness / private signal gate 对该场景的实际影响

仍建议后续继续做：

- 把剩余更敏感的 C++ 检测特征、native runtime 实现逐步迁出到私有 runtime
- 把真实业务 API 后台 / 运维配置逐步迁到 `private/api-backend`
- 对开源仓库保留 sample / stub / contract / docs

---

## 5. 建议的仓库策略

推荐最终形态：

### GitHub 开源仓库

- `leona-sdk-android`：public API + sample app + OSS runtime / 或 stub runtime
- 文档与接入说明
- 开源 CI

### 私有仓库 / 私有子模块

- `sdk-private-core`
- `api-backend`
- 生产配置 / 密钥 / 私有规则

---

## 6. 下一步建议（按收口口径）

1. **不再继续扩大 public 暴露面**，公开仓库冻结为 shell / sample / docs / fallback
2. 剩余更敏感的 native runtime 实现与策略，只继续收口到 `sdk-private-core`
3. 剩余真实部署 backend 配置、内部 API 与运维能力，只继续收口到 `private/api-backend`
4. 发布前按 `/Users/a/back/Game/cq/docs/open-vs-private-final-matrix.md` 与 `/Users/a/back/Game/cq/docs/closeout-strategy.md` 做最终边界校验
