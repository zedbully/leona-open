# Leona 当前总体验收总结

> 更新时间: 2026-04-29
> 适用范围：当前仓库 `/Users/a/back/Game/cq`

---

## 1. 一句话结论

> **Leona 已真实跑通 Android SDK + server + demo-backend 在模拟器上的完整闭环，并已补齐本地可回归执行的 E2E 自动化脚本、handshake attestation 摘要专项回归、alpha release notes、admin 真实联调留档、最小 observability 收口、GitHub manual E2E workflow scaffold，以及 private module split 脚手架与第一批敏感检测规则迁移；当前剩余工作主要收敛为“发布前清理 + 真机留档增强 + 首次 CI 跑验 + 私有实现继续迁移”。**

---

## 2. 分 Phase 总结

### Phase 0

结论：**通过**

### Phase 1

结论：**通过**

已完成：

- handshake / sense / verdict 协议主链路修正
- BoxId JSON 契约统一
- 热路径 Redis snapshot 打通
- sample app 已通过模拟器真实打通 SDK ↔ Server ↔ demo backend 闭环

### Phase 2

结论：**通过**

已完成：

- sample app 演示模式
- demo backend
- 演示流程文档
- verdict 签名校验
- sample app 页面已真实展示 `decision / risk / score`
- 模拟器联调留档已完成：
  - `/Users/a/back/Game/cq/docs/demo-record-2026-04-23.md`

### Phase 3

结论：**通过**

已完成：

- BoxId 生命周期
- key revoke / rotate
- worker DLQ
- verdict 响应签名
- 最小 metrics 与 API 文档
- admin 真实联调留档：
  - `/Users/a/back/Game/cq/docs/admin-record-2026-04-23.md`
- observability 收口：
  - `/Users/a/back/Game/cq/docs/observability.md`
  - `/Users/a/back/Game/cq/docs/observability-record-2026-04-23.md`
  - Prometheus alert rules 已加载
  - Grafana datasource / dashboard provisioning 已生效

### Phase 4

结论：**通过**

已完成：

- `leona-server` 全量 `test` / `build` 已真实跑通
- Redis claim 真实集成测试 hard-pass
- docker compose 本地 5 服务栈健康检查通过
- Android 模拟器真实 E2E 手工验收通过
- Android ↔ Server E2E 自动化已跑通：
  - 脚本：`/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-e2e.sh`
  - 本地执行时间：2026-04-27
  - 本次自动化产出 UI/demo BoxId：`01KQ792YC06BAEHG4WQZH308WX`
  - 本次 formal `/v1/verdict` BoxId：`01KQ794PAP1N9SXQVQ501B1075`
  - 本次 canonical：`L8a5d40fa9aa6a9ebd14101ef9b62c5b`
  - 本次自动化 verdict：
    - `decision=deny`
    - `risk=CRITICAL`
    - `score=100`
  - formal verdict response signature、`canonicalDeviceId`、`deviceFingerprint` 与跨 surface canonical 对齐均已自动校验
  - 自动化产物目录：`/tmp/leona-e2e-20260427-185131`
- handshake attestation 摘要自动化已跑通：
  - 脚本：`/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-attestation-e2e.sh`
  - 本地执行时间：2026-04-25
  - mode：`debug_fake`
  - 本次自动化产出 BoxId：`01KQ04NPATG3KP1S1526KXX3M3`
  - 本次自动化 attestation：
    - `provider=play_integrity`
    - `status=play_integrity/MEETS_DEVICE_INTEGRITY`
    - `code=PLAY_INTEGRITY_VERIFIED`
  - 自动化产物目录：`/tmp/leona-attestation-e2e-20260425-002000`
  - 专项留档：`/Users/a/back/Game/cq/docs/attestation-record-2026-04-25.md`

### Phase 5

结论：**通过（真机留档为增强项）**

已完成：

- Android Gradle / SDK / NDK 构建链恢复
- AAR release 产物已确认
- sample app debug APK 产物已确认
- sample app 联调参数注入已验证
- 模拟器真实联调留档已完成
- alpha release notes 已定稿：
  - `/Users/a/back/Game/cq/docs/alpha-release-notes.md`
- GitHub manual live emulator E2E / attestation summary E2E workflow 已补：
  - `/Users/a/back/Game/cq/leona-sdk-android/.github/workflows/android.yml`
  - `/Users/a/back/Game/cq/docs/ci-e2e-setup.md`
  - workflow_dispatch 输入：
    - `run_live_e2e`
    - `run_live_attestation_e2e`
  - Actions summary 已支持直接显示：
    - `deviceBindingStatus`
    - `provider`
    - `status`
    - `code`
    - `retryable`
- private module split 脚手架已补：
  - `/Users/a/back/Game/cq/docs/private-module-split.md`
  - public-only 构建验收留档：
    `/Users/a/back/Game/cq/docs/public-only-build-record-2026-04-23.md`
  - Android public SDK 已支持 `NativeRuntime` 私有替换
  - server 已支持可选 `private/api-backend` 模块目录
  - tamper / injection / Frida / environment / root / xposed / unidbg 敏感规则已支持 private header 优先加载
  - backend risk scorer / risk score policy 已支持 private 实现优先加载
  - `PrivateNativeRuntime` 已支持私有 `libleona_private.so` 优先加载
  - `sdk-private-core` 已支持独立构建 `libleona_private.so`
  - `PrivateNativeRuntime` 已切到独立 private JNI 入口
  - Android private core / sdk / sample-app 已重新完成构建验收
  - server common / ingestion / worker / private-api-backend 已重新完成构建验收
  - private backend 已开始承载真实事件模式加权与更严格阈值策略
  - private backend 已升级为 tenant-aware / stage-aware / profile-aware 私有风控实现
  - private backend 已支持 private config file 驱动的 tenant override / private signal 开关
  - admin-service 已支持导入 private-only internal ops endpoint
  - private internal ops endpoint 已支持显式 enable 开关与 backend status endpoint
  - private rollout / feature gate 内部运维视图已补齐
  - private config source / tenant explain 内部运维视图已补齐
  - private backend readiness / crypto explain 内部运维视图已补齐
  - private tenant override / rollout inventory 内部运维视图已补齐
  - private risk capability inventory 内部运维视图已补齐
  - private simulation / dry-run explain 内部运维视图已补齐
  - 私有模块一键验收脚本已再次跑通
- 本轮真实联调中暴露出的关键问题已修复：
  - Android X25519 兼容性
  - sample app cleartext 本地联调限制
  - ingestion-service Kafka producer idempotence 配置错误
  - native collector category 映射不完整

仍缺：

- 真机留档（模拟器留档已完成）

---

### Phase 6

结论：**通过（已进入收口冻结阶段）**

已完成：

- 开源版 / 私有版最终边界矩阵已固化：
  - `/Users/a/back/Game/cq/docs/open-vs-private-final-matrix.md`
- 最终收口策略已固化：
  - `/Users/a/back/Game/cq/docs/closeout-strategy.md`
- docs 首页与发布清单已更新为 freeze / closeout 口径
- public-only 构建已于 2026-04-24 再次通过复验：
  - `/Users/a/back/Game/cq/docs/public-only-build-record-2026-04-24.md`
- 私有模块最终验收已于 2026-04-24 再次通过：
  - `/Users/a/back/Game/cq/docs/private-module-verify-record-2026-04-24.md`
- 当前项目方向已明确切换为：
  - 冻结 public shell
  - 深化 private core / private backend
  - 优先做验收、发布清理、文档冻结

---

## 2.1 Mainland / 非 GMS 收口状态

结论：**public 路线通过，private 生产化待完成**

已完成：

- public `AttestationProvider` 可插拔接口已落地
- public ingestion 已支持 `oem_attestation` 路由到 private verifier
- sample 已支持：
  - `oem_debug_fake`
  - `oem_bridge`
- mainland 风险分层已固化为：
  - `gms_attested`
  - `oem_attested`
  - `no_attestation`
  - `attestation_failed`
- 文档链路已补齐：
  - `/Users/a/back/Game/cq/docs/mainland-closeout-summary.md`
  - `/Users/a/back/Game/cq/docs/mainland-attestation-record-2026-04-25.md`
  - `/Users/a/back/Game/cq/docs/mainland-attestation-risk-posture.md`
  - `/Users/a/back/Game/cq/docs/mainland-attestation-acceptance-checklist.md`
  - `/Users/a/back/Game/cq/leona-sdk-android/docs/mainland-attestation-e2e.md`
  - `/Users/a/back/Game/cq/leona-sdk-android/docs/mainland-attestation-release-gate.md`

仍缺：

- 真 OEM Android provider 接入
- 真 OEM server verifier / trust anchor / allowlist 生产配置
- 至少 1 条真实 mainland OEM staging E2E 留档
- posture bucket 仪表盘与运营量化

---

## 3. 当前最关键的剩余项

### 收口剩余项

当前已经有：

- 模拟器人工闭环留档
- 模拟器自动化 E2E 脚本与真实执行结果
- handshake attestation 摘要专项自动化脚本与真实执行结果
- attestation 摘要专项留档
- query / verdict 主链路真实验收
- admin create / create-key / rotate / revoke 真实联调留档
- 最小 observability dashboard / alerting 已完成
- GitHub manual E2E / attestation workflow scaffold 已完成
- private module split 脚手架已完成
- 开源版 / 私有版最终边界矩阵已完成
- 最终收口策略已完成
- 2026-04-29 Alpha P0 执行记录已完成：
  - `/Users/a/back/Game/cq/docs/alpha-execution-record-2026-04-29.md`

当前仍建议保留为收口项：

- USB 物理真机留档（增强项；当前环境只发现 `emulator-5554`）
- GitHub secrets / variables 配置与首次 live emulator E2E 跑验
- 私有模块继续深化，但不再扩大 public 面
- 真机 attestation 执行包已具备，待现场 USB 真机执行留档

---

## 4. 当前推荐执行顺序

1. 如果条件允许，接入 USB 物理真机并按 device E2E / attestation 执行包补留档
2. 在真实 GitHub 仓库配置 secrets / variables 并跑首次 live emulator E2E / live attestation E2E
3. 如正式发布前还有改动，再补一轮 release preflight / public-only / private split 检查
4. 后续新增高价值能力只继续进入 private 模块

---

## 5. 当前可对外使用的口径

> Leona 已完成 Android runtime security alpha 的本地工程闭环：Android SDK、sample app、server-side BoxId verdict pipeline 与 demo backend 已在 Android 模拟器上完成真实联调验收，并已有本地可回归执行的 E2E 自动化脚本、handshake attestation 摘要专项回归、正式 alpha release notes、admin 真实联调留档、最小 observability 收口、GitHub manual E2E / attestation workflow scaffold，以及已固化的 private module split、open-source shell、private core、private backend 边界。当前工作重点是发布前清理、真机/CI 增强项补充，以及只在 private 模块继续深化高价值能力。
