# Leona 当前项目状态

> 更新时间: 2026-04-27
> 适用范围: `/Users/a/back/Game/cq`

---

## 1. 当前定位

Leona 当前执行范围已经收敛为：

- **只做移动端应用安全**
- **Android 先行**
- iOS 保留在后续阶段
- 先把 **Android SDK + Server 闭环 + 最小演示链路** 做成可内测 alpha

当前仓库不是空白想法，而是已经进入 **alpha 工程化阶段**。

---

## 2. 各仓库当前状态

### `/Users/a/back/Game/cq/leona`

定位：CLI 入口仓库。

当前状态：

- 已有 `version` / `scan` / `rules list` 命令骨架
- 版本信息输出可用
- `scan` 与 `rules` 仍是 **placeholder**
- 尚未实现真正的 APK 静态扫描引擎

结论：

- **CLI 方向已起步，但暂不是主线交付物**

---

### `/Users/a/back/Game/cq/leona-sdk-android`

定位：Android 运行时安全 SDK。

当前已实现：

- 公共 API：
  - `Leona.init()`
  - `Leona.sense()`
  - `Leona.senseAsync()`
  - `BoxId`
  - `LeonaConfig`
  - `Honeypot`
  - `quickCheck()` 诱饵接口
- Kotlin ↔ JNI ↔ C++ 主链路
- Native payload 收集与编码
- BoxId 上传通道主要代码
- X25519 + HKDF + AES-GCM + HMAC 相关实现
- 运行时检测：
  - Frida / ptrace / trampoline 特征
  - Emulator
  - Root / Magisk / KernelSU / Riru
  - Xposed / LSPosed / EdXposed
  - Unidbg
- Honeypot 假数据原语
- sample app
- demo backend（最小演示后端）
- SDK changelog
- 部分单元测试与测试文档

当前限制：

- sample app 默认仍使用本地 stub 模式
- sample app 已支持通过 Gradle 属性接真实 server / demo backend
- Android 构建链已恢复，AAR 与 sample-app debug APK 已真实构建确认
- sample app 已在 Android 模拟器上真实跑通 `sense()` → `demo verdict` 闭环
- Android 模拟器本地 E2E 自动化脚本已跑通：
  - `/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-e2e.sh`
  - 2026-04-27 自动化结果：`BoxId=01KQ792YC06BAEHG4WQZH308WX`，`formalVerdictBoxId=01KQ794PAP1N9SXQVQ501B1075`，`canonical=L8a5d40fa9aa6a9ebd14101ef9b62c5b`，`decision=deny`，`risk=CRITICAL`，`score=100`
  - 当前脚本同时覆盖 sample `demo verdict` 与直接调用 formal `/v1/verdict`：校验 response signature、`canonicalDeviceId`、`deviceFingerprint`，并要求 diagnostic / transport / verdict / support bundle 四处 canonical 对齐。
- handshake attestation 摘要专项回归脚本已跑通：
  - `/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-attestation-e2e.sh`
  - 2026-04-25 自动化结果：`mode=debug_fake`，`BoxId=01KQ04NPATG3KP1S1526KXX3M3`
  - attestation：`provider=play_integrity`，`status=play_integrity/MEETS_DEVICE_INTEGRITY`，`code=PLAY_INTEGRITY_VERIFIED`
  - 专项留档：`/Users/a/back/Game/cq/docs/attestation-record-2026-04-25.md`
- Android GitHub manual live emulator E2E workflow scaffold 已补：
  - `/Users/a/back/Game/cq/leona-sdk-android/.github/workflows/android.yml`
  - `/Users/a/back/Game/cq/docs/ci-e2e-setup.md`
- Android GitHub manual live attestation E2E workflow scaffold 已补：
  - `/Users/a/back/Game/cq/leona-sdk-android/.github/workflows/android.yml`
  - workflow_dispatch 输入：`run_live_attestation_e2e`
  - job summary 已支持显示 attestation provider / status / code / retryable
- public-only 构建验收已完成：
  - `/Users/a/back/Game/cq/docs/public-only-build-record-2026-04-23.md`
  - `/Users/a/back/Game/cq/docs/public-only-build-record-2026-04-24.md`
- 私有模块拆分脚手架已补：
  - `/Users/a/back/Game/cq/docs/private-module-split.md`
  - Android public SDK 已增加 `NativeRuntime` 私有替换边界
  - server 已支持可选 `private/api-backend` 模块目录
  - tamper / injection / Frida / environment / root / xposed / unidbg 规则表已支持迁入 private core 头文件
  - backend API crypto / risk scorer / risk score policy 已支持私有实现替换
  - `PrivateNativeRuntime` 已支持私有 `libleona_private.so` 优先加载
  - `sdk-private-core` 已支持独立构建 private native 库 `libleona_private.so`
  - `PrivateNativeRuntime` 已切到独立 private JNI 入口
  - Android private core 当前骨架已重新编译通过，`sdk` / `sample-app` assemble 通过
  - server common / ingestion / worker / private-api-backend classes 编译通过
  - private backend 已开始承载真实事件模式加权与更严格风控阈值
  - private backend 已支持 tenant / stage / deployment-profile 感知风控配置
  - private backend 已支持 private JSON config file 驱动的 tenant override / feature gate
  - admin-service 已支持 private-only internal ops endpoint bridge
  - private internal ops endpoint 已支持显式开关与 backend status 视图
  - private risk rollout / feature gate 运维视图已补齐
  - private config source / tenant explain 运维视图已补齐
  - private backend readiness / crypto explain 运维视图已补齐
  - private tenant override / rollout inventory 运维视图已补齐
  - private risk capability inventory 运维视图已补齐
  - private simulation / dry-run explain 运维视图已补齐
  - `/Users/a/back/Game/cq/scripts/verify-private-modules.sh` 已于 2026-04-24 再次通过
  - 验收记录：`/Users/a/back/Game/cq/docs/private-module-verify-record-2026-04-24.md`
- 真实联调中暴露的 X25519 / cleartext / Kafka / category 映射问题已修复
- alpha release notes 正式文档已补：
  - `/Users/a/back/Game/cq/docs/alpha-release-notes.md`
- 真机留档仍待补齐
- 误报/漏报验证还不完整
- 公开 API 已进入冻结口径，后续不再继续扩大 public 面
- 大陆 / 非 GMS 文档链路已补齐：design / acceptance / risk posture / sample E2E / release gate
- `oem_debug_fake` 已于 2026-04-25 在标准 gateway `:8080` 链路完成真实留档：
  - `/Users/a/back/Game/cq/docs/mainland-attestation-record-2026-04-25.md`
- 真机 attestation 执行包已于 2026-04-27 补齐：
  - `/Users/a/back/Game/cq/leona-sdk-android/scripts/run-device-attestation-e2e.sh`
  - `/Users/a/back/Game/cq/docs/physical-attestation-runbook.md`
  - `/Users/a/back/Game/cq/docs/device-attestation-record-template.md`

结论：

- **这是当前完成度最高的部分，且已经具备模拟器真实联调能力。**

---

### `/Users/a/back/Game/cq/leona-server`

定位：Leona BoxId 协议与 verdict 查询后端。

当前已实现：

- 多模块结构：
  - `gateway`
  - `common`
  - `ingestion-service`
  - `query-service`
  - `admin-service`
  - `worker-event-persister`
- 协议与接口：
  - `/v1/handshake`
  - `/v1/sense`
  - `/v1/verdict`
  - tenant / key 管理接口（create / revoke / rotate）
- 安全链路：
  - HMAC 校验
  - timestamp 校验
  - nonce replay guard
  - Redis key lookup
  - AES-GCM 解密
  - TLV payload 解析
  - BoxId 生成与 claim
- 数据链路：
  - Kafka 发布 parsed events
  - worker 风险评分
  - Redis verdict cache
  - verdict 响应签名
  - BoxId JSON 字符串契约
  - Postgres 持久化
- 文档：
  - OpenAPI
  - architecture
  - threat model
  - docker-compose 本地栈
  - observability 最小说明
  - admin / query API 最小验收说明
  - alpha 发布准备文档
  - 联调 / 演示留档模板
  - alpha release notes 模板
  - Java / Gradle 恢复方案
  - 总体验收总结
  - 文档索引
  - 本地执行命令总览

当前限制：

- SDK ↔ Server 已完成模拟器真实端到端联调，真机留档仍待补
- sample app / demo backend 所需的 BoxId 字符串 JSON 契约已修正到服务端模型
- BoxId 过期/单次消费链路已完成真实 Redis 集成测试验收
- admin create / create-key / rotate / revoke 已在 2026-04-23 完成真实联调留档：
  - `/Users/a/back/Game/cq/docs/admin-record-2026-04-23.md`
- 最小 observability 收口已完成：
  - `/Users/a/back/Game/cq/docs/observability.md`
  - `/Users/a/back/Game/cq/docs/observability-record-2026-04-23.md`
  - Prometheus alert rules 已加载
  - Grafana datasource / dashboard provisioning 已生效
- quick start / 联调流程已具备模拟器真实演示与自动化脚本参考
- Java / Gradle 构建能力已恢复到可执行状态：`test` / `build` 已真实跑通，但默认系统 Java 25 仍不能直接启动 Gradle，当前需通过 `/Users/a/back/Game/cq/leona-server/scripts/gradlew-java21.sh`
- Docker Compose 本地栈已在 2026-04-22 真实拉起并验证：
  - `gateway` / `ingestion-service` / `query-service` / `admin-service` / `worker-event-persister`
  - 宿主机健康检查端口 `8080` ~ `8084` 全部返回 `UP`
  - `POST /v1/handshake` 通过 gateway 的最小 smoke test 已成功返回真实 `sessionId`

结论：

- **Server 已经是 MVP 骨架，不再只是设计稿**

---

## 3. 当前最真实的项目判断

如果只用一句话描述：

> **Leona 当前是：Android Runtime Security Alpha + Server MVP Skeleton + CLI Placeholder。**

更细分：

- Android SDK：**已进入真实功能阶段**
- Server：**已进入 MVP 骨架阶段**
- CLI Scanner：**仍在脚手架阶段**
- Dashboard / iOS / 商业化能力：**尚未开始或未落地**

---

## 4. 当前已确认的主要问题

1. **文档与代码存在漂移**
   - 例如 SDK 文档中仍有“加密链路是 placeholder”的旧描述
   - Server README 的状态描述落后于当前代码

2. **sample app 默认仍偏演示 stub**
   - 不利于真实联调

3. **E2E 自动化已具备本地回归入口**
   - 模拟器主链路自动化脚本已跑通
   - handshake attestation 摘要专项回归也已跑通
   - attestation 专项真实留档已补齐并挂接 docs 索引
   - GitHub manual workflow scaffold 已支持主链路与 attestation 两条 hosted 路径，但仍待真实仓库 secrets / variables 配置与首次 CI 跑验

4. **真机留档仍未完成**
   - 当前已有模拟器留档，但还没有真机联调记录

5. **CLI 主仓库尚不能提供真实扫描能力**
   - 当前不应把它作为主要卖点

6. **私有模块已进入“边界成型 + 内容迁移中”阶段**
   - Android private core runtime 与 private api-backend 的接入点已补
   - 已有一批敏感 detector catalog / heuristics 迁入 private core
   - server risk scoring 权重 / 阈值也已支持 private policy 替换
   - 但真正完整的 private runtime / private backend 仍需继续收口

7. **公开仓库独立构建边界已验证**
   - 临时移走 `private/` 目录后，Android / Server public-only 构建均已真实通过
   - 在 tamper 深层规则继续迁入 private 后又重新复验通过
   - 2026-04-24 已再次完成 public-only 构建复验

8. **发布前清理已推进到可执行项阶段**
   - `.gitignore` 对 `private/` 的隔离已确认
   - `application-local.yml` 已转为 example 模板
   - `.DS_Store` 已清理
   - 但当前环境不是 Git 工作树，因此 staged / 提交检查仍需在真实仓库环境再执行一轮

---

## 5. 当前阶段主目标（已切换为收口）

下一阶段不再继续扩大 public 功能，而是只做一件事：

> **把当前成果冻结成“公开版可发布、私有版可继续深化”的稳定边界。**

当前主线拆解为：

1. 固化开源版 / 私有版最终边界
2. 冻结 public shell、sample、docs、fallback
3. 再跑一轮总验收脚本
4. 补齐发布前清理口径
5. 后续新增高价值能力默认只进入 private 模块

---

## 6. 当前不再作为主线扩展的内容

以下内容不再作为本阶段 public 主线：

- 再扩大 public detector 规则面
- 再扩大 public server 风控细节
- iOS SDK
- Dashboard / Web Console
- 设备指纹
- 自适应策略引擎
- 商业化企业特性
- CLI 静态扫描器完整实现

---

## 7. 当前推荐的对外表述

建议当前对外统一描述为：

> Leona is an **Android runtime security alpha** with a **server-side BoxId verdict pipeline**. The public repository now acts as an **open-source shell** for integration, demo, and fallback runtime, while higher-value detection logic and backend strategy continue to move into a **private core / private backend** boundary.

---

## 8. 当前收口判断

一句话结论：

> **主线已经从“继续做功能”切换到“冻结 public、强化 private、完成验收与发布清理”。**

当前建议执行顺序：

1. 阅读 `/Users/a/back/Game/cq/docs/closeout-strategy.md`
2. 对照 `/Users/a/back/Game/cq/docs/open-vs-private-final-matrix.md` 检查边界
3. 执行 `/Users/a/back/Game/cq/scripts/verify-private-modules.sh`
4. 对照 `/Users/a/back/Game/cq/docs/open-source-release-checklist.md` 做最终清理
