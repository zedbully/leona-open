# Leona Alpha 开发计划

> 更新时间: 2026-04-29  
> 目标：尽快完成 `v0.1.0-alpha.1` 工程收口，形成可发布、可演示、可继续私有深化的稳定版本。

---

## 1. Alpha 完成定义

Alpha 阶段不再扩大 public API 和 public detector 面。完成标准是：

- Android SDK、sample app、Leona Server、demo-backend 的本地闭环可重复跑通
- 模拟器 E2E、attestation 摘要 E2E、真机 E2E 至少各有明确执行包；真机优先补真实留档
- public-only 构建可通过，private 模块可选存在且不会污染公开边界
- `/v1/handshake`、`/v1/sense`、`/v1/verdict` 协议和 OpenAPI / README / runbook 口径一致
- BoxId single-use、verdict response signature、canonical device id、support bundle 证据链稳定
- 发布前检查脚本、release notes、GitHub workflow 使用说明可执行
- 私有 detector catalog、secure reporting、private risk policy 继续留在 private core / private backend

---

## 2. 当前剩余工作分级

### P0：Alpha 发布阻塞项

1. **提交并冻结当前工作区**
   - 状态：已完成
   - 输出：已提交 E2E 脚本修正、文档修正、本计划

2. **跑最终 release preflight**
   - 命令：`/Users/a/back/Game/cq/scripts/release-preflight.sh --strict leona-sdk-android leona-server`
   - 状态：已完成，2026-04-29 strict 通过
   - 记录：`/Users/a/back/Game/cq/docs/alpha-execution-record-2026-04-29.md`

3. **补真机 E2E 留档**
   - 脚本：`/Users/a/back/Game/cq/leona-sdk-android/scripts/run-device-e2e.sh`
   - 推荐参数：使用 `LEONA_AUTO_CREATE_LOCAL_SERVER_APP_KEY=1`
   - 状态：blocked，当前 ADB 只发现 `emulator-5554`，未发现 USB 物理真机
   - 已完成：使用同一脚本在 emulator 上验证 auto-create app key、本地闭环、两轮 reinstall canonical 稳定性
   - 记录：`/Users/a/back/Game/cq/docs/alpha-execution-record-2026-04-29.md`

4. **最终 public-only 构建复验**
   - 动作：临时移走或禁用 `private/` 后跑 Android SDK / server public-only 构建
   - 状态：已完成，2026-04-29 Android / Server public-only 均通过
   - 记录：`/Users/a/back/Game/cq/docs/alpha-execution-record-2026-04-29.md`

5. **文档一致性收口**
   - 核对：README、`docs/current-status.md`、`docs/final-acceptance-summary.md`、`docs/phase-execution-checklist.md`、OpenAPI
   - 状态：进行中，已补 2026-04-29 执行记录并更新总览入口
   - 验收：不再把 private-only 能力写成 public-only 已完整启用能力

### P1：Alpha 强烈建议项

1. **GitHub manual E2E 首跑**
   - 配置 `LEONA_E2E_*` secrets / variables
   - 跑 `run_live_e2e` 和 `run_live_attestation_e2e`
   - 验收：Actions summary 中有 BoxId、canonical、risk、attestation provider/status/code

2. **大陆 / 非 GMS 真 OEM 路线最小留档**
   - 当前 `oem_debug_fake` 已可用
   - 下一步接 1 个真实 OEM bridge 或 staging verifier dry run
   - 验收：形成一份真实 OEM 或 staging 记录，明确 trust tier 和 fallback 策略

3. **Private 风控解释面补齐**
   - 继续完善 tenant / stage / profile explain
   - 验收：每个 private escalation reason 可在 internal ops view 中解释来源

4. **误报 / 漏报样本表**
   - 至少整理：干净真机、debuggable sample、模拟器、root/virtual 环境、Unidbg 样本
   - 验收：每类样本对应 expected risk level 和 known false positive note

### P2：Alpha 后进入 beta 前再做

1. Android API 23-30 secure reporting 兼容性设计
2. 真实 Play Integrity production bridge 接入样例
3. private detector 双路径 hardening
4. server payload parser fuzz / chaos test
5. tenant dashboard 和运营视图
6. CLI scanner 从 placeholder 升级为最小 APK baseline 生成工具

---

## 3. 推荐时间表

### 2026-04-29：提交与计划冻结

- 提交当前 E2E 脚本和文档改动
- 新增本开发计划
- 确认 `git status` clean
- 已执行 release preflight strict
- 已执行 public-only Android / Server 构建复验
- 已执行 private module split 一键复验
- 已执行 device E2E 脚本本地闭环验证；物理真机因当前环境无 USB 真机暂记 blocked

### 2026-04-30：最终本地验收

- 跑 release preflight strict
- 修复阻塞失败
- 重新跑相关单测 / 构建
- 更新验收记录

### 2026-05-01：真机留档

- 使用 USB 真机执行 device E2E
- 若真机不可用，记录明确 blocked reason，并保留脚本 dry-run / 参数校验结果
- 形成或更新真机记录文档

### 2026-05-02：public-only 与文档一致性

- public-only 构建复验
- 清理 README / docs 中的 public-private 口径漂移
- 确认 release notes 和 changelog 可对外

### 2026-05-03：Alpha release candidate

- 打 `v0.1.0-alpha.1` 候选 commit / tag 前检查
- 生成 AAR、sample APK、server 构建产物
- 准备 GitHub release body

### 2026-05-04 到 2026-05-08：增强项

- GitHub manual E2E 首跑
- OEM / mainland staging 留档
- private risk explain / false-positive matrix
- 不阻塞 alpha tag；作为 alpha 后续 patch 或 beta 前置项

---

## 4. 每日执行顺序

1. `git status --short --branch`
2. 看最新失败项，只修 P0
3. 跑最小相关测试
4. 更新对应验收文档
5. 提交小 commit
6. 当天结束前确认是否仍阻塞 alpha

---

## 5. 风险与兜底

- **真机不可用**：不阻塞 alpha 发布，但必须留下 blocked record；模拟器 E2E 作为 alpha 主证据，真机作为 alpha patch 增强项。
- **GitHub hosted E2E 未配置 secrets**：不阻塞 alpha；保留 workflow scaffold 和本地 E2E 记录。
- **public/private 文档漂移**：阻塞发布。公开文档必须清楚说明 public fallback 与 private core 的边界。
- **secure reporting API 31+ 限制**：alpha release note 必须说明；beta 前再规划 API 23-30 兼容策略。
- **private detector 内容继续变化**：不得扩大 public API；只允许通过 private catalog / runtime / backend 替换点深化。

---

## 6. Alpha 后路线

Alpha 完成后，开发重心切到三条线：

1. **Beta 稳定性**
   - API 23-30 secure reporting 兼容
   - payload parser fuzz
   - false-positive matrix
   - 真机 / 云机 / root 样本持续回归

2. **Private 能力深化**
   - Frida / Xposed / Zygisk / Unidbg 双路径 detector
   - 私有风控权重和 tenant profile
   - OEM attestation production verifier

3. **产品化**
   - tenant dashboard
   - release automation
   - docs site
   - 最小 CLI baseline generator
