# Leona 工作目标与迭代工作项

> 更新时间：2026-04-29  
> 用途：这是后续 Codex 会话的第一阅读文档。每次开始工作前，先看本文件，再看 `git status --short --branch`，然后只推进最高优先级的未完成项。

---

## 1. 迭代方向和思路

Leona 当前阶段的核心原则：

- **客户端只采集和上报证据，不做最终决策**。`sense()` 必须尽量成功返回 BoxId；环境风险、模拟器、Root、Hook、Tamper 等只作为事件进入服务端。
- **服务端负责判定、解释和策略演进**。客户端风险标签只用于调试与辅助展示，业务动作以 `/v1/verdict` 返回为准。
- **模拟器检测从运行原理出发**。不只匹配品牌字符串，而是收集 hypervisor/QEMU、CPU 虚拟化、virtio/9p、共享挂载、NAT 网段、设备身份伪装与运行时矛盾等证据。
- **public API 冻结，private 能力深化**。公开仓库保持可构建、可演示、可审计；私有 detector catalog、权重策略和运营解释面继续在 private core / private backend 深化。
- **每次迭代都要留下可复验记录**。实现、测试、模拟器/真机验证、服务端查询结果都要能通过文档或命令复现。

Alpha 阶段目标：

- Android SDK + sample-app + Leona Server + demo-backend 本地闭环稳定。
- BoxId、canonicalDeviceId、support bundle、server verdict 链路稳定。
- MuMu / Android Studio Emulator 等模拟器能被上报并由服务端判定。
- 发布前 public-only、private split、release preflight 可重复通过。
- 真机 E2E 和 GitHub live E2E 若当前环境不可用，必须有明确 blocked 记录和后续执行入口。

---

## 2. 当前已完成

- [x] 深度阅读项目并形成 Alpha 开发计划。
- [x] 提交首轮整理与收口代码。
- [x] sample-app 界面改为中文。
- [x] 修复客户端运行时风险不应阻断 `sense()` 的问题，保持上报优先。
- [x] 修复同设备 canonical device id 稳定性问题。
- [x] 修复 sample 查询判定的服务端地址与配置展示问题。
- [x] 重新安装并验证 sample-app 到 MuMu 模拟器 `127.0.0.1:16512`。
- [x] MuMu 表层特征检测已覆盖：`nemud.*`、`nemu*` service、MuMu binary、QEMU hypervisor prop。
- [x] 新增模拟器原理级 native 探针：QEMU/hypervisor、guest control service、guest metadata、CPU `linux,dummy-virt`、合成 ARM CPU profile、virtio devices、virtio/9p shared mount、QEMU NAT subnet、consumer brand virtualization conflict。
- [x] 服务端 verdict tag 已细化输出 `environment.emulator.detected`。
- [x] MuMu 实测通过：新 BoxId `01KQBAEJW4RR75TSFJY62Z7EE3` 收到原理级 emulator events，sample 查询显示 `environment.emulator.detected`。
- [x] Android SDK 单测和 sample-app 构建通过。
- [x] Server common 单测通过。
- [x] 本地 `query-service` 已用最新 jar 重建并重启。
- [x] 新增 Codex 启动工作项入口：`AGENTS.md` 与 `docs/work-items.md`。
- [x] GitHub Actions workflow 已从子目录提升到仓库根目录 `.github/workflows/android.yml`，并适配 monorepo 运行路径。

---

## 3. P0：Alpha 发布前必须完成

- [ ] **补 USB 物理真机 E2E 留档**
  - 入口：`/Users/a/back/Game/cq/leona-sdk-android/scripts/run-device-e2e.sh`
  - 验收：记录 BoxId、canonicalDeviceId、support bundle、server verdict、risk tags。
  - 当前状态：blocked，2026-04-29 再次检查 ADB，只发现 MuMu `127.0.0.1:16512` 与 Android Studio Emulator `emulator-5554`，未发现 USB 物理真机。

- [ ] **GitHub manual live E2E 首跑**
  - 入口：`/Users/a/back/Game/cq/.github/workflows/android.yml`
  - 验收：Actions summary 显示 BoxId、canonical、risk、attestation provider/status/code。
  - 当前状态：workflow 已移动到 GitHub 可识别的根目录，待推送后配置真实仓库 secrets / variables 并首次触发。

- [ ] **最终文档一致性收口**
  - 核对：`README.md`、`docs/current-status.md`、`docs/alpha-development-plan.md`、`docs/final-acceptance-summary.md`、OpenAPI。
  - 验收：不把 private-only 能力写成 public-only 已完整启用能力。

- [ ] **最终 release preflight**
  - 命令：`/Users/a/back/Game/cq/scripts/release-preflight.sh --strict leona-sdk-android leona-server`
  - 验收：strict 通过并更新执行记录。

- [ ] **最终 public-only / private split 复验**
  - 入口：既有 public-only 构建记录流程和 `/Users/a/back/Game/cq/scripts/verify-private-modules.sh`
  - 验收：公开构建无 private 依赖，private 模块可独立验证。

- [ ] **GitHub advisory 检查债务收敛**
  - 当前：root workflow 已启用，但 Android lint 和 native clang-format 暂作为 advisory，不阻塞 unit/build。
  - 已知项：SDK lint 中有 API guard / hidden API / device id / hardcoded path 警告；当前首个 lint 错误是 `AppIntegrity.kt` 的 `ComponentInfo#directBootAware` API 24 guard；native C++ 历史代码不符合 `clang-format --style=Google`。
  - 验收：引入 lint baseline 或逐项修复，并明确 native format 风格后再恢复 blocking gate。

---

## 4. P1：Alpha 后续增强

- [ ] **模拟器样本矩阵扩充**
  - 覆盖：MuMu、Android Studio Emulator、Nox、LDPlayer、BlueStacks、Genymotion、云手机。
  - 目标：每个样本记录运行原理证据，不只记录品牌特征。

- [ ] **误报 / 漏报矩阵**
  - 覆盖：干净真机、debuggable sample、Root、Hook、虚拟容器、模拟器、云手机、Unidbg。
  - 验收：每类样本有 expected risk level、已知误报说明、回归命令。

- [ ] **服务端策略解释面**
  - 目标：每个 escalation reason 能在 internal ops view 中解释来源。
  - 覆盖：tenant、stage、deployment profile、private policy reason、event id。

- [ ] **大陆 / 非 GMS 真 OEM 路线**
  - 当前：`oem_debug_fake` 已可用。
  - 下一步：接 1 个真实 OEM bridge 或 staging verifier dry run。

- [ ] **客户端 evidence 最小化与隐私审计**
  - 目标：证明 native evidence 只上传必要片段，敏感值脱敏或截断。
  - 特别检查：系统属性、CPU/mount/network sample、device identity。

---

## 5. P2：Beta 前规划

- [ ] Android API 23-30 secure reporting 兼容方案。
- [ ] 真实 Play Integrity production bridge 接入样例。
- [ ] Server payload parser fuzz / chaos test。
- [ ] Private detector 双路径 hardening。
- [ ] Tenant dashboard 与运营视图。
- [ ] CLI scanner 从 placeholder 升级为最小 APK baseline generator。
- [ ] Release automation 和 docs site。

---

## 6. 每次 Codex 启动后的固定动作

1. 阅读 `/Users/a/back/Game/cq/docs/work-items.md`。
2. 运行 `git status --short --branch`。
3. 如果用户没有指定新方向，优先推进 P0 中第一个未完成项。
4. 开始改代码前，先确认相关文档和最近提交。
5. 每完成或阻塞一个工作项，更新本文件的 checkbox 与状态说明。
6. 每轮结束前提交小 commit，或明确说明为什么暂不提交。

---

## 7. 最近验证记录

- 2026-04-29：MuMu `127.0.0.1:16512` 实测 `sense()` 成功，BoxId `01KQBAEJW4RR75TSFJY62Z7EE3`。
- 2026-04-29：Redis 收到原理级事件：`env.emulator.runtime.*`、`env.emulator.cpu.*`、`env.emulator.sysfs.virtio_devices`、`env.emulator.fs.virtio_9p_shared_mount`、`env.emulator.net.qemu_nat_subnet`、`env.emulator.identity.consumer_brand_virtualized`。
- 2026-04-29：sample verdict 返回 `environment.emulator.detected`。
- 2026-04-29：提交 `52a7a64 feat: add runtime emulator probes`。
- 2026-04-29：提交 `bfb59fd docs: add codex work item tracker`。
- 2026-04-29：已同步 `main` 到 GitHub `origin/main`；远端 fetch 后无新提交需要合并，首次 push 将远端从 `200cb18` 推进到 `9547be8`。
- 2026-04-29：发现 GitHub workflow 放在 `leona-sdk-android/.github/workflows/`，真实仓库不会识别；已移动到 `.github/workflows/android.yml` 并调整运行路径。
- 2026-04-29：首次触发 root workflow 时发现 job-level `runner.temp` 上下文解析失败；已改为固定 `/tmp/leona-*` 输出目录。
- 2026-04-29：GitHub `run_alpha_closure` 已能创建 run；后续失败点定位为 public checkout 缺少 private core、历史 C++ clang-format gate、SDK lint 缺少 VPN 权限保护。
- 2026-04-29：CI lint / clang-format 先改为 advisory；`verify-closure.sh` 已适配 public-only checkout 缺少 `:sdk-private-core` 的情况。
- 2026-04-29：GitHub run `25085752269` 失败点收敛为 `TamperCatalogParityTest` 在 public checkout 缺少 `private/sdk-private-core/src/main/cpp/private_tamper_catalog.h`；已改为 public catalog 与 detector 必测，private catalog 存在时再检查 public/private parity。
- 2026-04-29：SDK manifest 已声明普通权限 `ACCESS_NETWORK_STATE`，用于被动 VPN/network evidence，lint 的 VPN 权限阻塞点已消除。
- 2026-04-29：本地验证通过：`:sdk:testDebugUnitTest`、`scripts/verify-closure.sh`、public-only 临时 checkout 的 clean/no-build-cache `:sdk:testDebugUnitTest`。
