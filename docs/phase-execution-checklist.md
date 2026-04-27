# Leona 按 Phase 执行 + 验收总清单

> 更新时间: 2026-04-27
> 用途：按顺序推进实现时，直接把这份清单当作执行入口和验收总表使用。

状态说明：

- `[x]` 已完成
- `[-]` 进行中 / 部分完成
- `[ ]` 未完成

---

## Phase 0：文档与现状对齐

### 执行项
- [x] 统一项目战略范围到 Android 优先
- [x] 统一 SDK / server / CLI 的当前状态描述
- [x] 新增统一状态文档
- [x] 收口路线图与执行阶段定义

### 验收标准
- [x] 文档不再把当前项目描述成“纯想法”
- [x] 主线清晰收敛到 Android SDK ↔ Server alpha 闭环

---

## Phase 1：Android SDK ↔ Server 真闭环

### 执行项
- [x] handshake 走已注册 appKey 校验
- [x] `/v1/sense` 验签使用真实 session key
- [x] `/v1/sense` AES-GCM AAD 改为 `sessionId`
- [x] BoxId JSON 契约对齐为字符串
- [x] verdict 热路径支持直接读取 Redis snapshot
- [x] BoxId 过期判断改为 epoch millis
- [x] 新增 Android 联调执行脚本（`/Users/a/back/Game/cq/leona-sdk-android/scripts/run-live-sample.sh`）
- [x] 修复 Android X25519 兼容性

### 验收标准
- [x] handshake / sense / verdict 协议链路逻辑对齐
- [x] sample app / demo backend / OpenAPI 对 BoxId body 形态一致
- [x] 模拟器真实闭环留档完成
- [x] 一键式联调构建 / 安装入口已具备

---

## Phase 2：演示链路

### 执行项
- [x] sample app 支持 Gradle 属性注入
- [x] demo backend 可代理查询 `/v1/verdict`
- [x] sample app 展示 BoxId / decision / risk / score
- [x] verdict 响应签名与 demo backend 校验打通
- [x] sample app 带真实 BuildConfig 参数的 debug 构建已验证
- [x] sample app 本地 demo cleartext 限制已处理

### 验收标准
- [x] 演示链路文档已具备
- [x] debug APK 已产出
- [x] 模拟器真实演示截图 / 日志留档已完成

---

## Phase 3：Server MVP 收口

### 执行项
- [x] BoxId single-use / expired 生命周期收口
- [x] key revoke
- [x] key rotate
- [x] verdict 响应签名
- [x] worker DLQ
- [x] 最小 metrics 埋点
- [x] admin / query API 验收文档
- [x] 修复 ingestion-service Kafka idempotent producer 配置
- [x] admin 真实联调留档
- [x] 最小 observability dashboard / alerting 收口

### 验收标准
- [x] OpenAPI 与控制器能力基本一致
- [x] 核心收口项都有文档或测试支撑
- [x] dashboard / alerting 已完成最小收口（`/Users/a/back/Game/cq/docs/observability-record-2026-04-23.md`）
- [x] admin 真实联调已留档（`/Users/a/back/Game/cq/docs/admin-record-2026-04-23.md`）

---

## Phase 4：测试

### 执行项
- [x] common 单测
- [x] gateway filter 单测
- [x] ingestion-service 单测
- [x] admin-service service/controller 测试
- [x] query-service repository/service/webmvc 测试
- [x] Redis claim mock 测试
- [x] Redis claim 真实集成测试草稿
- [x] Android 模拟器人工 E2E 验收
- [x] Android ↔ Server E2E 自动化脚本

### 验收标准
- [x] 主要分支与契约测试已覆盖到位
- [x] `leona-server` 全量 `test` 已通过
- [x] `RedisBoxIdClaimIntegrationTest` 已通过真实 Redis 容器脚本硬验收
- [x] `docker compose` 本地 5 服务栈已真实启动并通过健康检查
- [x] Android ↔ Server E2E 自动化
  - 脚本：`/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-e2e.sh`
  - 最近执行：2026-04-27
  - 结果：UI/demo `BoxId=01KQ792YC06BAEHG4WQZH308WX`，formal `/v1/verdict` `BoxId=01KQ794PAP1N9SXQVQ501B1075`，`canonical=L8a5d40fa9aa6a9ebd14101ef9b62c5b`，`decision=deny`，`risk=CRITICAL`，`score=100`
  - 已校验：formal verdict response signature、`canonicalDeviceId`、`deviceFingerprint`、跨 surface canonical 对齐
  - 自动化产物：`/tmp/leona-e2e-20260427-185131`

---

## Phase 5：Android alpha 发布准备

### 执行项
- [x] 补 SDK changelog
- [x] 补 alpha 发布准备文档
- [x] 补联调 / 演示留档模板
- [x] 补 alpha release notes 模板
- [x] 固化 alpha release notes 正式文档
- [x] 补 Java / Gradle 恢复方案文档
- [x] 恢复 Java 构建环境
- [x] 构建 AAR release 产物
- [x] 构建 sample app debug APK 产物
- [x] 验证 sample app 真实联调 BuildConfig 参数注入
- [x] 完成一次真实模拟器联调留档
- [x] 修复 native event category 映射
- [x] 固化对外 release note
- [x] 补 private module split 脚手架
- [x] 迁移第一批敏感 detector catalog / heuristics 到 private core
- [x] 补 private module split 一键验收脚本
- [x] 补 public-only 构建验收记录
- [-] 补真机留档（执行包已就绪，待 USB 真机执行）
  - `/Users/a/back/Game/cq/leona-sdk-android/scripts/run-device-attestation-e2e.sh`
  - `/Users/a/back/Game/cq/docs/physical-attestation-runbook.md`
  - `/Users/a/back/Game/cq/docs/device-attestation-record-template.md`

### 验收标准
- [x] 发布准备文档已具备
- [x] AAR 产物已确认
- [x] debug APK 产物已确认
- [x] 模拟器 Alpha 证据链已齐备
- [x] 对外发布材料已具备

---

## Phase 6：边界冻结与最终收口

### 执行项
- [x] 固化“开源版保留什么、私有版保留什么”矩阵
- [x] 固化最终收口策略与冻结规则
- [x] 更新 docs 首页与发布清单
- [x] 再跑一轮最终验收脚本并补最新结果（`/Users/a/back/Game/cq/docs/private-module-verify-record-2026-04-24.md`）
- [-] 真正公开发布前再做一轮 GitHub 清理检查（当前环境非 Git 工作树，已先完成可执行清理项）

### 验收标准
- [x] public / private 边界已有最终文档口径
- [x] 后续新增高价值能力默认进入 private
- [x] public 侧执行重点已切换为稳定、文档、验收、发布清理
- [x] 最终验收脚本最新结果已补齐

---

## 当前总判断

### 已通过
- Phase 0
- Phase 1
- Phase 2
- Phase 3
- Phase 4
- Phase 5（真机留档为增强项）
- Phase 6（发布前 GitHub 清理仍需最后一轮执行）

---

## 接下来自动优先级

1. 在真实 Git 工作树里执行 `/Users/a/back/Game/cq/scripts/release-preflight.sh --strict leona-sdk-android leona-server`
2. 如正式发布前还有改动，再补一轮 public-only 构建检查
3. 条件允许时按真机执行包补真机留档
4. 后续新增高价值能力只继续进入 private runtime / private backend
