# Leona Phase 验收清单

> 更新时间: 2026-04-23
> 说明：该清单用于跟踪按 Phase 推进后的阶段性验收结果。

状态说明：

- `[x]` 已完成
- `[-]` 部分完成 / 进行中
- `[ ]` 未完成

---

## Phase 0：文档与现状对齐

- [x] 统一 `leona-sdk-android/README.md`
- [x] 统一 `leona-server/README.md`
- [x] 统一 `leona/README.md`
- [x] 统一 `roadmap.md`
- [x] 统一 `docs/strategy.md`
- [x] 新增 `docs/current-status.md`

### Phase 0 验收结论

**通过。**

---

## Phase 1：打通 Android SDK ↔ Server 真闭环

- [x] handshake 走已注册 appKey 校验
- [x] `/v1/sense` 网关按 `X-Leona-Session-Id` 读取真实 session key 验签
- [x] `/v1/sense` 解密 AAD 改为与 Android SDK 一致的 `sessionId`
- [x] BoxId JSON 契约已对齐为字符串
- [x] ingestion 热路径立即写 Redis verdict 快照
- [x] query-service 可直接从 Redis 读取 risk snapshot
- [x] BoxId claim 增加过期检查
- [x] BoxId 维持 single-use 语义
- [x] 已新增 `/Users/a/back/Game/cq/leona-sdk-android/scripts/run-live-sample.sh`
- [x] 模拟器上完成一次 Android sample app → server → verdict 联调
- [x] Android X25519 兼容性问题已修复

### Phase 1 当前结论

**通过。**

---

## Phase 2：演示链路

- [x] sample app 支持通过 Gradle 属性配置
- [x] sample app 页面展示 server mode
- [x] sample app 支持查询 demo verdict
- [x] sample app 展示 decision / risk / score
- [x] 新增最小 demo backend
- [x] 新增 `docs/demo-flow.md`
- [x] demo backend 可代表业务后端调用 `/v1/verdict`
- [x] sample app 带真实 BuildConfig 参数的构建已验证
- [x] sample app debug APK 已产出
- [x] 模拟器真实演示截图 / 留档已完成（`docs/demo-record-2026-04-23.md`）

### Phase 2 当前结论

**通过。**

---

## Phase 3：Server MVP 收口

- [x] BoxId 基础生命周期继续完善（single-use / expired）
- [x] key revoke 接口已补齐
- [x] key rotate 接口已补齐
- [x] admin / query 最小 API 验收文档已补
- [x] worker DLQ
- [x] verdict 响应签名
- [x] ingestion-service Kafka producer 配置已修复
- [x] native event category 映射已修复
- [x] admin 真实联调留档已完成（`/Users/a/back/Game/cq/docs/admin-record-2026-04-23.md`）
- [x] 最小 observability dashboard / alerting 已完成（`/Users/a/back/Game/cq/docs/observability-record-2026-04-23.md`）

### Phase 3 当前结论

**通过。**

---

## Phase 4：测试

- [x] `leona-server` 全量 `test` 已在 2026-04-22 真实执行通过
- [x] `RedisBoxIdClaimIntegrationTest` 已通过真实 Redis 容器脚本硬验收
- [x] `docker compose` 本地 5 服务栈已真实启动并通过健康检查
- [x] Android 模拟器人工 E2E 已通过
- [x] Android ↔ Server E2E 自动化已通过（`/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-e2e.sh`）
  - 最近执行：2026-04-23
  - BoxId：`01KPV5E417A7467GRBRMQXYF30`
  - Verdict：`decision=deny` / `risk=CRITICAL` / `score=100`
  - 产物目录：`/tmp/leona-e2e-20260423-015719`

### Phase 4 当前结论

**通过。**

---

## Phase 5：Android alpha 发布准备

- [x] SDK changelog 已补
- [x] alpha 发布准备文档已补
- [x] 联调 / 演示留档模板已补
- [x] alpha release notes 模板已补
- [x] alpha release notes 正式文档已补（`/Users/a/back/Game/cq/docs/alpha-release-notes.md`）
- [x] Java / Gradle 恢复方案文档已补
- [x] 总体验收总结已补
- [x] 文档索引与本地命令总览已补
- [x] Android AAR 产物已构建并确认
- [x] sample app debug APK 已构建并确认
- [x] sample app 真实联调参数注入已验证
- [x] 模拟器真实联调留档已完成
- [x] alpha release note 最终定稿
- [x] private module split 脚手架已补（`/Users/a/back/Game/cq/docs/private-module-split.md`）
- [x] 第一批敏感 detector catalog / heuristics 已迁入 Android private core
- [x] private module split 一键验收脚本已补（`/Users/a/back/Game/cq/scripts/verify-private-modules.sh`）
- [x] public-only 构建验收记录已补（`/Users/a/back/Game/cq/docs/public-only-build-record-2026-04-23.md`）
- [ ] 真机留档（可选增强项）

### Phase 5 当前结论

**通过（真机留档为增强项）。**

---

## 当前总体验收判断

### 已通过
- Phase 0
- Phase 1
- Phase 2
- Phase 3
- Phase 4
- Phase 5

---

## 下一步建议

1. 条件允许时补一轮真机留档
2. 在真实 GitHub 仓库配置 secrets / variables 并跑一次 live emulator E2E
3. 继续把 private runtime / private backend 真实实现收口
