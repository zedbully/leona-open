# Leona Docs Index

> 更新时间: 2026-04-29
> 用途：作为当前项目的文档入口，按“先收口、再验收、再发布”的顺序阅读。

---

## 1. 现在继续项目，先看这 4 份

1. `/Users/a/back/Game/cq/docs/closeout-strategy.md`
2. `/Users/a/back/Game/cq/docs/open-vs-private-final-matrix.md`
3. `/Users/a/back/Game/cq/docs/phase-execution-checklist.md`
4. `/Users/a/back/Game/cq/docs/final-acceptance-summary.md`
5. `/Users/a/back/Game/cq/docs/alpha-development-plan.md`

---

## 2. 当前最关键文档

- 当前状态：`/Users/a/back/Game/cq/docs/current-status.md`
- Alpha 开发计划：`/Users/a/back/Game/cq/docs/alpha-development-plan.md`
- 最终收口策略：`/Users/a/back/Game/cq/docs/closeout-strategy.md`
- 开源版 / 私有版最终边界矩阵：`/Users/a/back/Game/cq/docs/open-vs-private-final-matrix.md`
- 私有模块拆分：`/Users/a/back/Game/cq/docs/private-module-split.md`
- 开源发布前清理清单：`/Users/a/back/Game/cq/docs/open-source-release-checklist.md`
- 总体验收总结：`/Users/a/back/Game/cq/docs/final-acceptance-summary.md`
- 执行阶段总清单：`/Users/a/back/Game/cq/docs/phase-execution-checklist.md`
- Public-only 构建验收：`/Users/a/back/Game/cq/docs/public-only-build-record-2026-04-23.md`
- Public-only 构建复验：`/Users/a/back/Game/cq/docs/public-only-build-record-2026-04-24.md`
- 私有模块最终验收：`/Users/a/back/Game/cq/docs/private-module-verify-record-2026-04-24.md`
- 发布前清理记录：`/Users/a/back/Game/cq/docs/release-cleanup-record-2026-04-24.md`
- 最终发布口令清单：`/Users/a/back/Game/cq/docs/release-final-commands.md`
- 模拟器联调留档：`/Users/a/back/Game/cq/docs/demo-record-2026-04-23.md`
- Attestation 摘要专项留档：`/Users/a/back/Game/cq/docs/attestation-record-2026-04-25.md`
- Admin 联调留档：`/Users/a/back/Game/cq/docs/admin-record-2026-04-23.md`
- 观测留档：`/Users/a/back/Game/cq/docs/observability-record-2026-04-23.md`
- CI E2E 说明：`/Users/a/back/Game/cq/docs/ci-e2e-setup.md`
- 本地执行入口：`/Users/a/back/Game/cq/docs/local-runbook.md`
- 本地/线上数据同步执行包：`/Users/a/back/Game/cq/docs/online-data-sync-runbook.md`
- 真机 attestation 执行包：`/Users/a/back/Game/cq/docs/physical-attestation-runbook.md`
- Alpha 发布准备：`/Users/a/back/Game/cq/docs/alpha-release-prep.md`
- Alpha release notes：`/Users/a/back/Game/cq/docs/alpha-release-notes.md`
- 大陆 / 非 GMS 收口总览：`/Users/a/back/Game/cq/docs/mainland-closeout-summary.md`
- 大陆 / 非 GMS OEM 留档：`/Users/a/back/Game/cq/docs/mainland-attestation-record-2026-04-25.md`
- 大陆 / 非 GMS 风险分层：`/Users/a/back/Game/cq/docs/mainland-attestation-risk-posture.md`
- 大陆 / 非 GMS 验收清单：`/Users/a/back/Game/cq/docs/mainland-attestation-acceptance-checklist.md`
- 大陆 / 非 GMS 设计稿：`/Users/a/back/Game/cq/docs/mainland-non-gms-attestation-design.md`

---

## Mainland / 非 GMS 快速入口

1. `/Users/a/back/Game/cq/docs/mainland-closeout-summary.md`
2. `/Users/a/back/Game/cq/docs/mainland-attestation-record-2026-04-25.md`
3. `/Users/a/back/Game/cq/docs/mainland-attestation-risk-posture.md`
4. `/Users/a/back/Game/cq/leona-sdk-android/docs/mainland-attestation-release-gate.md`
5. `/Users/a/back/Game/cq/leona-sdk-android/docs/mainland-attestation-e2e.md`
6. `/Users/a/back/Game/cq/docs/mainland-attestation-acceptance-checklist.md`

---

## 3. 当前收口判断

当前不是继续扩 public 功能，而是进入 **freeze / closeout**：

1. **public 边界冻结**：公开仓库只保留 shell、sample、docs、fallback
2. **private 边界深化**：核心检测内容与后台策略只继续落在 private core / private backend
3. **工程优先级切换**：优先 bugfix、验证、文档、发布清理，不再扩 public 面

---

## 4. 当前剩余项（按收口优先级）

1. 在真实 Git 工作树里执行最后一轮 `git status` / `git diff --cached` 检查
2. 条件允许时补真机留档
3. 在真实 GitHub 仓库配置 secrets / variables 并跑首次 live emulator E2E
4. 如需继续补 attestation 侧留档，优先补真机记录 / 真 OEM 记录
5. 如正式发布前有改动，再补一轮 public-only 构建检查
6. 后续新增能力只进入 private 模块
