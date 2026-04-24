# Leona 开源发布前清理清单

> 更新时间: 2026-04-24
> 用途：在把仓库整理成真正公开可发 GitHub 版本前，逐项执行与验收。

---

状态说明：

- `[x]` 已完成 / 已有证据
- `[-]` 已具备基础，但发布前仍需再确认
- `[ ]` 尚未完成

---

## 1. 目标

这份清单只解决一件事：

> **让公开仓库可构建、可演示、可接入，但不泄露核心检测内容与私有后台策略。**

发布后目标形态：

- 开源版 = Open Shell
- 私有版 = Private Core + Private Backend

---

## 2. 开源版必须保留

### Android

- [x] 保留 public API：
  - `Leona`
  - `LeonaConfig`
  - `BoxId`
  - `BoxIdCallback`
  - `Honeypot`
- [x] 保留 `sample-app`
- [x] 保留 `sdk` 的 OSS fallback runtime
- [x] 保留 `libleona.so`
- [x] 保留 public fallback detector catalog
- [x] 保留接入 README / changelog / docs
- [x] 保留 E2E / CI scaffold

### Server

- [x] 保留 `common`
- [x] 保留 `gateway`
- [x] 保留 `ingestion-service`
- [x] 保留 `query-service`
- [x] 保留 `admin-service`
- [x] 保留 `worker-event-persister`
- [x] 保留 OpenAPI / docker compose / observability 文档
- [x] 保留默认 fallback risk scorer / risk policy

### Demo / Docs

- [x] 保留 `demo-backend`
- [x] 保留 docs 目录
- [x] 保留本地 runbook
- [x] 保留 alpha 演示链路文档

---

## 3. 私有版必须保留

### Android private core

- [x] `private/sdk-private-core`
- [x] `PrivateNativeRuntime`
- [x] `libleona_private.so`
- [x] private JNI bridge
- [x] private detector catalogs / heuristics
- [-] 更完整的 native detector 实现
- [ ] 后续真实 private runtime 对抗逻辑

### Server private backend

- [x] `private/api-backend`
- [x] `PrivateApiCryptoBootstrap`
- [x] `PrivateRiskScoringEngine`
- [x] `PrivateRiskScorePolicy`
- [x] `PrivateSensitiveEventRules`
- [x] tenant-specific / environment-specific 策略
- [x] private risk config file / env / JVM property 边界
- [x] 私有 internal ops endpoint bridge
- [x] private internal ops 显式启用开关
- [ ] 生产密钥 / KMS / Vault / 内部配置
- [ ] 私有内部 API / 运维配置

---

## 4. 发布前必须删掉或确认不进入公开仓库

### Git 边界

- [ ] `leona-sdk-android/private/` 不进入公开仓库
- [ ] `leona-server/private/` 不进入公开仓库
- [x] Android / Server 子仓库 `.gitignore` 已覆盖 private 目录
- [-] 无临时调试文件 / 本地密钥 / 本地配置残留（已清理 `.DS_Store`，`application-local.yml` 已改为 example；仍需在真实 Git 工作树复查）

### Android 敏感内容

- [x] 不公开完整 Frida signatures
- [x] 不公开完整 injection library needles
- [x] 不公开完整 emulator / root / xposed / unidbg 高价值规则
- [x] 不公开 private JNI 实现
- [x] 不公开 private so 的真实策略逻辑

### Server 敏感内容

- [x] 不公开真实风险权重
- [x] 不公开真实风险阈值
- [x] 不公开 tenant 特化策略
- [x] 不公开私有 API crypto 细节
- [ ] 不公开生产环境配置
- [ ] 不公开任何密钥/证书/KMS/Vault 接入

---

## 5. 发布前必须验证 public fallback 仍可独立工作

### Android public-only 验收

- [x] 去掉 `private/sdk-private-core` 后，`sdk` 仍可构建
- [x] 去掉 `private/sdk-private-core` 后，`sample-app` 仍可构建
- [x] `sample-app` 仍能跑基本 demo
- [x] public fallback 不依赖 private headers

建议命令：

```bash
cd /Users/a/back/Game/cq/leona-sdk-android
./gradlew :sdk:assembleDebug :sample-app:assembleDebug --no-daemon --no-configuration-cache
```

### Server public-only 验收

- [x] 去掉 `private/api-backend` 后，server 仍可构建
- [x] `common` / `ingestion-service` / `worker-event-persister` 可独立 classes
- [x] 默认 fallback scorer / policy 可工作

建议命令：

```bash
cd /Users/a/back/Game/cq/leona-server
./scripts/gradlew-java21.sh :common:classes :ingestion-service:classes :worker-event-persister:classes --no-daemon --no-configuration-cache
```

---

## 6. 私有模块验收

使用一键脚本：

```bash
/Users/a/back/Game/cq/scripts/verify-private-modules.sh
```

必须确认：

- [x] `libleona_private.so` 真实产出
- [x] sample-app 合并打包 `libleona.so` + `libleona_private.so`
- [x] private backend jar 真实产出
- [x] private module split verification passed

---

## 7. 文档发布前收口

- [x] README 不暴露 private 实现细节
- [x] docs 只说明“边界”和“能力”，不说明高价值规则内容
- [x] 示例命令不要求 private 目录必须存在
- [x] 文档中所有私有路径说明都明确为 internal / optional
- [x] 对外表述统一为：
  - open-source shell
  - private core
  - private backend

---

## 8. GitHub 发布前最终动作

- [x] 检查 `.gitignore`
- [x] 检查 `git diff --cached`
- [x] 检查 `git status`
- [x] 检查是否误提交 private 文件
- [x] public-only 构建跑一遍（2026-04-24 复验：`/Users/a/back/Game/cq/docs/public-only-build-record-2026-04-24.md`）
- [x] private split 验收脚本跑一遍
- [x] README / docs 首页更新
- [x] CHANGELOG / release notes 更新

---

最终发布操作口令：

- `/Users/a/back/Game/cq/docs/release-final-commands.md`
- `/Users/a/back/Game/cq/scripts/release-preflight.sh`

## 9. 最终通过标准

以下全部满足，才算“可公开发布”：

- [x] 开源版可独立构建
- [x] 开源版可独立演示
- [x] 开源版只保留弱化版 detector / risk policy
- [x] 私有版可独立构建 private core / private backend
- [x] Android 私有运行时优先走 `libleona_private.so`
- [x] Server 私有策略不在 public repo 暴露
- [x] 文档不泄露私有实现

---

## 10. 当前仓库的收口结论

截至 2026-04-24，已经完成：

- [x] Android / Server 私有边界已建立
- [x] `sdk-private-core` 已独立产出 `libleona_private.so`
- [x] `PrivateNativeRuntime` 已切到独立 private JNI
- [x] `private/api-backend` 已承载 private risk / config / internal ops 能力
- [x] 一键验收脚本已通过（2026-04-24 复验：`/Users/a/back/Game/cq/docs/private-module-verify-record-2026-04-24.md`）
- [x] public-only 构建验收已完成（`/Users/a/back/Game/cq/docs/public-only-build-record-2026-04-23.md`）
- [x] “开源版保留什么、私有版保留什么” 已固化到：
  - `/Users/a/back/Game/cq/docs/open-vs-private-final-matrix.md`
- [x] 最终收口策略已固化到：
  - `/Users/a/back/Game/cq/docs/closeout-strategy.md`

当前建议：

- **停止继续扩大 public 面**
- **优先做最终验收、发布清理、文档冻结**
- **Git 相关 staged/提交检查放到真实仓库工作树里做最后一轮**
- **后续新增高价值能力默认只进入 private 模块**
