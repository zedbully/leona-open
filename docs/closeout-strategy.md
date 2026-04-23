# Leona 最终收口策略

> 更新时间：2026-04-24
> 目标：把当前阶段收敛成“**公开版可发布、私有版可继续深化**”的稳定形态。

---

## 1. 当前收口结论

Leona 当前不再继续扩 public 边界，正式进入：

> **Open Shell 冻结 + Private Core / Private Backend 深化**

也就是：

- 公开版负责：可构建、可演示、可接入、可说明边界
- 私有版负责：核心检测、核心策略、内部运维、生产化集成

---

## 2. 收口目标状态

达到以下状态，就算这一阶段完成：

### 公开版

- 能独立构建
- 能独立演示 sample flow
- 能说明接入方式与系统边界
- 不暴露高价值检测规则与真实风控策略

### 私有版

- Android private core 能独立构建并被 sample / 正式接入方打包
- server private backend 能独立构建并通过 bridge 接入 admin-service
- 私有策略、私有配置、私有 internal ops 都只留在 private 路径

---

## 3. 开源版保留范围

### Android

保留：

- `Leona` / `LeonaConfig` / `BoxId` / `BoxIdCallback` / `Honeypot`
- `sample-app`
- OSS fallback `NativeRuntime`
- `libleona.so`
- 弱化后的 detector catalog / fallback heuristics
- SDK 文档、changelog、runbook、E2E scaffold

不再新增：

- 更深的高价值 detector 规则公开面
- 更强的 native 对抗逻辑公开实现
- 真实私有 JNI 策略实现

### Server

保留：

- `common`
- `gateway`
- `ingestion-service`
- `query-service`
- `admin-service`
- `worker-event-persister`
- 默认 fallback scorer / fallback policy
- OpenAPI、docker compose、observability、runbook 文档

不再新增：

- 真实生产风险阈值公开化
- tenant 特化策略公开化
- 私有 internal ops controller 公开化
- 私有 crypto/provider 真实实现公开化

---

## 4. 私有版保留范围

### Android private core

继续只放在：

- `/Users/a/back/Game/cq/leona-sdk-android/private/sdk-private-core`

保留并继续深化：

- `PrivateNativeRuntime`
- `libleona_private.so`
- private JNI bridge
- private detector catalogs / heuristics
- 更高价值的 native runtime 对抗逻辑

### Server private backend

继续只放在：

- `/Users/a/back/Game/cq/leona-server/private/api-backend`

保留并继续深化：

- `PrivateApiCryptoBootstrap`
- `PrivateRiskScoringEngine`
- `PrivateRiskScorePolicy`
- `PrivateSensitiveEventRules`
- tenant / stage / profile aware risk config
- private config file / env / JVM property 边界
- private internal ops endpoint
- 生产密钥 / KMS / Vault / 私有部署配置

---

## 5. 冻结边界规则

从现在开始按下面规则执行：

### Rule A：不再扩大 public 攻防细节

允许：

- 修 bug
- 补测试
- 补文档
- 修 fallback
- 修 sample / demo 可用性

不允许作为主线：

- 在 public repo 新增更强 detector 规则
- 在 public repo 写入真实策略阈值
- 在 public repo 暴露真实内部 API / 运维逻辑

### Rule B：新增高价值能力默认进 private

以下新增项默认只进 private：

- 更敏感 detector catalog
- 更完整 heuristic / signature / fingerprint
- 更严格 risk scoring / policy tuning
- tenant 级差异化策略
- internal ops / rollout / explain / simulate 深化能力
- 密钥、证书、KMS、Vault、内网集成

### Rule C：public 只做壳，不做核心

公开仓库后续只承担：

- API shell
- sample
- docs
- OSS fallback
- CI / E2E scaffold

---

## 6. 允许继续做的事

### 公开版允许继续

1. 文档校对与对外口径统一
2. sample-app 可用性增强
3. public-only build / demo 验证
4. CI / E2E 收口
5. 真机留档补充

### 私有版允许继续

1. Android private runtime 深化
2. 私有 backend 风控深化
3. 运维能力深化
4. rollout / explain / simulation 深化
5. 生产配置、密钥与内网能力接入

---

## 7. 不建议继续做的事

这一阶段不建议继续：

- 扩更多 public API 面
- 扩 public detector 细节
- 扩新的 public server 复杂策略接口
- 重新把 private 能力挪回 public
- 为了“看起来完整”继续扩大开源暴露面

---

## 8. 发布前收口动作

### 必做

1. 按 `/Users/a/back/Game/cq/docs/open-source-release-checklist.md` 逐项过一遍
2. 跑 `/Users/a/back/Game/cq/scripts/verify-private-modules.sh`
3. 确认 public-only 验收记录仍成立
4. 检查 README / docs 首页口径是否已经统一
5. 检查是否还有 private 细节泄露到公开文档

### 增强项

1. 真机留档
2. 首次 GitHub live emulator E2E
3. 更完整 private runtime / backend 深化

---

## 9. 最终验收口径

这一阶段完成的标准是：

> **公开版已经可以独立发布；私有版已经有稳定接入口；后续新增高价值能力默认只进入 private。**

如果继续推进，默认方向不是“扩 public”，而是：

> **只做稳定、验证、文档、发布清理，以及 private 深化。**
