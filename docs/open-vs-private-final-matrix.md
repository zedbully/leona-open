# Leona 开源版 / 私有版最终边界矩阵

> 更新时间：2026-04-24
> 用途：作为最终收口时的边界说明与发布检查基线。

---

## 1. 总体原则

| 项目 | 开源版 | 私有版 |
|---|---|---|
| 目标 | 可构建、可演示、可接入 | 可对抗、可运营、可生产化 |
| 角色 | Open Shell | Private Core / Private Backend |
| 对外可见性 | 可公开 | 不对外开源 |
| 后续新增高价值能力 | 不建议继续加 | 默认进入这里 |

---

## 2. Android 边界

| 模块/能力 | 开源版保留 | 私有版保留 | 备注 |
|---|---|---|---|
| `Leona` / `LeonaConfig` / `BoxId` / `Honeypot` | 是 | 可复用 | public API 保持稳定 |
| `sample-app` | 是 | 可带 private core 联调 | 公开版保留演示能力 |
| OSS `NativeRuntime` | 是 | 否 | 作为 fallback runtime |
| `PrivateNativeRuntime` | 否 | 是 | private runtime 主入口 |
| `libleona.so` | 是 | 可共存 | OSS native 库 |
| `libleona_private.so` | 否 | 是 | private native 库 |
| public fallback detector catalog | 是 | 否 | 仅保留弱化版/空实现 |
| private detector catalog / heuristics | 否 | 是 | 高价值规则全部只留 private |
| private JNI bridge | 否 | 是 | 不进入公开仓库 |
| 更完整 native 对抗逻辑 | 否 | 是 | 后续新增默认 private |

---

## 3. Server 边界

| 模块/能力 | 开源版保留 | 私有版保留 | 备注 |
|---|---|---|---|
| `common` | 是 | 复用 | 公共协议与基础能力 |
| `gateway` | 是 | 复用 | 公共接入层 |
| `ingestion-service` | 是 | 复用 | 公共数据入口 |
| `query-service` | 是 | 复用 | verdict 查询 |
| `admin-service` | 是 | 通过 bridge 导入 private 能力 | public 只保留 bridge |
| `worker-event-persister` | 是 | 复用 | 公共 worker 骨架 |
| fallback risk scorer / policy | 是 | 否 | public 默认弱化策略 |
| `private/api-backend` | 否 | 是 | 私有后台模块 |
| `PrivateRiskScoringEngine` | 否 | 是 | 私有风控引擎 |
| `PrivateRiskScorePolicy` | 否 | 是 | 私有阈值/权重策略 |
| `PrivateSensitiveEventRules` | 否 | 是 | 私有高价值事件规则 |
| private internal ops endpoint | 否 | 是 | 仅内部运维启用 |
| tenant / stage / profile aware config | 否 | 是 | 私有化部署调优 |
| KMS / Vault / 密钥 / 生产配置 | 否 | 是 | 永不进入公开仓库 |

---

## 4. 文档与演示边界

| 内容 | 开源版保留 | 私有版保留 | 备注 |
|---|---|---|---|
| 接入 README / runbook | 是 | 可补内部版 | 对外只讲边界和接入 |
| demo-backend | 是 | 可选 | 用于最小演示 |
| alpha release notes | 是 | 可复用 | 对外版本说明 |
| private 实现细节 | 否 | 是 | 文档中只说边界，不说细节 |
| internal ops 细节文档 | 否 | 是 | 内部运维使用 |
| private config 样例 / 生产部署资料 | 否 | 是 | 内部资产 |

---

## 5. 发布边界判断

满足以下判断时，可以认定边界已成立：

- 开源版去掉 `private/` 后仍可独立构建
- 私有版加回 `private/` 后仍可独立增强
- public 文档不泄露真实高价值规则
- admin-service 只保留 bridge，不保留 private controller 实现
- Android private runtime 与 server private backend 都有独立构建与验收路径

---

## 6. 后续默认规则

从现在开始：

- **公开版默认只修稳定性、文档、演示、fallback**
- **私有版默认承接所有高价值新增能力**
- **任何让 public 边界变厚的改动，都需要被视为例外而不是默认**
