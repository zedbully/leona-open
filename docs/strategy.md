# Leona 三年战略与架构

> 创建日期: 2026-04-19
> 定位锁死日: 2026-04-19
> 执行范围更新: 2026-04-21

---

## 🎯 产品定性(锁死)

**只做移动端应用安全(Android + iOS),其它平台一概不做。**
Android 先行,iOS 等 Android 有商业回报再启动。
开源驱动增长,SaaS 变现。目标客户:海外独立开发者 + 中型公司。

## 当前执行说明

截至 2026-04-21，代码仓库的真实状态与执行优先级如下：

1. **Android runtime SDK 是当前主线**
2. **Server 目标是先打通 BoxId 闭环，而不是先做完整 SaaS 控制台**
3. CLI scanner 目前只保留为后续开源获客入口，不抢当前交付优先级

因此，下面的三年规划继续有效，但近期执行顺序以：

> Android SDK alpha → SDK ↔ Server 闭环 → demo/backend integration → beta 内测

为准。

---

# Part 1:三年路线图

## 总览

| Year | 战略目标 | 核心里程碑 |
|------|---------|----------|
| Year 1 (2026) | Android 全系 + 建立社区 | GitHub 5K stars, ARR $50–100K |
| Year 2 (2027) | iOS 启动 + SaaS 商业化 | ARR $1M, 10K stars, 团队 2–3 人 |
| Year 3 (2028) | 双端企业化 | ARR $5M+, 团队 8–12 人, 细分第一品牌 |

## Year 1 (2026):Android 全系

| 季度 | 产品里程碑 | 社区/商业目标 |
|------|----------|-------------|
| Q1 (M1–M3) | Android SDK alpha + Server 闭环验证 | GitHub 首发、500 stars、跑通内测 demo |
| Q2 (M4–M6) | Android SDK beta：Frida/Xposed/Magisk/蜜罐稳定化 | 1500 stars、3 个早期用户 |
| Q3 (M7–M9) | leona-server MVP：tenant、verdict、策略闭环 | 3000 stars、SaaS 内测、首个付费客户 |
| Q4 (M10–M12) | CLI scanner MVP 作为开源入口 + 文档体系 | 5000 stars、5–10 付费客户、ARR $50–100K |

## Year 2 (2027):iOS 启动 + SaaS 商业化

| 季度 | 产品里程碑 | 社区/商业目标 |
|------|----------|-------------|
| Q5 (M13–M15) | SaaS v1.0:Dashboard、CI/CD 集成、团队管理 | ARR $150K、招首个同事(iOS) |
| Q6 (M16–M18) | leona-fingerprint:持久化设备指纹(ML 模型) | ARR $300K |
| Q7 (M19–M21) | leona-scanner-ios v0.1:iOS 静态扫描开源 | 8000 stars、ARR $500K |
| Q8 (M22–M24) | leona-sdk-ios v0.1:iOS 运行时检测 | 10K stars、ARR $1M |

## Year 3 (2028):双端企业化

| 季度 | 产品里程碑 | 社区/商业目标 |
|------|----------|-------------|
| Q9 (M25–M27) | leona-sdk-ios v0.2:iOS 蜜罐 + 指纹 | ARR $2M、团队 4–5 人 |
| Q10 (M28–M30) | Enterprise 功能:SSO、SOC 2、多租户、私有部署 | 首个 Enterprise $50K/年 |
| Q11 (M31–M33) | 开发者生态:规则市场、插件、第三方集成 | ARR $3.5M、50+ 活跃贡献者 |
| Q12 (M34–M36) | 威胁情报订阅 | ARR $5M+、团队 8–12 人 |

---

# Part 2:核心技术成果

Year 1 三大武器:
1. **汇编特征级 Hook 检测引擎** — 护城河 9/10
2. **Rules-as-Code YAML DSL 框架** — 护城河 6/10
3. **欺骗性防御原语库**(蜜罐数据 + 动态策略) — 护城河 9/10

Year 2 两大武器:
4. **持久化设备指纹 ML 模型**(对标 FingerprintJS Pro $1B) — 护城河 10/10
5. **跨平台 C++ 检测核心**(Android/iOS 共用) — 护城河 7/10

Year 3 三大武器:
6. **自适应策略引擎**(ML + 实时下发)
7. **全球移动威胁情报库**
8. **开发者生态 Platform**(规则市场 + 插件 + 集成)

---

# Part 3:开源 vs 付费矩阵

战略原则：**Open Shell + Private Core + Cloud**。

## 对外开源

| 产品 | 理由 |
|------|------|
| leona-scanner-android | 获取用户入口 |
| leona-scanner-ios | 获取用户入口 |
| leona-sdk-android (public API / sample / docs) | 作为接入入口与开发者信任面 |
| leona-sdk-ios (public API / docs) | 同上 |
| leona-rules (builtin) | 社区贡献、长尾覆盖 |
| leona-honeypot (framework) | 开源理念证明 |
| leona-docs | SEO + 建立权威 |

## 私有 / 付费产品

| 产品 | 定价 | 核心价值 |
|------|------|--------|
| Leona Android Private Core | 私有报价 | 核心检测 runtime、对抗逻辑、敏感 signatures |
| Leona API Backend | 私有报价 | BoxId API 后台、私有部署配置、内部能力 |
| Leona Cloud Scanner | $49–499/月 | 云扫描、CI/CD、协作 |
| Leona Dashboard | $99–999/月 | 事件流、团队、告警 |
| Leona Rules Pro | $199/月 起 | 高级规则周更 |
| Leona Fingerprint | $499–4999/月 | 设备指纹 API |
| Leona Adaptive Defense | $999–9999/月 | 策略引擎、蜜罐编排 |
| Leona Threat Intel | $2K–20K/年 | 威胁订阅 |
| Leona Enterprise | $50K+/年 | 私有部署、SLA、SOC 2 |

## 绝不开源的三条红线

1. Android 核心检测 runtime / 敏感 signatures
2. API 后台与 Server 智能逻辑(策略引擎、ML 模型)
3. Enterprise 特性(SSO、审计、多租户)

---

# Part 4:GitHub 运营手册(🔴 重点 🔴)

## 核心心法

> GitHub 不是代码仓库,是你最重要的"产品"。
> 90% 独立开源项目死于"代码好但没人发现"。

## 4 个核心指标

| 指标 | Year 1 目标 |
|------|----------|
| ⭐ Stars | 5000 |
| 👥 External Contributors | 20+ |
| 📥 Binary Downloads | 10K+ |
| 📧 Newsletter 订阅 | 1000 |

## Phase 0:发布前清单

### 仓库配置
- 仓库名:`leona`
- 组织名:`leonasec`
- Topic 标签:`android, mobile-security, security-tools, appsec, reverse-engineering, frida, anti-tampering, security-scanner, sast, devsecops, opensource, golang`
- 网站:`https://leonasec.io`
- 开启 GitHub Sponsors
- 自定义 social preview image(1280×640)

### 必须有的文件
- README.md(核心,花 20+ 小时打磨)
- LICENSE(已有)
- CHANGELOG.md(已有)
- CONTRIBUTING.md
- CODE_OF_CONDUCT.md
- SECURITY.md
- .github/ISSUE_TEMPLATE/*
- .github/PULL_REQUEST_TEMPLATE.md
- .github/FUNDING.yml
- .github/workflows/ci.yml
- .github/workflows/release.yml

### README 结构(严格按顺序)
1. Logo / Banner
2. Tagline
3. 徽章条
4. Demo GIF(最重要)
5. 问题陈述
6. 核心功能
7. Quick Start
8. 竞品对比表
9. Roadmap
10. 贡献指南入口
11. License + 创始人寄语

## Phase 1:首发周计划

### D-Day 前一周
- 周一:README 终稿、release 准备、Homebrew formula
- 周二:HN 标题打磨
- 周三:朋友圈真实背书(不刷星)
- 周四:Reddit 分平台文案准备
- 周五:Twitter 长推草稿

### D-Day(周二 PT 7–9 AM)
- 07:00:Show HN
- 07:15:Twitter 首发长推
- 07:30:Reddit(分区分帖)
- 08:00:邀请朋友去 HN **评论**
- 全天:逐条回复

### Show HN 标题公式
- `Show HN: <名> – <价值 ≤ 10 字>`
- `Show HN: I built <具体事> because <个人动机>`

## Phase 2:运营周节奏

| 周几 | 固定动作 |
|------|---------|
| 周一 | 合并 PR、回 issue、发周报 |
| 周二 | 发布小版本(有内容才发) |
| 周三 | 写 1 篇技术博客(多平台分发) |
| 周四 | Twitter 技术分享 |
| 周五 | This Week in Leona Newsletter |
| 周六 | Discord / 社区互动 |
| 周日 | 休息 / 月度深度写作 |

## Phase 3:10 个获客策略

1. 每个功能 → 1 篇技术博客(多平台)
2. Awesome List 埋点(主导 + 投稿)
3. Release Notes 写成博客
4. README 关键词 SEO
5. 攻防故事(HN/Reddit 软广)
6. DM 30 个安全大 V 求 feedback
7. 上 3 档 Podcast
8. Show HN 每 3–6 月一次
9. DEF CON / Black Hat Demo Lab
10. 发 CVE / 漏洞研究

## 反模式(必须避开)

- ❌ 买 stars
- ❌ 一稿多投所有平台
- ❌ Issue 回复慢 > 48h
- ❌ README 空话多
- ❌ 跳版本号
- ❌ 早期关闭 issue
- ❌ 开源仓库贴"这个付费"
- ❌ 早期要 CLA
- ❌ 用 GPL

## 本周 10 个动作

1. 买域名:`leonasec.io` / `leona.dev` / `leona.security`
2. 注册 GitHub 组织 `leonasec`
3. 注册 Twitter/X `@leonasec`
4. 注册 Discord 服务器
5. 设计 Logo(Midjourney + Fiverr $50)
6. Stripe Atlas 开 Delaware C-Corp
7. 起 LemonSqueezy 账户
8. 建个人 blog 站(Astro + Tailwind)
9. 注册 Dev.to / Medium / Hashnode
10. README 终稿打磨
