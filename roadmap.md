# Leona 移动端安全产品 - 当前执行路线图

> 创建日期: 2026-04-19
> 最近更新: 2026-04-21
> 当前执行范围: Android 优先，先完成 SDK ↔ Server alpha 闭环

---

## 0. 战略定位

**产品**:移动端应用安全产品，当前阶段只聚焦 **Android runtime security + server-side verdict pipeline**。

中期扩展顺序：

1. Android
2. iOS
3. 其他方向按商业反馈再评估

**目标客户**:
- 海外独立开发者
- 中型应用/游戏团队
- 需要低接入成本风控能力的移动产品团队

**差异化**:
- 运行时检测走 native-first，不给客户端布置最终决策点
- verdict 在服务端，客户端只拿 BoxId
- 接入路径尽可能短，先让首个客户能在 1~2 周内接入
- 开源建立信任，SaaS 提供服务端价值

---

## 1. 当前已落地的真实能力

### Android SDK
- `Leona.init()` / `sense()` / `senseAsync()`
- BoxId API
- Kotlin + JNI + C++ 主链路
- Frida / ptrace / trampoline 特征检测
- Emulator / Root / Xposed / Unidbg 检测
- Honeypot 原语
- sample app

### Server
- `gateway`
- `ingestion-service`
- `query-service`
- `admin-service`
- `worker-event-persister`
- `/v1/handshake` / `/v1/sense` / `/v1/verdict`
- HMAC / nonce replay / timestamp / AES-GCM / TLV payload 解析
- Redis / Kafka / Postgres 本地开发栈

### CLI
- 命令骨架已存在
- 扫描引擎尚未落地

---

## 2. 当前最重要的阶段目标

> **先完成 Android SDK ↔ Server 的真实 alpha 闭环。**

具体是：

1. 修正文档与代码漂移
2. 跑通 handshake → sense → verdict
3. 让 sample app 默认可用于真实 server 演示
4. 增加最小 demo backend
5. 补 E2E 测试
6. 形成可内测 alpha 包

---

## 3. 近期 Phase 路线

### Phase 0
- 文档和代码状态对齐
- 输出统一 current status 文档

### Phase 1
- 修通 Android SDK ↔ Server 真闭环
- 完成 handshake / sense / verdict 联调

### Phase 2
- 做 sample app + demo backend 演示链路

### Phase 3
- 完善 Server MVP
  - BoxId 生命周期
  - key rotate / revoke
  - worker 可靠性
  - metrics / logging

### Phase 4
- 补测试
  - SDK unit
  - server integration
  - E2E

### Phase 5
- 发布 Android alpha
  - AAR
  - 文档
  - changelog
  - 演示流程
  - 发布准备清单与留档模板

---

## 4. 暂不抢主线的内容

- iOS SDK
- Dashboard / Web Console
- 设备指纹
- 自适应策略引擎
- Enterprise 能力
- CLI scanner 完整实现

---

## 5. 当前验收里程碑

### M1：真实闭环跑通
- Android sample app 能调用真实 server
- `sense()` 返回真实 BoxId
- backend 可查询 verdict

### M2：可演示
- sample app 展示 BoxId / verdict / 风险结果
- demo backend 可演示 allow / deny / honeypot

### M3：可内测
- SDK API 稳定
- AAR 可构建
- 文档可用
- E2E 基本通过

## 6. 当前 Phase 5 准备状态

已补：

- SDK changelog
- alpha 发布准备文档
- 联调 / 演示留档模板
- alpha release notes 模板

当前 blocker：

- `leona-server` Java / Gradle 环境尚未恢复
- 真实联调证据仍未留档

恢复与收口文档：

- `docs/gradle-recovery.md`
- `docs/final-acceptance-summary.md`
