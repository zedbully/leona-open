# Leona Android Alpha Release Notes

> 版本：`0.1.0-alpha.1`
> 发布日期：2026-04-23
> 适用范围：`/Users/a/back/Game/cq`

---

## 1. 本次发布是什么

本次发布是 **Leona Android runtime security alpha** 的首个可内测工程版本。

当前已经具备：

- Android SDK 基础接入能力
- BoxId 上报与服务端 verdict 查询链路
- sample app 演示闭环
- demo backend 参考实现
- 本地模拟器 E2E 自动化脚本

本次 alpha 面向：

- 小范围内部联调
- 首批接入方 PoC / 技术验证
- Android 风险感知与服务端判定链路验证

---

## 2. 本次可用能力

### Android SDK

- `Leona.init()`
- `Leona.sense()`
- `Leona.senseAsync()`
- `BoxId`
- `LeonaConfig`
- `Honeypot`
- `quickCheck()`

### 当前检测覆盖

- Frida / trampoline / ptrace 特征
- emulator 特征
- root / Magisk / KernelSU / Riru
- Xposed / LSPosed / EdXposed
- Unidbg 特征

### 服务端链路

- `/v1/handshake`
- `/v1/sense`
- `/v1/verdict`
- BoxId single-use / expired 语义
- Redis 热路径 verdict 快照
- Kafka → worker 风险评分
- verdict 响应签名

### 演示与联调

- sample app 可展示 `BoxId / decision / risk / score`
- demo backend 可代表业务后端调用 `/v1/verdict`
- 本地 Docker Compose 五服务栈可运行
- 已具备一键联调脚本与一键模拟器 E2E 自动化脚本

---

## 3. 本次已验证结果

### 本地真实联调

已在 Android 模拟器上真实跑通：

`sample app -> handshake -> sense -> Redis/Kafka/worker -> demo backend -> verdict`

已验证结果包括：

- `sense()` 成功返回真实 `BoxId`
- sample app 成功展示最终 `decision / risk / score`
- BoxId single-use 语义真实生效
- Redis 中存在完整 verdict snapshot
- worker 持久化日志可见

### 本地自动化 E2E

脚本：

- `/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-e2e.sh`

2026-04-23 最近一次执行结果：

- `BoxId=01KPV5E417A7467GRBRMQXYF30`
- `decision=deny`
- `risk=CRITICAL`
- `score=100`
- 产物目录：`/tmp/leona-e2e-20260423-015719`

---

## 4. 推荐接入方式

推荐链路：

1. App 初始化 Leona SDK
2. 需要风险判断时调用 `Leona.sense()`
3. App 仅拿到 `BoxId`
4. App 将 `BoxId` 上传到自己的业务后端
5. 业务后端调用 Leona `/v1/verdict`
6. 按 `riskLevel / riskScore / decision` 做 allow / challenge / deny / honeypot

不建议：

- 在客户端本地直接做最终风控决策
- 重复消费同一个 `BoxId`
- 在未做误报评估前直接面向大规模正式用户开启强拦截

---

## 5. 当前不包含 / 已知限制

- 本次仅覆盖 Android；iOS 不在本次范围
- sample app 默认仍偏本地 stub 演示模式，真实联调需注入 Gradle 参数
- API / SDK 仍处于 alpha，后续版本可能继续调整
- Dashboard / Console 不是当前正式交付物
- CLI 扫描器不是本次主线交付
- 真机留档仍未补齐
- 自动化 E2E 已具备本地脚本，且已补 GitHub manual workflow scaffold；但仍待真实仓库 secrets / variables 配置与首次 CI 跑验

---

## 6. 本次建议阅读材料

- `/Users/a/back/Game/cq/leona-sdk-android/CHANGELOG.md`
- `/Users/a/back/Game/cq/docs/demo-flow.md`
- `/Users/a/back/Game/cq/docs/demo-record-2026-04-23.md`
- `/Users/a/back/Game/cq/docs/local-runbook.md`
- `/Users/a/back/Game/cq/docs/api-acceptance.md`
- `/Users/a/back/Game/cq/docs/observability.md`

---

## 7. 反馈与问题上报

如果反馈 false positive / false negative / 联调失败，请至少附带：

- 设备型号 / Android 版本 / ABI
- 是否模拟器、真机、root、Magisk、Frida、Xposed
- SDK 版本与 app 包版本
- 关键日志、截图、BoxId
- 若涉及 verdict，请附带后端请求时间与 requestId

---

## 8. 当前对外口径

> Leona is an Android runtime security alpha with a server-side BoxId verdict pipeline. The SDK, sample app, demo backend, and local emulator E2E automation are already available for internal alpha validation.
