# Leona Android Alpha Release Notes 模板

> 发布版本：
> 发布日期：

---

## 1. 本次发布是什么

一句话说明本次 alpha：

> Leona 提供 Android runtime security SDK，以及基于 BoxId 的服务端 verdict 查询链路。

---

## 2. 本次可以使用的能力

- Android SDK 初始化与 `sense()` / `senseAsync()`
- 运行时检测：Frida / emulator / root / Xposed / Unidbg
- BoxId 上传与服务端 verdict 查询
- sample app 演示链路
- demo backend 接入参考

---

## 3. 本次不包含 / 已知限制

- iOS 不在本次范围
- Dashboard 仍不是正式交付物
- CLI 扫描器不是当前主线
- API / SDK 仍可能在 alpha 阶段发生调整
- 当前已具备本地模拟器 E2E 自动化脚本，但尚未收口到 CI 与更多设备场景

---

## 4. 接入建议

- App 只拿 BoxId，不做本地最终决策
- 业务后端使用 BoxId 调用 Leona `/v1/verdict`
- 根据 `riskLevel` / `riskScore` 决定 allow / challenge / deny / honeypot

---

## 5. 推荐阅读

- SDK README
- SDK CHANGELOG
- demo-flow
- api-acceptance
- observability

---

## 6. 升级 / 反馈

- 反馈 false positive / false negative 时，附带设备信息、工具版本、日志与截图
- alpha 阶段优先修复真实闭环问题与高优先级误报
