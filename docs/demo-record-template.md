# Leona 联调 / 演示留档模板

> 使用方式：每完成一次真实本地联调，就复制本模板保存一份记录。

---

## 1. 基本信息

- 日期：
- 执行人：
- 环境：本地 / 模拟器 / 真机
- 设备型号：
- Android 版本：
- Leona SDK 版本：
- Server 提交/快照说明：
- Demo backend 提交/快照说明：

---

## 2. 联调配置

- `LEONA_API_KEY`：
- `LEONA_REPORTING_ENDPOINT`：
- `LEONA_DEMO_BACKEND_BASE_URL`：
- `LEONA_SECRET_KEY` 使用来源：
- tenantId：

---

## 3. 启动结果

### server

- docker compose 是否成功启动：是 / 否
- 健康检查结果：
- 关键日志：

### demo backend

- `/health` 是否正常：是 / 否
- 关键日志：

### sample app

- 是否成功安装：是 / 否
- 是否成功启动：是 / 否
- server mode 页面是否正确显示：是 / 否

---

## 4. 真闭环结果

### Step 1: Run sense()

- 是否成功返回 BoxId：是 / 否
- BoxId：
- 页面截图路径：
- 关键日志：

### Step 2: Query demo verdict

- 是否成功查询 verdict：是 / 否
- response decision：
- response riskLevel：
- response riskScore：
- 页面截图路径：
- demo backend 日志：
- query-service 日志：

### Step 3: 单次消费验证

- 同一个 BoxId 二次查询结果：
- 是否符合 single-use 预期：是 / 否

---

## 5. 观测结果

- `leona_handshake_success_total` 是否增长：是 / 否
- `leona_sense_success_total` 是否增长：是 / 否
- `leona_verdict_success_total` 是否增长：是 / 否
- risk level 指标是否增长：是 / 否
- Prometheus / Grafana 截图路径：

---

## 6. 问题记录

- 发现的问题：
- 是否阻塞 alpha：是 / 否
- 临时绕过方案：
- 后续修复建议：

---

## 7. 最终结论

- 本次联调是否通过：通过 / 部分通过 / 未通过
- 是否可作为 alpha 留档证据：是 / 否
- 下一步行动：
