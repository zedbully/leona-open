# Leona 观测 / Dashboard / 告警留档（2026-04-23）

> 日期：2026-04-23
> 环境：`/Users/a/back/Game/cq`
> 目的：留档一次 Prometheus 规则、Grafana provisioning 与最小观测面板的真实校验结果

---

## 1. 本次新增资产

### Prometheus

- 规则文件：
  - `/Users/a/back/Game/cq/leona-server/deploy/docker-compose/prometheus-alerts.yml`
- 配置文件：
  - `/Users/a/back/Game/cq/leona-server/deploy/docker-compose/prometheus.yml`

### Grafana

- datasource provisioning：
  - `/Users/a/back/Game/cq/leona-server/deploy/docker-compose/grafana/provisioning/datasources/datasources.yml`
- dashboard provisioning：
  - `/Users/a/back/Game/cq/leona-server/deploy/docker-compose/grafana/provisioning/dashboards/dashboards.yml`
- dashboard JSON：
  - `/Users/a/back/Game/cq/leona-server/deploy/docker-compose/grafana/dashboards/leona-overview.json`

---

## 2. 本次最小收口内容

### Prometheus 告警规则

已加入：

- `LeonaServiceDown`
- `LeonaWorkerDlqPublished`
- `LeonaIngestion5xx`
- `LeonaQuery5xx`

### Grafana 面板

已 provision：

- Folder：`Leona`
- Dashboard：`Leona Overview`

面板包含：

- Targets Up
- Handshake Success (15m)
- Sense Success (15m)
- DLQ Published (15m)
- Risk Level Distribution
- HTTP Request Rate (non-actuator)
- JVM Heap Used
- System CPU Usage

---

## 3. 真实验证结果

### 3.1 Prometheus 规则已加载

验证方式：

```bash
curl http://localhost:9090/api/v1/rules
```

结果：

- 返回 `leona-platform` rule group
- 4 条 alert rules 均为 `health=ok`

### 3.2 Grafana provisioning 已生效

验证方式（容器内）：

```bash
docker exec leona-grafana /bin/sh -lc \
  "wget -qO- --header 'Authorization: Basic YWRtaW46YWRtaW4=' \
  http://127.0.0.1:3000/api/search?query=Leona"
```

结果：

- 可查询到 folder `Leona`
- 可查询到 dashboard `Leona Overview`
- `uid=leona-overview`

### 3.3 Grafana 健康检查正常

验证方式（容器内）：

```bash
docker exec leona-grafana /bin/sh -lc \
  "wget -qO- http://127.0.0.1:3000/api/health"
```

结果：

- `database=ok`
- `version=11.3.0`

---

## 4. 当前环境备注

在本次 Codex 桌面环境中，宿主机 `localhost:3000` 返回的是另一套本地前端页面，因此本次 Grafana 校验采用了 **容器内 API** 的方式完成。

这不影响以下事实：

- docker-compose 中的 Grafana 容器已正常启动
- datasource provisioning 已插入
- dashboard provisioning 已完成
- Grafana 内部健康检查正常

---

## 5. 结论

结论：

> **Leona 当前已具备最小可用的 observability 收口：Prometheus 抓取、核心业务 metrics、Prometheus alert rules、Grafana datasource provisioning 与 Leona Overview dashboard 均已落地并完成真实校验。**

当前观测侧剩余增强项主要是：

- 更细粒度的 tenant / appKey 标签策略
- Redis / Kafka / Postgres 依赖面板
- 更完整的 SLO / 告警分级
