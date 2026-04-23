# Leona 观测说明

> 更新时间: 2026-04-23
> 目标：为当前 alpha 阶段提供最小可验收的 metrics / Prometheus / Grafana / alerting 说明

---

## 1. 当前已具备的观测基础设施

本地 docker compose 已包含：

- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3000`
- 各服务 actuator / prometheus 暴露

主要端口：

- gateway: `http://localhost:8080/actuator/prometheus`
- ingestion-service: `http://localhost:8081/actuator/prometheus`
- query-service: `http://localhost:8082/actuator/prometheus`
- admin-service: `http://localhost:8083/actuator/prometheus`
- worker-event-persister: `http://localhost:8084/actuator/prometheus`

Prometheus 抓取配置位置：

- `/Users/a/back/Game/cq/leona-server/deploy/docker-compose/prometheus.yml`
- `/Users/a/back/Game/cq/leona-server/deploy/docker-compose/prometheus-alerts.yml`

Grafana provisioning 位置：

- `/Users/a/back/Game/cq/leona-server/deploy/docker-compose/grafana/provisioning/datasources/datasources.yml`
- `/Users/a/back/Game/cq/leona-server/deploy/docker-compose/grafana/provisioning/dashboards/dashboards.yml`
- `/Users/a/back/Game/cq/leona-server/deploy/docker-compose/grafana/dashboards/leona-overview.json`

---

## 2. 当前已落地的业务指标

### ingestion / handshake

- `leona.handshake.success`
- `leona.sense.success`
- `leona.sense.risk_level{risk=...}`

来源：

- `/Users/a/back/Game/cq/leona-server/ingestion-service/src/main/java/io/leonasec/server/ingestion/domain/SessionService.java`
- `/Users/a/back/Game/cq/leona-server/ingestion-service/src/main/java/io/leonasec/server/ingestion/domain/SenseService.java`

### query / verdict

- `leona.verdict.success`
- `leona.verdict.risk_level{risk=...}`

来源：

- `/Users/a/back/Game/cq/leona-server/query-service/src/main/java/io/leonasec/server/query/api/VerdictController.java`

### worker / DLQ

- `leona.worker.dlq.published`

来源：

- `/Users/a/back/Game/cq/leona-server/worker-event-persister/src/main/java/io/leonasec/server/worker/infra/DlqPublisher.java`

---

## 3. 当前已落地的 dashboard / alerting

### Grafana

已 provision：

- datasource：`Prometheus`
- folder：`Leona`
- dashboard：`Leona Overview`

当前 dashboard 已覆盖：

- Targets Up
- Handshake Success (15m)
- Sense Success (15m)
- DLQ Published (15m)
- Risk Level Distribution
- HTTP Request Rate (non-actuator)
- JVM Heap Used
- System CPU Usage

### Prometheus alert rules

已加入：

- `LeonaServiceDown`
- `LeonaWorkerDlqPublished`
- `LeonaIngestion5xx`
- `LeonaQuery5xx`

---

## 4. 最小验证方式

### 启动本地栈

```bash
cd /Users/a/back/Game/cq/leona-server/deploy/docker-compose
docker compose up -d --build
```

### 查看 Prometheus 暴露

```bash
curl http://localhost:8081/actuator/prometheus | grep leona_
curl http://localhost:8082/actuator/prometheus | grep leona_
curl http://localhost:8084/actuator/prometheus | grep leona_
```

### 做一次最小链路后再检查

当完成一次：

- handshake
- sense
- verdict

之后，至少应能看到：

- handshake / sense / verdict success counter 增长
- 对应 risk level counter 增长

如果人为制造 worker 持久化失败并进入 DLQ，则应看到：

- `leona_worker_dlq_published_total` 增长

> Prometheus 中最终暴露的名字通常会转成下划线风格，例如 `leona.sense.success` 会表现为 `leona_sense_success_total`。

---

### 校验 alert rules

```bash
curl http://localhost:9090/api/v1/rules
```

应看到：

- rule group: `leona-platform`
- 4 条 alert rules

### 校验 Grafana provisioning

如果宿主机 `localhost:3000` 可直接访问 Grafana，可在 UI 中确认：

- folder `Leona`
- dashboard `Leona Overview`

如果当前环境的 `localhost:3000` 被其他本地进程占用，可使用容器内 API 校验：

```bash
docker exec leona-grafana /bin/sh -lc \
  "wget -qO- --header 'Authorization: Basic YWRtaW46YWRtaW4=' \
  http://127.0.0.1:3000/api/search?query=Leona"
```

以及：

```bash
docker exec leona-grafana /bin/sh -lc \
  "wget -qO- http://127.0.0.1:3000/api/health"
```

真实留档：

- `/Users/a/back/Game/cq/docs/observability-record-2026-04-23.md`

---

## 5. 当前观测范围仍然缺少的内容

当前还没有完全收口：

- 关键错误率、延迟分位数、Redis/Kafka/Postgres 依赖面板
- 针对 tenant / appKey 的更细粒度标签策略
- 更完整的 SLO / 告警分级

所以当前结论是：

> **metrics 基础埋点、Prometheus alert rules、Grafana provisioning 与 Leona Overview dashboard 已具备最小可验收状态。**

---

## 6. 现阶段建议的验收口径

Phase 3 / 4 当前要求达到：

1. 本地 Prometheus 能抓到各服务 `/actuator/prometheus`
2. 业务核心 counter 已存在
3. 一次真实联调后可以观察到 counter 增长
4. Prometheus alert rules 已加载
5. Grafana dashboard provisioning 已生效

不要求当前阶段完成：

- 完整 SLO / 告警体系
- 多租户维度报表
- 完整依赖拓扑 / 存储面板
