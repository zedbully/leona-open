# Local development stack

```bash
cd deploy/docker-compose
docker compose up -d --build
```

### Endpoints

| URL | Service |
|---|---|
| http://localhost:8080/v1/health | Gateway |
| http://localhost:8081/actuator/health | ingestion-service |
| http://localhost:8082/actuator/health | query-service |
| http://localhost:8083/actuator/health | admin-service |
| http://localhost:8084/actuator/health | worker-event-persister |
| http://localhost:9000 | Kafdrop (Kafka UI) |
| http://localhost:9090 | Prometheus |
| http://localhost:3000 | Grafana (admin / admin) |

### Observability assets

- Prometheus config: `/Users/a/back/Game/cq/leona-server/deploy/docker-compose/prometheus.yml`
- Prometheus alert rules: `/Users/a/back/Game/cq/leona-server/deploy/docker-compose/prometheus-alerts.yml`
- Grafana dashboard: `/Users/a/back/Game/cq/leona-server/deploy/docker-compose/grafana/dashboards/leona-overview.json`

### Quick checks

```bash
curl http://localhost:9090/api/v1/rules

docker exec leona-grafana /bin/sh -lc \
  "wget -qO- --header 'Authorization: Basic YWRtaW46YWRtaW4=' \
  http://127.0.0.1:3000/api/search?query=Leona"
```

### Smoke test

```bash
# Handshake: get a session id and server public key
curl -X POST http://localhost:8080/v1/handshake \
  -H "Content-Type: application/json" \
  -H "X-Leona-App-Key: lk_dev_sample" \
  -d '{
    "clientPublicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "installId": "dev-install-1",
    "sdkVersion": "0.1.0-alpha.1"
  }'
```

See the parent [README.md](../../README.md) for full API docs.

备注：

- 当前 compose 已为 5 个应用服务加上更保守的本地 JVM 参数，避免 query-service 在本地整栈运行时被 OOM kill。
- `worker-event-persister` 的 8084 端口现在已暴露到宿主机，可直接做 `actuator` / `prometheus` 检查。
