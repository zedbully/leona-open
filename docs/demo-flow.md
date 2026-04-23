# Leona 本地演示流程

> 目标：跑通 Android SDK → Leona Server → Demo Backend 的最小演示链路

---

## 1. 启动 Leona Server

```bash
cd /Users/a/back/Game/cq/leona-server/deploy/docker-compose
docker compose up -d
```

确保服务启动后，查看：

```bash
curl http://localhost:8080/actuator/health
```

---

## 2. 获取本地开发 tenant 凭据

`admin-service` 的 `local` profile 会在首次启动时打印：

- `tenantId`
- `appKey`
- `secretKey`

把它们记录下来。

如果需要补发新凭据，使用 admin 接口：

- `POST /v1/admin/tenants/{tenantId}/keys`
- `DELETE /v1/admin/tenants/{tenantId}/keys/{appKey}`
- `POST /v1/admin/tenants/{tenantId}/keys/{appKey}/rotate`

> rotate 语义：创建 replacement key pair，并在同一 admin 操作中 revoke 旧 key。

---

## 3. 启动 demo backend

```bash
cd /Users/a/back/Game/cq/demo-backend
LEONA_BASE_URL=http://localhost:8080 \
LEONA_SECRET_KEY=<secretKey> \
go run .
```

检查：

```bash
curl http://localhost:8090/health
```

---

## 4. 配置 sample app

sample app 会从 Gradle 属性读取以下配置：

- `LEONA_API_KEY`
- `LEONA_REPORTING_ENDPOINT`
- `LEONA_DEMO_BACKEND_BASE_URL`

示例：

```bash
cd /Users/a/back/Game/cq/leona-sdk-android
./gradlew :sample-app:installDebug \
  -PLEONA_API_KEY=<appKey> \
  -PLEONA_REPORTING_ENDPOINT=http://10.0.2.2:8080 \
  -PLEONA_DEMO_BACKEND_BASE_URL=http://10.0.2.2:8090
```

> 如果是真机，不要用 `10.0.2.2`，改成你电脑在局域网中的 IP。

---

## 5. 启动 sample app

构建并安装后打开 app。

打开 app 后：

1. 点击 `Run sense()`
2. 查看是否拿到 BoxId
3. 点击 `Query demo verdict`
4. 查看 decision / risk / score

> 注意：当前 BoxId 设计为 **single-use**。一次成功查询后，不要重复用同一个 BoxId 再查 verdict。

---

## 6. 验收标准

最小演示成功标准：

- sample app 可以拿到 **真实 BoxId**
- demo backend 可以查询 `/v1/verdict`
- query-service 返回 verdict 响应签名头
- demo backend 能完成签名校验
- sample app 能展示：
  - `decision`
  - `riskLevel`
  - `riskScore`

---

## 7. 当前留档状态

当前仓库内已经完成：

- sample app 的真实 server 参数注入
- demo backend 最小代理逻辑
- verdict 响应签名与 demo backend 校验
- Phase 1/2/3 所需主要文档与清单
- 一次真实模拟器演示截图与联调留档
- Android ↔ Server 模拟器 E2E 自动化脚本与真实执行结果

当前仍**没有**留档完成的内容：

- 真机演示截图 / 留档
- GitHub live emulator E2E 首次跑验

---

## 8. 当前已知限制 / blocker

- `leona-server` 的 Java / Gradle 构建已恢复，可通过 `/Users/a/back/Game/cq/leona-server/scripts/gradlew-java21.sh` 执行
- 当前更真实的剩余项已变成：真机留档，以及 GitHub live emulator E2E 的首次跑验
- 因此当前主线已不再是“能否跑通”，而是“如何补强发布前证据链与工程化能力”
