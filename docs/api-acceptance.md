# Leona API 最小验收说明

> 更新时间: 2026-04-23
> 目标：为当前 alpha 阶段的 admin / query API 提供最小可执行验收口径

---

## 1. 验收范围

当前文档只覆盖：

- admin-service
  - `POST /v1/admin/tenants`
  - `POST /v1/admin/tenants/{tenantId}/keys`
  - `DELETE /v1/admin/tenants/{tenantId}/keys/{appKey}`
  - `POST /v1/admin/tenants/{tenantId}/keys/{appKey}/rotate`
- query-service
  - `POST /v1/verdict`

不覆盖：

- gateway 全量鉴权细节
- dashboard API
- Android SDK 端到端自动化

---

## 2. admin API 最小验收

### 本地 profile 预期

本地 docker compose / `local` profile 下：

- admin API 允许无 OIDC/JWT 直接调用
- 目的是降低本地联调门槛

这一点已由：

- `/Users/a/back/Game/cq/leona-server/admin-service/src/main/java/io/leonasec/server/admin/config/SecurityConfig.java`
- `/Users/a/back/Game/cq/leona-server/admin-service/src/test/java/io/leonasec/server/admin/api/TenantControllerWebMvcTest.java`

覆盖。

### 手动验收命令

创建 tenant：

```bash
curl -X POST http://localhost:8083/v1/admin/tenants \
  -H 'Content-Type: application/json' \
  -d '{"name":"Demo Tenant"}'
```

预期：

- HTTP `201`
- body 含：
  - `tenantId`
  - `name`
  - `keyPair.appKey`
  - `keyPair.secretKey`

创建新 key：

```bash
curl -X POST http://localhost:8083/v1/admin/tenants/<tenantId>/keys
```

预期：

- HTTP `201`
- body 含 `appKey` / `secretKey`

revoke key：

```bash
curl -X DELETE http://localhost:8083/v1/admin/tenants/<tenantId>/keys/<appKey>
```

预期：

- HTTP `200`
- body 含：
  - `appKey`
  - `revokedAt`
  - `alreadyRevoked`

rotate key：

```bash
curl -X POST http://localhost:8083/v1/admin/tenants/<tenantId>/keys/<appKey>/rotate
```

预期：

- HTTP `200`
- body 含：
  - `oldAppKey`
  - `oldKeyRevokedAt`
  - `replacement.appKey`
  - `replacement.secretKey`

### 真实留档状态

2026-04-23 已完成一轮真实 admin 联调留档：

- `/Users/a/back/Game/cq/docs/admin-record-2026-04-23.md`

已真实验证：

- create tenant
- create key
- rotate key
- revoke key
- Redis key registry 同步增删

---

## 3. query API 最小验收

### 请求契约

`/v1/verdict` 当前 body 约定为：

```json
{"boxId":"01..."}
```

也就是：

- `boxId` 是字符串
- 不是嵌套对象

这一点当前已由：

- `/Users/a/back/Game/cq/leona-server/common/src/main/java/io/leonasec/server/common/api/BoxId.java`
- `/Users/a/back/Game/cq/leona-server/common/src/test/java/io/leonasec/server/common/api/BoxIdJsonTest.java`
- `/Users/a/back/Game/cq/leona-server/query-service/src/test/java/io/leonasec/server/query/api/VerdictControllerWebMvcTest.java`

共同约束。

### 手动验收命令

```bash
curl -X POST http://localhost:8080/v1/verdict \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <secretKey>' \
  -H 'X-Leona-Timestamp: <timestamp>' \
  -H 'X-Leona-Nonce: <nonce>' \
  -H 'X-Leona-Signature: <signature>' \
  -d '{"boxId":"<boxId>"}'
```

预期：

- HTTP `200`
- response headers 包含：
  - `X-Leona-Verdict-Generated-At`
  - `X-Leona-Verdict-Signature`
  - `X-Leona-Verdict-Signature-Alg: HMAC-SHA256`
- response body 包含：
  - `boxId`
  - `risk.level`
  - `risk.score`
  - `observedAt`
  - `usedAt`

### 错误分支验收

当 BoxId：

- 已消费 -> 预期 `410 Gone`
- 已过期 -> 预期 `410 Gone`
- 不存在 -> 预期 `404 Not Found`

这一层目前已由：

- `/Users/a/back/Game/cq/leona-server/query-service/src/test/java/io/leonasec/server/query/domain/VerdictServiceTest.java`
- `/Users/a/back/Game/cq/leona-server/query-service/src/test/java/io/leonasec/server/query/api/VerdictControllerWebMvcTest.java`

部分覆盖。

---

## 4. 当前仍未完成的验收

当前仍缺：

- gateway 层完整签名构造的独立留档
- 更多真实设备 / 更多错误分支覆盖

因此当前结论是：

> **admin / query API 已具备最小真实验收基础：admin create/create-key/rotate/revoke、query verdict 以及 Android sample app → demo backend → verdict 主链路都已有真实留档。剩余主要是扩展场景与更多设备覆盖。**
