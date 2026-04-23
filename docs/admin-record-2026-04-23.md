# Leona Admin API 真联调留档（2026-04-23）

> 日期：2026-04-23
> 环境：`/Users/a/back/Game/cq`
> 目的：留档一次真实的 admin-service create / create-key / rotate / revoke 联调结果

---

## 1. 运行环境

- admin-service：`http://localhost:8083`
- Redis：Docker 容器 `leona-redis`
- 执行前提：本地 docker-compose 五服务栈已启动且健康检查通过

---

## 2. 本次真实执行

### 2.1 创建 tenant

执行：

```bash
curl -X POST http://localhost:8083/v1/admin/tenants \
  -H 'Content-Type: application/json' \
  -d '{"name":"Admin Acceptance 2026-04-23 B"}'
```

结果：

- `tenantId`: `de4ca831-539b-4ade-a48f-81abd38702b8`
- 初始 `appKey`: `lk_live_app_AkqjRe3ohxBhpuBm5Khy5mWs`
- 初始 `secretKey`: `lk_live_sec_ZHn6orHvDP1307SwHEkf2VHSx6s60UpKNsDXb7rm`

### 2.2 创建新 key

执行：

```bash
curl -X POST \
  http://localhost:8083/v1/admin/tenants/de4ca831-539b-4ade-a48f-81abd38702b8/keys
```

结果：

- 新 `appKey`: `lk_live_app_r4uFESlJ7pOZn6OdxayFhBTH`
- 新 `secretKey`: `lk_live_sec_MC6ql656WRcJnZsnMEwQhJOPZWb80irPxdct2AXP`

### 2.3 rotate key

执行：

```bash
curl -X POST \
  http://localhost:8083/v1/admin/tenants/de4ca831-539b-4ade-a48f-81abd38702b8/keys/lk_live_app_r4uFESlJ7pOZn6OdxayFhBTH/rotate
```

结果：

- `oldAppKey`: `lk_live_app_r4uFESlJ7pOZn6OdxayFhBTH`
- `oldKeyRevokedAt`: `2026-04-22T18:07:27.964225596Z`
- replacement `appKey`: `lk_live_app_aCMNXg4OSLcKN73HpfUQMUEh`
- replacement `secretKey`: `lk_live_sec_MW5BUWQs8eAcdSU8meCS3csKWQvcCjEPx826XbYq`

### 2.4 revoke 初始 key

执行：

```bash
curl -X DELETE \
  http://localhost:8083/v1/admin/tenants/de4ca831-539b-4ade-a48f-81abd38702b8/keys/lk_live_app_AkqjRe3ohxBhpuBm5Khy5mWs
```

结果：

- `appKey`: `lk_live_app_AkqjRe3ohxBhpuBm5Khy5mWs`
- `revokedAt`: `2026-04-22T18:07:28.019590846Z`
- `alreadyRevoked`: `false`

---

## 3. Redis 注册表真实验证

验证结果：

- 被 revoke 的初始 `appKey` Redis 映射已删除
- 被 rotate 的旧 `appKey` Redis 映射已删除
- replacement `appKey` Redis 映射存在
- 被 revoke / rotate 的旧 `secret` 哈希 Redis 映射已删除
- replacement `secret` 哈希 Redis 映射存在

示例：

```bash
docker exec leona-redis redis-cli HGETALL \
  leona:appkey:lk_live_app_aCMNXg4OSLcKN73HpfUQMUEh
```

返回：

- `tenant=de4ca831-539b-4ade-a48f-81abd38702b8`
- `session_key_b64=55tYASeRvfNfl7YL2X289Y7tss9s3JLS7Lfall5HAC8=`

以及：

```bash
docker exec leona-redis redis-cli HGETALL \
  leona:secret:rDqUgiRLnlfyI2TYecJwARVAL3JNaSQC5qxBNbA9v0Q
```

返回：

- `tenant=de4ca831-539b-4ade-a48f-81abd38702b8`
- `app_key=lk_live_app_aCMNXg4OSLcKN73HpfUQMUEh`

---

## 4. 本次留档文件

- `/tmp/admin-acceptance-20260423/create.json`
- `/tmp/admin-acceptance-20260423/create-key.json`
- `/tmp/admin-acceptance-20260423/rotate.json`
- `/tmp/admin-acceptance-20260423/revoke.json`

---

## 5. 结论

结论：

> **admin-service 的 tenant create / key create / rotate / revoke 已在本地真实服务栈中完成联调留档，并验证了 Redis key registry 的实际增删效果。**

当前 Phase 3 剩余重点已收敛为：

- 真机留档（增强项）
- 更细粒度 observability / SLO 增强项
