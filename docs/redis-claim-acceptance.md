# Redis BoxId Claim 验收设计

> 更新时间: 2026-04-21
> 目标：为 `RedisBoxIdClaim` 的真实 Redis 验收提供可执行设计，补上当前仅有 mock 单测的缺口

---

## 1. 当前状态

当前已经具备：

- `RedisBoxIdClaimTest`
- `VerdictServiceTest`
- `CompositeVerdictRepositoryTest`

这些测试已经覆盖：

- 状态映射
- claim 后服务层错误分支
- Redis miss / throw 时的 repository fallback

当前仍未覆盖：

- **Lua 脚本在真实 Redis 中的原子行为**
- `used_at` 是否真的被写入
- `expires_at_epoch_ms` 的数值比较是否按预期工作

---

## 2. 真实验收应验证的核心场景

### 场景 A：首次 claim 成功

前提：

- Redis 中存在 `leona:box:<boxId>`
- `tenant` 匹配
- `expires_at_epoch_ms` 大于当前时间
- `used_at` 为空

期望：

- 返回 `CLAIMED`
- Redis hash 中新增 `used_at`

### 场景 B：重复 claim

前提：

- 同一个 box 已经成功 claim 过一次

期望：

- 返回 `ALREADY_USED`
- 不覆盖第一次写入的 `used_at`

### 场景 C：tenant 不匹配

前提：

- `tenant` 字段与调用方 tenant 不同

期望：

- 返回 `WRONG_TENANT`
- Redis 中 `used_at` 不应被写入

### 场景 D：box 已过期

前提：

- `expires_at_epoch_ms <= now`

期望：

- 返回 `EXPIRED`
- Redis 中 `used_at` 不应被写入

### 场景 E：box 不存在

前提：

- Redis 中不存在对应 key

期望：

- 返回 `NOT_FOUND`

---

## 3. 推荐的测试脚手架方向

优先推荐：

- 在 `query-service` 增加一个 **真实 Redis 集成测试**
- 使用 Testcontainers 启一个最小 Redis 容器
- 对 `StringRedisTemplate` 注入真实连接
- 直接调用 `RedisBoxIdClaim.claim()`

建议测试名：

- `RedisBoxIdClaimIntegrationTest`

建议位置：

- `/Users/a/back/Game/cq/leona-server/query-service/src/test/java/io/leonasec/server/query/infra/RedisBoxIdClaimIntegrationTest.java`

---

## 4. 依赖建议

当前 `query-service` 已有：

- `testcontainers-junit-jupiter`
- `testcontainers-postgresql`

如需跑 Redis container，建议后续补一个通用 Testcontainers 依赖，或直接引入 Redis 对应容器方案。

如果暂时不改依赖，也可以先采用：

- 本地 `docker compose` 中已有 Redis
- 手动 smoke test

但这种方式不适合作为 CI 验收。

---

## 5. 手动 smoke test 方案

当本地 docker compose 已启动：

```bash
redis-cli HSET leona:box:01TESTBOXID00000000000000 \
  tenant 11111111-1111-1111-1111-111111111111 \
  expires_at_epoch_ms 4102444800000
```

然后调用 query-service 对应逻辑，或在测试中直接执行 `claim()`。

验收重点：

- 首次 claim 后 `used_at` 出现
- 第二次 claim 返回 already used
- 修改 `expires_at_epoch_ms` 到过去后返回 expired

---

## 6. 当前结论

当前可以认为：

> `RedisBoxIdClaim` 的 **Java 分支逻辑与状态映射已覆盖**，但 **真实 Redis 原子语义** 仍需单独验收。
