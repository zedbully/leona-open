# Leona 本地数据 / 线上数据同步执行包

> 更新时间：2026-04-27
> 目的：把线上环境的数据拉到本地 Leona docker-compose 栈，默认只做 dry-run。

---

## 1. 范围

当前执行包只覆盖 Leona 本地栈里的两个核心数据面：

- PostgreSQL
- Redis

本地默认目标：

- Postgres：`leona-postgres` / `127.0.0.1:5432` / db `leona`
- Redis：`leona-redis` / `127.0.0.1:6379`

执行脚本：

- `/Users/a/back/Game/cq/scripts/sync-online-data-to-local.sh`
- `/Users/a/back/Game/cq/scripts/sync-online-data-preflight.sh`

参数模板：

- `/Users/a/back/Game/cq/docs/examples/online-sync.env.example`
- `/Users/a/back/Game/cq/.env.local-sync.example`

本地私有入口：

- `/Users/a/back/Game/cq/.env.local-sync`（已加入 `.gitignore`）
- `/Users/a/back/Game/cq/scripts/run-online-sync.sh`

---

## 2. 安全默认值

脚本默认：

- `DRY_RUN=1`
- **只打印将要执行的动作**
- **不会改写本地数据**

要真正执行，必须显式传：

```bash
DRY_RUN=0
```

---

## 3. 同步方向

当前脚本固定为：

> **remote / online -> local**

也就是：

- 先备份本地
- 再拉线上 dump
- 最后覆盖本地

不支持本地直接推线上。

---

## 4. 需要提供的线上连接参数

### 4.1 PostgreSQL

```bash
REMOTE_PGHOST=<host>
REMOTE_PGPORT=5432
REMOTE_PGDATABASE=<database>
REMOTE_PGUSER=<user>
REMOTE_PGPASSWORD=<password>
```

### 4.2 Redis

```bash
REMOTE_REDIS_HOST=<host>
REMOTE_REDIS_PORT=6379
REMOTE_REDIS_PASSWORD=<password-if-any>
```

---

## 5. 用法

### 5.0 推荐先准备本地私有参数文件

```bash
cp /Users/a/back/Game/cq/.env.local-sync.example \
   /Users/a/back/Game/cq/.env.local-sync
```

然后把线上连接参数填进去。

### 5.1 先做 preflight

```bash
SYNC_MODE=preflight \
/Users/a/back/Game/cq/scripts/run-online-sync.sh
```

它会输出：

- 本地 Postgres/Redis 容器是否在线
- 本地表行数 / Redis keyspace
- 如果你已填远端参数，也会检查远端端口是否可达

### 5.2 只看计划，不执行

最短入口：

```bash
SYNC_MODE=dry-run \
/Users/a/back/Game/cq/scripts/run-online-sync.sh
```

或者显式带环境变量执行：

#### Postgres

```bash
SYNC_COMPONENTS=postgres \
REMOTE_NAME=staging \
REMOTE_PGHOST=<host> \
REMOTE_PGDATABASE=<db> \
REMOTE_PGUSER=<user> \
REMOTE_PGPASSWORD=<password> \
/Users/a/back/Game/cq/scripts/sync-online-data-to-local.sh
```

#### Redis

```bash
SYNC_COMPONENTS=redis \
REMOTE_NAME=staging \
REMOTE_REDIS_HOST=<host> \
REMOTE_REDIS_PASSWORD=<password> \
/Users/a/back/Game/cq/scripts/sync-online-data-to-local.sh
```

#### 两者都看

```bash
SYNC_COMPONENTS=all \
REMOTE_NAME=staging \
REMOTE_PGHOST=<host> \
REMOTE_PGDATABASE=<db> \
REMOTE_PGUSER=<user> \
REMOTE_PGPASSWORD=<password> \
REMOTE_REDIS_HOST=<host> \
REMOTE_REDIS_PASSWORD=<password> \
/Users/a/back/Game/cq/scripts/sync-online-data-to-local.sh
```

### 5.3 真正执行

最短入口：

```bash
SYNC_MODE=apply \
/Users/a/back/Game/cq/scripts/run-online-sync.sh
```

或者显式执行：

```bash
DRY_RUN=0 \
SYNC_COMPONENTS=all \
REMOTE_NAME=staging \
REMOTE_PGHOST=<host> \
REMOTE_PGDATABASE=<db> \
REMOTE_PGUSER=<user> \
REMOTE_PGPASSWORD=<password> \
REMOTE_REDIS_HOST=<host> \
REMOTE_REDIS_PASSWORD=<password> \
/Users/a/back/Game/cq/scripts/sync-online-data-to-local.sh
```

---

## 6. 脚本行为

### PostgreSQL

1. 备份本地到：
   - `local-postgres-before-sync.sql`
2. 从远端导出：
   - `<remote-name>-postgres.sql`
3. 导入到本地 `leona` 数据库

### Redis

1. 备份本地到：
   - `local-redis-before-sync.rdb`
2. 从远端导出：
   - `<remote-name>-redis.rdb`
3. 停掉本地 `leona-redis`
4. 把远端 RDB 覆盖到容器 `/data/dump.rdb`
5. 重启本地 `leona-redis`

---

## 7. 产物

默认产物目录：

```bash
/tmp/leona-online-sync-<timestamp>
```

其中会保存：

- 本地 Postgres 备份
- 远端 Postgres dump
- 本地 Redis 备份
- 远端 Redis dump

---

## 8. 当前限制

- 目前没有在当前环境中发现已配置好的线上连接参数
- 当前仓库里也没有现成的线上同步脚本
- 所以本次补的是**执行包**，不是直接连线上落库

---

## 9. 推荐执行顺序

1. 复制 `.env.local-sync.example` 到 `.env.local-sync`
2. 先跑一次 `SYNC_MODE=preflight`
3. 再跑一次 `SYNC_MODE=dry-run`
4. 检查 host / db / user 是否都指向正确环境
5. 确认本地容器都在跑
6. 最后执行 `SYNC_MODE=apply`
