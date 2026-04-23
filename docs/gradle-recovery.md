# Leona Server Java / Gradle 恢复方案

> 更新时间: 2026-04-22
> 目标：恢复 `/Users/a/back/Game/cq/leona-server` 的可执行构建能力，解除当前测试与验收 blocker。

---

## 1. 当前状态

当前已经确认：

- `gradlew` 存在
- `gradle/wrapper/gradle-wrapper.properties` 存在
- `gradle/wrapper/gradle-wrapper.jar` 已恢复到仓库工作区
- Gradle 8.10.2 distribution 已下载并可运行
- `/Users/a/back/Game/cq/leona-server/scripts/gradlew-java21.sh` 已加入仓库
- 2026-04-22 已真实执行通过：
  - `:admin-service:test`
  - `:query-service:test`
  - `test`
  - `build`

当前剩余注意事项：

- **默认系统 OpenJDK 25 仍不能直接启动本仓 Gradle Kotlin DSL**
- 直接执行 `./gradlew ...` 在 Java 25 下会报：
  - `java.lang.IllegalArgumentException: 25`
- 因此当前统一入口改为：
  - `/Users/a/back/Game/cq/leona-server/scripts/gradlew-java21.sh`

当前真正还会阻塞的事情是：

- Docker Desktop socket / Testcontainers 发现配置仍需收口（当前 `RedisBoxIdClaimIntegrationTest` 仍会 skip）
- docker-compose 本地栈联调仍受 Docker Hub 拉镜像超时影响

---

## 2. 已知目标版本

当前 wrapper 配置指向：

- Gradle `8.10.2`

配置文件：

- `/Users/a/back/Game/cq/leona-server/gradle/wrapper/gradle-wrapper.properties`

---

## 3. 推荐执行方式

### 推荐命令

```bash
cd /Users/a/back/Game/cq/leona-server
./scripts/gradlew-java21.sh test
./scripts/gradlew-java21.sh build
```

helper script 行为：

- 优先使用 `LEONA_SERVER_JAVA_HOME`
- 否则使用已设置且版本为 21 的 `JAVA_HOME`
- 否则回退到 IntelliJ IDEA / PyCharm 自带 JBR 21
- 默认写入 `GRADLE_USER_HOME=/Users/a/back/Game/cq/.gradle-home`

### 为什么还需要这个脚本

- Gradle 8.10.2 自身在本机默认 Java 25 launcher 下仍会触发 Kotlin DSL 兼容问题
- 但在 Java 21 launcher 下，当前仓库已能稳定执行 `test` 与 `build`

---

## 4. 恢复后第一批必须执行的命令

建议恢复后按这个顺序执行：

```bash
cd /Users/a/back/Game/cq/leona-server
./scripts/gradlew-java21.sh :admin-service:test
./scripts/gradlew-java21.sh :query-service:test --tests io.leonasec.server.query.infra.RedisBoxIdClaimIntegrationTest
./scripts/gradlew-java21.sh test
./scripts/gradlew-java21.sh build
```

如果 Docker 环境已可用，再补：

```bash
cd /Users/a/back/Game/cq/leona-server/deploy/docker-compose
docker compose up -d --build
```

---

## 5. 恢复后要重点确认的验收项

### query-service

- `RedisBoxIdClaimIntegrationTest` 在无 Docker daemon 时自动 skip
- 当前即使 Docker Desktop 已启动，测试仍会 skip；下一步要补 Docker Desktop socket/provider 配置
- `VerdictControllerWebMvcTest` 能通过
- BoxId 字符串 JSON 契约没有回归

### admin-service

- `TenantControllerWebMvcTest` 能通过
- key rotate / revoke 没有构建期问题

### 全局

- `./scripts/gradlew-java21.sh test` 能完成
- `./scripts/gradlew-java21.sh build` 能完成

---

## 6. 当前建议结论

当前可执行结论是：

> **Leona Server 的 Java / Gradle 构建能力已经恢复，但请统一通过 `scripts/gradlew-java21.sh` 执行。**

后续优先级已经不再是 wrapper / distribution，而是：

1. 启动 Docker Desktop
2. 修正 Testcontainers 对 Docker Desktop socket 的发现配置
3. 处理 docker-compose 拉取基础镜像时的 Docker Hub 超时
4. 完成 sample app 真联调留档
