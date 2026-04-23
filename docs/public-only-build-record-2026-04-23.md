# Leona Public-only 构建验收记录（2026-04-23）

> 时间：2026-04-23
> 目的：验证在临时移走 `private/` 目录后，公开仓库仍可独立构建。

---

## 1. 验收方式

本次验收通过临时移走以下目录进行：

- `/Users/a/back/Game/cq/leona-sdk-android/private`
- `/Users/a/back/Game/cq/leona-server/private`

构建完成后已自动恢复原目录。

---

## 2. Android public-only 验收

执行命令：

```bash
cd /Users/a/back/Game/cq/leona-sdk-android
./gradlew :sdk:assembleDebug :sample-app:assembleDebug --no-daemon --no-configuration-cache
```

结果：

- `:sdk:assembleDebug` ✅
- `:sample-app:assembleDebug` ✅

结论：

- 去掉 `private/sdk-private-core` 后，Android 开源版仍可独立构建
- public fallback 不依赖 private headers / private module

---

## 3. Server public-only 验收

执行命令：

```bash
cd /Users/a/back/Game/cq/leona-server
./scripts/gradlew-java21.sh :common:classes :ingestion-service:classes :worker-event-persister:classes --no-daemon --no-configuration-cache
```

结果：

- `:common:classes` ✅
- `:ingestion-service:classes` ✅
- `:worker-event-persister:classes` ✅

结论：

- 去掉 `private/api-backend` 后，server 开源版仍可独立构建
- fallback risk scorer / risk policy 可独立工作

---

## 4. 总结

本次验收确认：

- 开源版 Android 可独立构建
- 开源版 Server 可独立构建
- private 目录当前已经不再是公开仓库构建的硬依赖

这意味着：

> Leona 当前已经具备“公开仓库可独立发布，私有模块可独立增强”的基本工程边界。
