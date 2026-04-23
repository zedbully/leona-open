# Leona Public-only 构建复验记录（2026-04-24）

> 时间：2026-04-24
> 目的：在收口阶段再次确认临时移走 `private/` 目录后，公开仓库边界仍可独立构建。

---

## 1. 验收方式

本次复验通过临时移走以下目录进行：

- `/Users/a/back/Game/cq/leona-sdk-android/private`
- `/Users/a/back/Game/cq/leona-server/private`

构建完成后已自动恢复原目录。

---

## 2. Android public-only 复验

执行命令：

```bash
cd /Users/a/back/Game/cq/leona-sdk-android
./gradlew :sdk:assembleDebug :sample-app:assembleDebug --no-daemon --no-configuration-cache
```

结果：

- `:sdk:assembleDebug` ✅
- `:sample-app:assembleDebug` ✅

补充说明：

- 本次 sample-app 仅打包 OSS `libleona.so`
- private core 不存在时，public fallback 仍可独立工作

---

## 3. Server public-only 复验

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
- fallback risk scorer / risk policy 仍可独立工作

---

## 4. 结论

本次复验确认：

> **截至 2026-04-24，Leona 的 public-only 构建边界仍然成立。**

也就是：

- 开源版 Android 可独立构建
- 开源版 Server 可独立构建
- `private/` 目录不是公开仓库构建的硬依赖
