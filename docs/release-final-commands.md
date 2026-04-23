# Leona 最终发布前操作口令清单

> 更新时间：2026-04-24
> 用途：在你真正准备把仓库推到 GitHub 前，按顺序直接执行。

---

## 1. 先进入真实发布工作树

下面命令要在**真正的 Git 仓库目录**里执行，而不是当前这个非 Git 快照目录。

如果你的发布工作树结构仍然是：

- `leona-sdk-android`
- `leona-server`
- `demo-backend`
- `leona`

那么直接进入根目录后执行下面命令。

---

## 2. 先跑一键 Git 预检

```bash
cd <your-release-workspace>
/Users/a/back/Game/cq/scripts/release-preflight.sh --strict leona-sdk-android leona-server
```

如果你也想顺手带上构建检查：

```bash
cd <your-release-workspace>
export JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
export GRADLE_USER_HOME=/Users/a/back/Game/cq/.gradle-home
/Users/a/back/Game/cq/scripts/release-preflight.sh --strict --with-build leona-sdk-android leona-server
```

预期：

- `git status` 没有异常 staged 内容
- `git diff --cached` 为空或只包含你要发布的公开改动
- 没有 tracked / staged 的 `private/` 文件
- 没有本地密钥、`.env`、`application-local.yml` 之类残留

---

## 3. 手动再看一眼关键 Git 输出

### Android

```bash
cd <your-release-workspace>/leona-sdk-android
git status --short
git diff --cached --name-only
git ls-files | grep '^private/' || true
```

### Server

```bash
cd <your-release-workspace>/leona-server
git status --short
git diff --cached --name-only
git ls-files | grep '^private/' || true
```

---

## 4. 再跑一轮 public-only 构建检查

### Android

```bash
cd <your-release-workspace>/leona-sdk-android
mv private /tmp/leona-android-private-backup
./gradlew :sdk:assembleDebug :sample-app:assembleDebug --no-daemon --no-configuration-cache
mv /tmp/leona-android-private-backup private
```

### Server

```bash
cd <your-release-workspace>/leona-server
mv private /tmp/leona-server-private-backup
./scripts/gradlew-java21.sh :common:classes :ingestion-service:classes :worker-event-persister:classes --no-daemon --no-configuration-cache
mv /tmp/leona-server-private-backup private
```

如果你怕中断恢复，优先参考：

- `/Users/a/back/Game/cq/docs/public-only-build-record-2026-04-24.md`

---

## 5. 再跑一轮 private 模块验收

```bash
cd /Users/a/back/Game/cq
./scripts/verify-private-modules.sh
```

参考验收记录：

- `/Users/a/back/Game/cq/docs/private-module-verify-record-2026-04-24.md`

---

## 6. 最后确认以下文件口径

重点再看：

- `/Users/a/back/Game/cq/docs/closeout-strategy.md`
- `/Users/a/back/Game/cq/docs/open-vs-private-final-matrix.md`
- `/Users/a/back/Game/cq/docs/open-source-release-checklist.md`
- `/Users/a/back/Game/cq/docs/release-cleanup-record-2026-04-24.md`

确认：

- 对外只讲 shell / sample / docs / fallback
- 不写真实高价值 detector 细节
- 不写真实风险阈值 / 权重 / tenant 策略
- 不写私有 internal ops 具体实现

---

## 7. 发布前最终通过标准

满足下面 7 条再推 GitHub：

1. `private/` 未进入 staged / tracked 内容
2. `git status` 可解释且没有误提交文件
3. `git diff --cached` 只包含准备公开的内容
4. public-only 构建通过
5. private split 验收通过
6. 文档口径已经冻结为 open-source shell / private core / private backend
7. 没有本地密钥、`.env`、`application-local.yml`、`.DS_Store` 残留

---

## 8. 建议的最后发布顺序

```bash
# 1) Git 预检
/Users/a/back/Game/cq/scripts/release-preflight.sh --strict leona-sdk-android leona-server

# 2) public-only 复验
# 3) private split 复验
# 4) 再看 git status / diff --cached
# 5) push 到 GitHub
```

一句话：

> **先确认没有把 private 带出去，再确认 public 自己能活，最后再发。**
