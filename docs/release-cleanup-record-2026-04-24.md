# Leona 发布前清理记录（2026-04-24）

> 时间：2026-04-24
> 目标：在收口阶段先做一轮实际可执行的发布前清理检查。

---

## 1. 已完成的检查

### 1.1 private 目录隔离

已确认：

- `/Users/a/back/Game/cq/leona-sdk-android/.gitignore` 包含 `private/`
- `/Users/a/back/Game/cq/leona-server/.gitignore` 包含 `private/`
- Android / Server private 模块目录都存在于可选路径下，不是 public 构建硬依赖

### 1.2 public-only 构建复验

已完成复验：

- `/Users/a/back/Game/cq/docs/public-only-build-record-2026-04-24.md`

结论：

- Android public-only build ✅
- Server public-only build ✅

### 1.3 private 模块验收

已完成复验：

- `/Users/a/back/Game/cq/docs/private-module-verify-record-2026-04-24.md`

结论：

- Android private core build ✅
- server private backend build ✅

### 1.4 本地配置与杂项文件清理

本轮处理：

- 将 `/Users/a/back/Game/cq/leona-server/admin-service/src/main/resources/application-local.yml`
  调整为示例模板：
  `/Users/a/back/Game/cq/leona-server/admin-service/src/main/resources/application-local.example.yml`
- 已删除工作区中的 `.DS_Store` 文件

---

## 2. 当前仍未完成的项

### 2.1 Git 检查仍待真正仓库环境执行

当前 `/Users/a/back/Game/cq` 以及各子目录 **不是可直接执行 Git 命令的仓库工作树**，因此以下检查本轮无法在当前环境内完成：

- `git status`
- `git diff --cached`
- 检查 staged 内容里是否误带 private 文件

这部分需要在你真正准备发布的 Git 仓库工作树里再执行一轮。

### 2.2 真机 / CI 为增强项

仍建议后续补：

- 真机留档
- 首次 GitHub live emulator E2E

---

## 3. 当前结论

本轮可以确认：

> **代码边界、构建边界、文档边界已经进入可发布前整理状态；剩余主要是 Git 工作树检查与最终发布动作。**
