# Codex Startup Instructions

本仓库后续每次启动 Codex 或开始新任务时，先执行以下动作：

1. 阅读 `/Users/a/back/Game/cq/docs/work-items.md`。
2. 运行 `git status --short --branch`。
3. 若用户没有指定更高优先级的新任务，优先推进 `docs/work-items.md` 中 P0 的第一个未完成项。
4. 每完成、阻塞或调整一个工作项，都要同步更新 `docs/work-items.md`。
5. 客户端 SDK 只采集和上报证据，不做最终判定；所有业务决策必须由服务端 verdict 处理。

关键文档入口：

- `/Users/a/back/Game/cq/docs/work-items.md`
- `/Users/a/back/Game/cq/docs/alpha-development-plan.md`
- `/Users/a/back/Game/cq/docs/current-status.md`
- `/Users/a/back/Game/cq/docs/README.md`
