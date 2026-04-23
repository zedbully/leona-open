# Leona Alpha 发布准备清单

> 更新时间: 2026-04-23
> 目标：把当前工程状态收口成一次可内测的 Android alpha 发布准备文档

---

## 1. 本次 alpha 的定义

> **面向少量内测接入方的 Android runtime security alpha。**

本次 alpha 的最小交付边界：

- Android SDK 可构建 AAR
- sample app 可演示真实闭环
- demo backend 可展示业务后端如何查询 verdict
- server 端文档、测试、协议说明基本齐备

---

## 2. 当前已确认交付物

### Android

- AAR：`/Users/a/back/Game/cq/leona-sdk-android/sdk/build/outputs/aar/sdk-release.aar`
- debug APK：`/Users/a/back/Game/cq/leona-sdk-android/sample-app/build/outputs/apk/debug/sample-app-debug.apk`
- 一键联调脚本：`/Users/a/back/Game/cq/leona-sdk-android/scripts/run-live-sample.sh`
- 模拟器 E2E 自动化脚本：`/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-e2e.sh`

### Demo / Server

- 本地 docker-compose 五服务栈
- demo-backend
- 模拟器联调留档：`/Users/a/back/Game/cq/docs/demo-record-2026-04-23.md`

---

## 3. alpha 发布前仍需完成的项目

### Blocker A：alpha release note 定稿（已关闭）

当前已完成：

- 发布范围说明
- 可用能力清单
- 已知限制说明
- 推荐接入方式
- 对外口径

对应文档：

- `/Users/a/back/Game/cq/docs/alpha-release-notes.md`

### Blocker B：Android ↔ Server E2E 自动化（已关闭）

当前已经完成：

- 模拟器人工闭环
- sample app → sense → verdict 真实留档
- 可回归执行的自动化 E2E
- 2026-04-23 已真实执行：
  - `BoxId=01KPV5E417A7467GRBRMQXYF30`
  - `decision=deny`
  - `risk=CRITICAL`
  - `score=100`
  - 产物目录：`/tmp/leona-e2e-20260423-015719`

### Blocker C：真机留档（增强项）

当前已经完成：

- 模拟器留档

建议补充：

- 一轮真机联调记录，用于对外 alpha 更有说服力

---

## 4. 当前发布判断

截至 2026-04-23：

- **文档收口：较好**
- **服务端协议与 MVP 收口：较好**
- **Android 构建链 / AAR / APK：已确认**
- **模拟器真实联调：已通过**
- **自动化回归：本地脚本已具备**
- **对外 release material：已具备**

所以当前建议口径是：

> **Leona 已进入 alpha 发布准备的最后阶段；本地真实联调、模拟器 E2E 自动化、alpha release notes、admin 真实联调留档、最小 observability 收口与 GitHub manual E2E workflow scaffold 已完成，剩余主要是真机留档与首次 CI 跑验。**
