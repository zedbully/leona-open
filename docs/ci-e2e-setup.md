# Leona 模拟器 E2E 接入 GitHub CI 说明

> 更新时间：2026-04-29
> 适用对象：`/Users/a/back/Game/cq/leona-sdk-android`

---

## 1. 当前已落地内容

Android repo 已补充 manual workflow：

- `/Users/a/back/Game/cq/.github/workflows/android.yml`

新增 job：

- `live-emulator-e2e`
- `alpha-closure`

触发方式：

- GitHub Actions `workflow_dispatch`
- input：`run_live_e2e=true`
- 每天 02:00 Asia/Shanghai 自动运行 `alpha-closure`

---

## 2. 该 workflow 做什么

`live-emulator-e2e` 会：

1. 校验 GitHub secrets / variables
2. 安装 JDK 21、NDK、emulator、API 34 system image
3. 启动 Android API 34 `google_apis` x86_64 模拟器
4. 执行：

```bash
bash ./scripts/run-emulator-e2e.sh
```

5. 上传截图 / XML artifacts

`alpha-closure` 会在无人值守场景下自动做最小 alpha 闭环：

1. 运行 SDK / sample / public split 构建门禁
2. 启动本地 demo-backend
3. 运行 cloud config smoke
4. 生成 `report.json` / `report.md`
5. 上传 alpha closure artifacts

说明：

- 自动定时只跑不依赖外部密钥和真实设备的 alpha closure。
- live emulator E2E 和 live attestation E2E 仍需要手动 `workflow_dispatch`，因为它们依赖真实 `LEONA_E2E_*` secrets / variables。

---

## 3. 需要配置的 GitHub 设置

### Secret

- `LEONA_E2E_API_KEY`

### Repository Variables

- `LEONA_E2E_REPORTING_ENDPOINT`
- `LEONA_E2E_DEMO_BACKEND_BASE_URL`

建议：

- `LEONA_E2E_REPORTING_ENDPOINT=https://<your-staging-gateway>`
- `LEONA_E2E_DEMO_BACKEND_BASE_URL=https://<your-staging-demo-backend>`

---

## 4. 当前状态

当前已经完成：

- 本地模拟器 E2E 脚本跑通
- GitHub manual workflow scaffold 已补
- GitHub nightly alpha closure 已补，默认每天 02:00 Asia/Shanghai 自动执行

当前仍待完成：

- 在 GitHub 仓库中配置 secrets / variables
- 对 staging 环境跑一次真实 `workflow_dispatch`
- 留档一次 Actions 执行结果

---

## 5. 建议的下一步

1. 在 Android 开源仓库中配置上述 secret / variables
2. 手动触发 `Android CI` workflow，并勾选 `run_live_e2e`
3. 下载 artifact，补一份 CI 留档
