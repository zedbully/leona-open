# Leona 模拟器 E2E 接入 GitHub CI 说明

> 更新时间：2026-04-23
> 适用对象：`/Users/a/back/Game/cq/leona-sdk-android`

---

## 1. 当前已落地内容

Android repo 已补充 manual workflow：

- `/Users/a/back/Game/cq/.github/workflows/android.yml`

新增 job：

- `live-emulator-e2e`

触发方式：

- GitHub Actions `workflow_dispatch`
- input：`run_live_e2e=true`

---

## 2. 该 workflow 做什么

该 job 会：

1. 校验 GitHub secrets / variables
2. 安装 JDK 21、NDK、emulator、API 34 system image
3. 启动 Android API 34 `google_apis` x86_64 模拟器
4. 执行：

```bash
bash ./scripts/run-emulator-e2e.sh
```

5. 上传截图 / XML artifacts

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

当前仍待完成：

- 在 GitHub 仓库中配置 secrets / variables
- 对 staging 环境跑一次真实 `workflow_dispatch`
- 留档一次 Actions 执行结果

---

## 5. 建议的下一步

1. 在 Android 开源仓库中配置上述 secret / variables
2. 手动触发 `Android CI` workflow，并勾选 `run_live_e2e`
3. 下载 artifact，补一份 CI 留档
