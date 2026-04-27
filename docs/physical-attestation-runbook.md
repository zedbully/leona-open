# Leona 真机 attestation 执行包

> 更新时间：2026-04-27
> 目的：在没有模拟器自动 `10.0.2.2` 前提下，给 USB 真机执行 attestation 留档一个固定入口。

---

## 1. 适用范围

当前脚本适用于以下 staging 模式：

- `debug_fake`
- `oem_debug_fake`

对应脚本：

- `/Users/a/back/Game/cq/leona-sdk-android/scripts/run-device-attestation-e2e.sh`

说明：

- 该脚本会先对 host 侧 `/v1/handshake` 做摘要校验
- 再通过 `adb reverse` 让真机使用 `127.0.0.1:8080`
- 再校验 Android transport / support bundle 是否与 handshake 摘要一致

---

## 2. 前置条件

### Android 设备

- 至少 1 台 USB 真机
- `adb devices -l` 可见设备为 `device`
- 开启 USB 调试

### Server

- 本地 server 栈已启动
- `http://127.0.0.1:8080` ~ `8084` 健康检查通过

### OEM 模式额外要求

如果跑 `oem_debug_fake`，需要在 ingestion-service 所在环境配置：

```bash
LEONA_HANDSHAKE_ATTESTATION_OEM_TRUSTED_PROVIDERS=sample_mainland_debug
```

---

## 3. 执行命令

### 3.1 Play-style debug token

```bash
ADB_SERIAL=<device-serial> \
LEONA_API_KEY=<appKey> \
LEONA_SAMPLE_ATTESTATION_MODE=debug_fake \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-device-attestation-e2e.sh
```

预期：

- `deviceBindingStatus=bound-software/play_integrity/MEETS_DEVICE_INTEGRITY`
- `provider=play_integrity`
- `code=PLAY_INTEGRITY_VERIFIED`

### 3.2 Mainland OEM debug token

```bash
ADB_SERIAL=<device-serial> \
LEONA_API_KEY=<appKey> \
LEONA_SAMPLE_ATTESTATION_MODE=oem_debug_fake \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-device-attestation-e2e.sh
```

预期：

- `deviceBindingStatus=bound-software/oem_attestation/oem_attested`
- `provider=sample_mainland_debug`
- `code=OEM_ATTESTATION_VERIFIED`

---

## 4. 脚本行为

脚本会自动执行：

1. 检查真机是否在线
2. 执行 `adb reverse tcp:8080 tcp:8080`
3. 如可用，附带执行 `adb reverse tcp:8090 tcp:8090`
4. 先校验 host `/v1/handshake` 的摘要结果
5. 安装 sample app 到真机
6. 启动 app 并点击 `Run sense()`
7. 读取：
   - `transportSummary`
   - `supportBundleSummary`
   - `transportJson`
   - `supportBundleJson`
8. 生成：
   - `handshake-response.json`
   - `attestation-e2e-report.json`

---

## 5. 产物目录

默认输出目录：

```bash
/tmp/leona-device-attestation-e2e-<timestamp>
```

关键产物：

- `handshake-request.json`
- `handshake-response.json`
- `attestation-e2e-report.json`
- UI dump XML / PNG

---

## 6. 留档方式

执行完后，复制模板：

- `/Users/a/back/Game/cq/docs/device-attestation-record-template.md`

建议命名：

- `/Users/a/back/Game/cq/docs/device-attestation-record-YYYY-MM-DD.md`
- `/Users/a/back/Game/cq/docs/device-mainland-attestation-record-YYYY-MM-DD.md`

---

## 7. 当前状态

截至 2026-04-27：

- 本地 server 栈在线
- 当前仅检测到模拟器 `emulator-5554`
- 尚未检测到 USB 真机，因此本次未直接生成新的真机留档

这不是代码阻塞，而是现场设备条件未满足。
