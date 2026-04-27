# Leona attestation 摘要专项留档（2026-04-25）

> 日期：2026-04-25
> 环境：`/Users/a/back/Game/cq`
> 目的：留档一次真实的 handshake attestation 摘要 → Android transport/support bundle 透传结果

---

## 1. 运行环境

### Android

- AVD：`leona-api34`
- 设备：`emulator-5554`
- sample app endpoint：`http://10.0.2.2:8080`
- attestation mode：`debug_fake`

### Server

- gateway：`http://127.0.0.1:8080`
- ingestion-service：`http://127.0.0.1:8081`
- query-service：`http://127.0.0.1:8082`
- admin-service：`http://127.0.0.1:8083`
- worker-event-persister：`http://127.0.0.1:8084`

### 凭据

- `LEONA_API_KEY=lk_live_app_SiHCmESWBDBP2Bi5SpGkKekU`

---

## 2. 本次真实执行

执行命令：

```bash
LEONA_API_KEY=lk_live_app_SiHCmESWBDBP2Bi5SpGkKekU \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-attestation-e2e.sh
```

本次输出目录：

- `/tmp/leona-attestation-e2e-20260425-002000`

关键产物：

- `/tmp/leona-attestation-e2e-20260425-002000/handshake-response.json`
- `/tmp/leona-attestation-e2e-20260425-002000/attestation-e2e-report.json`

---

## 3. Server handshake 真实结果

本次 `/v1/handshake` 真实返回：

```json
{
  "deviceBindingStatus": "bound-software/play_integrity/MEETS_DEVICE_INTEGRITY",
  "attestation": {
    "provider": "play_integrity",
    "status": "play_integrity/MEETS_DEVICE_INTEGRITY",
    "code": "PLAY_INTEGRITY_VERIFIED",
    "retryable": false
  }
}
```

说明：

- server 端 attestation 摘要已真实出现在握手响应
- 响应不是 mock，来自本地 docker compose 网关 `:8080`

---

## 4. Android sample 真实结果

本次 sample app 成功执行 `sense()`，页面显示：

- `BoxId: 01KQ04NPATG3KP1S1526KXX3M3`

### 4.1 transport summary

真实显示：

```text
sessionBindingStatus=bound-software/play_integrity/MEETS_DEVICE_INTEGRITY
serverAttestationProvider=play_integrity
serverAttestationStatus=play_integrity/MEETS_DEVICE_INTEGRITY
serverAttestationCode=PLAY_INTEGRITY_VERIFIED
serverAttestationRetryable=false
```

### 4.2 support bundle summary

真实显示：

```text
transportBindingStatus=bound-software/play_integrity/MEETS_DEVICE_INTEGRITY
serverAttestationProvider=play_integrity
serverAttestationStatus=play_integrity/MEETS_DEVICE_INTEGRITY
serverAttestationCode=PLAY_INTEGRITY_VERIFIED
```

---

## 5. 原始 JSON 对齐结果

`attestation-e2e-report.json` 已校验以下对齐关系：

- server handshake `deviceBindingStatus`
- transport `session.deviceBindingStatus`
- support bundle `secureTransport.session.deviceBindingStatus`
- server handshake `attestation.provider/status/code/retryable`
- transport `session.serverAttestation.*`
- support bundle `secureTransport.session.serverAttestation.*`

本次结果：

```json
{
  "attestationMode": "debug_fake",
  "checks": {
    "transportBindingStatus": "bound-software/play_integrity/MEETS_DEVICE_INTEGRITY",
    "supportBundleBindingStatus": "bound-software/play_integrity/MEETS_DEVICE_INTEGRITY",
    "transportServerAttestation": {
      "provider": "play_integrity",
      "status": "play_integrity/MEETS_DEVICE_INTEGRITY",
      "code": "PLAY_INTEGRITY_VERIFIED",
      "retryable": false
    },
    "supportBundleServerAttestation": {
      "provider": "play_integrity",
      "status": "play_integrity/MEETS_DEVICE_INTEGRITY",
      "code": "PLAY_INTEGRITY_VERIFIED",
      "retryable": false
    }
  }
}
```

结论：

- server handshake 摘要与 Android transport / support bundle 已真实对齐

---

## 6. Closure / CI 接入状态

本次留档对应的工程状态：

- 已接入本地 closure：

```bash
RUN_ATTESTATION_E2E=1 LEONA_API_KEY=<appKey> \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-alpha-closure.sh
```

- 已接入 GitHub Actions `workflow_dispatch`：
  - `run_live_attestation_e2e`

- Actions summary 已支持显示：
  - `deviceBindingStatus`
  - `provider`
  - `status`
  - `code`
  - `retryable`

---

## 7. 当前结论

结论：

> **Leona 已在本地真实验证 handshake attestation 摘要从 server 返回并被 Android sample 的 transport / support bundle 完整透传。**

当前仍未在本地完成的专项项：

- `oem_debug_fake` 真环境回归
- 真机 attestation 留档
