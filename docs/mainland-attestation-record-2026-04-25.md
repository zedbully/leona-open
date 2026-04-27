# Mainland / non-GMS attestation 留档（2026-04-25）

> 日期：2026-04-25
> 环境：`/Users/a/back/Game/cq`
> 目的：留档一次 `oem_debug_fake` 在标准 gateway `:8080` 链路上的真实握手与 Android 透传结果

---

## 1. 运行环境

### Android

- AVD：`leona-api34`
- 设备：`emulator-5554`
- sample app endpoint：`http://10.0.2.2:8080`
- attestation mode：`oem_debug_fake`

### Server

- gateway：`http://127.0.0.1:8080`
- ingestion-service：`http://127.0.0.1:8081`
- query-service：`http://127.0.0.1:8082`
- admin-service：`http://127.0.0.1:8083`
- worker-event-persister：`http://127.0.0.1:8084`

### 本次额外条件

为满足 OEM provider allowlist，本次将 gateway 后的 ingestion-service 切到带以下环境变量的运行实例：

```bash
LEONA_HANDSHAKE_ATTESTATION_OEM_TRUSTED_PROVIDERS=sample_mainland_debug
```

本次实际使用的替换命令：

```bash
docker rm -f leona-ingestion
docker run -d \
  --name leona-ingestion \
  --network docker-compose_default \
  --network-alias ingestion-service \
  -p 8081:8081 \
  -e JAVA_OPTS='-XX:+UseG1GC -Xms64m -Xmx256m' \
  -e REDIS_HOST=redis \
  -e KAFKA_BOOTSTRAP_SERVERS=kafka:9092 \
  -e LEONA_REGION=local \
  -e LEONA_HANDSHAKE_ATTESTATION_OEM_TRUSTED_PROVIDERS=sample_mainland_debug \
  docker-compose-ingestion-service
```

---

## 2. 本次真实执行

执行命令：

```bash
LEONA_API_KEY=lk_live_app_SiHCmESWBDBP2Bi5SpGkKekU \
LEONA_SAMPLE_ATTESTATION_MODE=oem_debug_fake \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-attestation-e2e.sh
```

本次输出目录：

- `/tmp/leona-attestation-e2e-20260425-234724`

关键产物：

- `/tmp/leona-attestation-e2e-20260425-234724/handshake-response.json`
- `/tmp/leona-attestation-e2e-20260425-234724/attestation-e2e-report.json`

---

## 3. Server handshake 真实结果

本次 `/v1/handshake` 真实返回：

```json
{
  "deviceBindingStatus": "bound-software/oem_attestation/oem_attested",
  "attestation": {
    "provider": "sample_mainland_debug",
    "status": "oem_attestation/oem_attested",
    "code": "OEM_ATTESTATION_VERIFIED",
    "retryable": false
  }
}
```

说明：

- gateway `:8080` 已能透传 OEM attestation 成功结果
- server 端摘要已归一化到 `oem_attestation/oem_attested`

---

## 4. Android sample 真实结果

本次 sample app 成功执行 `sense()`，页面显示：

- `BoxId: 01KQ2N6QSRED247JTFSDPJV01A`

### 4.1 transport summary

真实显示：

```text
sessionBindingStatus=bound-software/oem_attestation/oem_attested
serverAttestationProvider=sample_mainland_debug
serverAttestationStatus=oem_attestation/oem_attested
serverAttestationCode=OEM_ATTESTATION_VERIFIED
serverAttestationRetryable=false
```

### 4.2 support bundle summary

真实显示：

```text
transportBindingStatus=bound-software/oem_attestation/oem_attested
serverAttestationProvider=sample_mainland_debug
serverAttestationStatus=oem_attestation/oem_attested
serverAttestationCode=OEM_ATTESTATION_VERIFIED
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
  "attestationMode": "oem_debug_fake",
  "boxId": "01KQ2N6QSRED247JTFSDPJV01A",
  "checks": {
    "transportBindingStatus": "bound-software/oem_attestation/oem_attested",
    "supportBundleBindingStatus": "bound-software/oem_attestation/oem_attested",
    "transportServerAttestation": {
      "provider": "sample_mainland_debug",
      "status": "oem_attestation/oem_attested",
      "code": "OEM_ATTESTATION_VERIFIED",
      "retryable": false
    },
    "supportBundleServerAttestation": {
      "provider": "sample_mainland_debug",
      "status": "oem_attestation/oem_attested",
      "code": "OEM_ATTESTATION_VERIFIED",
      "retryable": false
    }
  }
}
```

结论：

- `oem_debug_fake` 已在标准 gateway `:8080` 路径上真实打通
- server handshake 摘要与 Android transport / support bundle 已真实对齐

---

## 6. 当前结论

结论：

> **Leona 已在本地真实验证 `oem_debug_fake` 经 private OEM verifier + provider allowlist 后，可通过标准 gateway `:8080` 返回 OEM attestation 摘要，并被 Android sample 的 transport / support bundle 完整透传。**

本次留档仍然属于：

- mainland / non-GMS 的 public sample + private verifier staging 验证

当前仍未完成：

- 真 OEM Android provider 接入
- 真 OEM server verifier / trust anchor / allowlist 生产配置
- 真机 mainland OEM 留档
