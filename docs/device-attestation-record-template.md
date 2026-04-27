# Leona 真机 attestation 留档模板

> 使用方式：每完成一次真机 attestation 联调，就复制本模板保存一份记录。

---

## 1. 基本信息

- 日期：
- 执行人：
- 设备型号：
- Android 版本：
- ADB_SERIAL：
- Leona SDK 版本：
- attestation mode：`debug_fake` / `oem_debug_fake` / 真实 provider

---

## 2. 联调配置

- `LEONA_API_KEY`：
- `LEONA_HOST_BASE_URL`：
- `LEONA_REPORTING_ENDPOINT`：
- `LEONA_CLOUD_CONFIG_ENDPOINT`：
- `LEONA_DEMO_BACKEND_BASE_URL`：
- `LEONA_HANDSHAKE_ATTESTATION_OEM_TRUSTED_PROVIDERS`：
- 是否使用 `adb reverse`：是 / 否

---

## 3. Server 结果

### `/v1/handshake`

- 是否成功：是 / 否
- `deviceBindingStatus`：
- `attestation.provider`：
- `attestation.status`：
- `attestation.code`：
- `attestation.retryable`：
- `handshake-response.json` 路径：

---

## 4. Android 结果

### transport summary

- `sessionBindingStatus`：
- `serverAttestationProvider`：
- `serverAttestationStatus`：
- `serverAttestationCode`：
- `serverAttestationRetryable`：

### support bundle summary

- `transportBindingStatus`：
- `serverAttestationProvider`：
- `serverAttestationStatus`：
- `serverAttestationCode`：

### BoxId

- `sense()` 是否成功：是 / 否
- BoxId：

---

## 5. 对齐校验

- transport `session.deviceBindingStatus` 是否与 handshake 一致：是 / 否
- support bundle `secureTransport.session.deviceBindingStatus` 是否与 handshake 一致：是 / 否
- transport `serverAttestation.*` 是否与 handshake 一致：是 / 否
- support bundle `serverAttestation.*` 是否与 handshake 一致：是 / 否
- `attestation-e2e-report.json` 路径：

---

## 6. 产物

- 截图目录：
- `handshake-response.json`：
- `attestation-e2e-report.json`：
- `transport.json`：
- `support-bundle.json`：

---

## 7. 问题记录

- 发现的问题：
- 是否阻塞发布：是 / 否
- 临时绕过方案：
- 后续动作：

---

## 8. 最终结论

- 本次真机 attestation 是否通过：通过 / 部分通过 / 未通过
- 是否可作为留档证据：是 / 否
- 下一步：
