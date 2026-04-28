# Leona Alpha 模拟器验证记录（2026-04-29）

> 时间：2026-04-29  
> 目的：在暂无 USB 物理真机的情况下，继续使用 `emulator-5554` 执行 Alpha 计划中的本地可回归验证，并修复模拟器 E2E 中发现的脚本可靠性问题。

---

## 1. 环境

当前 ADB 设备：

```text
emulator-5554 device product:sdk_gphone64_arm64 model:sdk_gphone64_arm64 device:emu64a
```

本地服务健康状态：

- `http://127.0.0.1:8080/actuator/health`：`UP`
- `http://127.0.0.1:8081/actuator/health`：`UP`
- `http://127.0.0.1:8082/actuator/health`：`UP`
- `http://127.0.0.1:8083/actuator/health`：`UP`
- `http://127.0.0.1:8084/actuator/health`：`UP`
- `http://127.0.0.1:8090/health`：`ok=true`

---

## 2. Alpha Closure 总入口

执行入口：

```bash
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-alpha-closure.sh
```

本轮参数：

- `RUN_ATTESTATION_E2E=1`
- `RUN_EMULATOR_E2E=1`
- `RUN_DEVICE_E2E=0`
- `LEONA_SAMPLE_ATTESTATION_MODE=oem_debug_fake`
- local app key / secret 由 admin-service 临时创建，仅作为环境变量传入，不写入记录

产物目录：

```text
/tmp/leona-alpha-closure-20260429-emulator
```

结果：**PASS**

报告摘要：

- buildGate：`true`
- cloudConfigSmoke：`true`
- attestationE2E requested/passed：`true/true`
- emulatorE2E requested/passed：`true/true`
- deviceE2E requested：`false`

Formal verdict：

- `formalBoxId=01KQB43PEZF34JA2TDZSRS32D8`
- `formalCanonical=Lbfe0e7fbba18b857dee43a9c4b24907`
- `formalRiskLevel=CRITICAL`
- `formalRiskScore=100`
- `formalSignatureVerified=true`

Emulator E2E 关键校验：

- BoxId：`01KQB41YC9B7KFK3CMDDS3ZBNN`
- Formal Verdict BoxId：`01KQB43PEZF34JA2TDZSRS32D8`
- Device before：`T0IoabGzRvhcGNeM186Owtjnd593MeunqitfFp5-Bq8A`
- Device after：`Lbfe0e7fbba18b857dee43a9c4b24907`
- `effectiveDisabled=androidId`
- `cloudRawPresent=true`
- transport / support bundle / verdict canonical 对齐
- `deviceFingerprint` 存在
- formal verdict response signature 校验通过

OEM debug fake attestation：

- provider：`sample_mainland_debug`
- status：`oem_attestation/oem_attested`
- code：`OEM_ATTESTATION_VERIFIED`
- retryable：`false`
- binding status：`bound-software/oem_attestation/oem_attested`

---

## 3. Play Integrity Debug Fake 复验

初次执行 `debug_fake` 时，脚本发现 transport summary 仍保留上一轮 `oem_debug_fake` session：

```text
sessionBindingStatus=bound-software/oem_attestation/oem_attested
```

预期应为：

```text
sessionBindingStatus=bound-software/play_integrity/MEETS_DEVICE_INTEGRITY
```

判断：

- 这是脚本隔离问题，不是服务端 attestation 判定问题
- `run-emulator-attestation-e2e.sh` 安装新 sample 前未清理旧 app/session 状态
- 跨 attestation mode 连续执行时，会复用上一轮 secure transport session

修复：

- `/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-attestation-e2e.sh`
  - 在 `install_sample` 前增加 `adb uninstall`
  - 与 `run-emulator-e2e.sh` 的隔离策略保持一致

重跑产物目录：

```text
/tmp/leona-attestation-debug-fake-20260429-rerun
```

重跑结果：**PASS**

复验摘要：

- mode：`debug_fake`
- BoxId：`01KQB48392Y4PB1TGT4GF4G59K`
- deviceBindingStatus：`bound-software/play_integrity/MEETS_DEVICE_INTEGRITY`
- provider：`play_integrity`
- status：`play_integrity/MEETS_DEVICE_INTEGRITY`
- code：`PLAY_INTEGRITY_VERIFIED`
- retryable：`false`
- transportBindingStatus：`bound-software/play_integrity/MEETS_DEVICE_INTEGRITY`
- supportBundleBindingStatus：`bound-software/play_integrity/MEETS_DEVICE_INTEGRITY`

---

## 4. 日志脱敏修复

修复：

- `/Users/a/back/Game/cq/leona-sdk-android/scripts/run-live-sample.sh`
  - 不再直接 grep 输出 `BuildConfig` 中的敏感字段
  - 对 `LEONA_API_KEY` 和 `LEONA_DEMO_VERDICT_SECRET_KEY` 输出 `<redacted>`

验证：

- `/tmp/leona-alpha-closure-20260429-emulator/emulator-e2e.log`
- `/tmp/leona-alpha-closure-20260429-emulator/attestation-e2e.log`
- `/tmp/leona-attestation-debug-fake-20260429-rerun`

上述日志中敏感字段只以 `<redacted>` 形式出现。

---

## 5. 当前结论

截至本轮：

- 模拟器 Alpha closure 总入口通过
- `oem_debug_fake` mainland / 非 GMS attestation 路线通过
- `debug_fake` Play Integrity attestation 路线通过
- emulator E2E formal verdict 签名、canonical、risk、support bundle 对齐通过
- E2E 日志已避免明文输出 app key / verdict secret
- attestation E2E 已修复跨模式 session 污染问题

仍未替代的事项：

- USB 物理真机 E2E 留档
- GitHub Actions live E2E 首跑

