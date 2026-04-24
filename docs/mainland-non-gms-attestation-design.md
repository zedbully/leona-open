# 中国大陆无 GMS 设备 Attestation 设计草案

> 更新时间：2026-04-24
> 目标：给 Leona 的 **private core / private backend** 提供一条可替代 Play Integrity 的大陆设备证明链路。

---

## 1. 背景

当前公开版框架：

- **SDK 侧**已经支持可插拔 `AttestationProvider`
- **服务端公开实现**当前只内置 `play_integrity` 校验
- 因此无 GMS 设备可以跑主流程，但默认没有正式 attestation 能力

本设计的目标不是扩 public 面，而是：

> 在 **private 模块** 中补齐大陆设备的 attestation provider + verifier + risk 融合链路。

---

## 2. 设计目标

### 必须满足

1. 无 GMS 设备可参与 handshake / sense / verdict
2. attestation 与现有 `clientPublicKey + installId + sdkVersion` challenge 绑定
3. 服务端能区分：
   - `play_integrity`
   - `oem_attestation`
   - `none`
4. 风控层能对不同 attestation 强度做差异化处理
5. public repo 不引入厂商私有 SDK / 私有 verifier 细节

### 明确不做

1. 不在公开仓库里实现真实厂商 attestation 逻辑
2. 不在公开仓库里写死真实策略阈值
3. 不要求大陆方案与 Play Integrity 强度完全等价

---

## 3. 边界划分

### Public 保留

- `AttestationProvider` 接口
- `AttestationStatement(format, token)`
- 无 attestation 的 fallback 路径
- 公开 sample 的 `off / debug_fake / bridge` 模式

### Private 承接

#### Android private core

- `MainlandAttestationProvider`
- 厂商 / OEM / 企业 attestation bridge
- token 组装与签名材料采集

#### Server private backend

- `oem_attestation` verifier
- token 验签 / challenge / timestamp / nonce 校验
- attestation 强度分级
- 风控融合策略

---

## 4. 总体链路

```text
[Android App]
   │
   │ 1. private MainlandAttestationProvider 生成 attestation token
   ▼
[Leona SDK / private core]
   │
   │ 2. handshake 携带:
   │    - clientPublicKey
   │    - installId
   │    - deviceBinding
   │    - attestationFormat=oem_attestation
   │    - attestationToken=<opaque token>
   ▼
[Leona ingestion / private verifier]
   │
   │ 3. 校验 token:
   │    - challenge
   │    - timestamp
   │    - replay
   │    - device trust tier
   ▼
[Session / Risk Engine]
   │
   │ 4. 产出:
   │    - attestation status
   │    - provider
   │    - trust tier
   │    - risk uplift / downgrade
   ▼
[Verdict]
```

---

## 5. 客户端设计

### 5.1 Provider 结构

建议在 private Android 模块中新增：

```kotlin
class MainlandAttestationProvider(
    private val delegate: MainlandAttestationBridge,
) : AttestationProvider
```

其中：

```kotlin
interface MainlandAttestationBridge {
    suspend fun attest(request: MainlandAttestationRequest): MainlandAttestationResult?
}
```

### 5.2 Request 输入

客户端 attestation 请求至少绑定以下字段：

- `challenge`
- `installId`
- `clientPublicKey`
- `sdkVersion`
- `packageName`
- `appCertDigest`
- `deviceModel`
- `osVersion`
- `romVendor`
- `timestamp`

其中前四项必须与服务端 handshake challenge 可重建。

### 5.3 Result 输出

```kotlin
data class MainlandAttestationResult(
    val provider: String,
    val token: String,
)
```

最终映射为：

```kotlin
AttestationStatement(
    format = "oem_attestation",
    token = token,
)
```

### 5.4 客户端失败语义

客户端需要统一失败分类，至少包括：

- provider unavailable
- api not supported
- service bind failed
- signature invalid
- timeout
- transient network
- unknown

这些错误码只进入 private transport / diagnostics，不需要扩 public 对外接口。

---

## 6. Token 结构建议

token 可以是 JWS / CBOR / protobuf + signature，但服务端必须能稳定解析。

建议逻辑字段：

```json
{
  "ver": 1,
  "provider": "oem_xxx",
  "issuedAt": 1713900000000,
  "expiresAt": 1713900300000,
  "nonce": "random",
  "challenge": "sha256(installId\\nsdkVersion\\nclientPublicKey)",
  "installId": "optional-or-hash",
  "app": {
    "packageName": "io.example.app",
    "signingCertSha256": "..."
  },
  "device": {
    "brand": "...",
    "model": "...",
    "osVersion": "...",
    "trustTier": "BASIC|DEVICE|STRONG"
  },
  "evidence": {
    "bootState": "...",
    "systemIntegrity": "...",
    "teeBacked": true
  },
  "sig": "..."
}
```

### 关键要求

1. `challenge` 必须与 handshake challenge 强绑定
2. token 必须短期有效
3. 必须带 replay 防护材料：
   - `nonce`
   - `issuedAt`
   - `expiresAt`
4. 必须能映射出服务端统一 trust tier

---

## 7. 服务端私有 verifier 设计

### 7.1 入口

在 private backend 中扩展 attestation verifier 分流：

- `play_integrity`
- `oem_attestation`
- `none`

建议新增：

```java
interface PrivateDeviceAttestationVerifier {
    Result verify(HandshakeRequest request);
}
```

### 7.2 `oem_attestation` 校验步骤

1. 解析 token
2. 校验签名 / 证书链 / provider identity
3. 校验 `issuedAt / expiresAt`
4. 校验 `challenge`
5. 校验 packageName / signingCert
6. 校验 replay（nonce / ticket / cache）
7. 生成统一结果：
   - accepted/rejected
   - provider
   - code
   - retryable
   - trust tier

### 7.3 建议错误码

- `OEM_ATTESTATION_PARSE_FAILED`
- `OEM_ATTESTATION_SIGNATURE_INVALID`
- `OEM_ATTESTATION_CHALLENGE_MISMATCH`
- `OEM_ATTESTATION_EXPIRED`
- `OEM_ATTESTATION_REPLAY_DETECTED`
- `OEM_ATTESTATION_APP_MISMATCH`
- `OEM_ATTESTATION_PROVIDER_UNTRUSTED`
- `OEM_ATTESTATION_DEVICE_UNTRUSTED`

---

## 8. Trust Tier 统一

为避免 provider 各说各话，服务端统一归一化到三档：

- `BASIC`
- `DEVICE`
- `STRONG`

### 映射原则

- `BASIC`：仅证明“环境有一定可信材料”，不能证明强硬件可信
- `DEVICE`：可证明真实设备/系统完整性到一定程度
- `STRONG`：具备硬件信任根/TEE/更强设备证明

不要把厂商原始字段直接暴露到 public API，统一在 private 风控内部消化。

---

## 9. 风控融合

### 9.1 新增 attestation posture

在风险引擎内部统一产出：

- `gms_attested`
- `oem_attested`
- `no_attestation`
- `attestation_failed`

### 9.2 风控原则

- `play_integrity + STRONG`：最低 uplift
- `oem_attestation + DEVICE/STRONG`：中低 uplift
- `oem_attestation + BASIC`：中等 uplift
- `no_attestation`：明显 uplift
- `attestation_failed`：高 uplift

### 9.3 与本地信号联动

无 GMS 设备建议额外放大以下信号权重：

- root / Magisk / KernelSU
- Frida / ptrace / hook
- Xposed / LSPosed
- emulator / unidbg
- installId / fingerprint 漂移
- account / IP / device cluster 异常

---

## 10. 灰度发布策略

### Stage 1

- 先放开 `no_attestation`
- 不阻断，只打标
- 观察误伤与通过率

### Stage 2

- 对无 GMS 设备启用 `oem_attestation`
- 先只接部分 ROM / 厂商 / 渠道

### Stage 3

- 按厂商/机型白名单放量
- 逐步提升 `attestation_failed` 的风险权重

---

## 11. 验收清单

### Android

- [ ] 无 GMS 设备可正常 `Leona.init`
- [ ] 无 GMS 设备可正常 `sense()`
- [ ] `oem_attestation` token 可被稳定生成
- [ ] provider 失败能稳定分类
- [ ] transport diagnostics 能看到 provider/code/retryable

### Server

- [ ] `oem_attestation` token 可被解析
- [ ] challenge mismatch 会拒绝
- [ ] expired token 会拒绝
- [ ] replay token 会拒绝
- [ ] trust tier 可稳定归一化
- [ ] 风控能区分 `play_integrity / oem_attestation / none`

### Ops

- [ ] 报表可看不同 attestation posture 占比
- [ ] 风控结果可按厂商 / ROM / 渠道拆分
- [ ] 可快速回滚到 `attestation optional`

---

## 12. 推荐实施顺序

1. **先上线 no-attestation fallback**
2. **再实现 private MainlandAttestationProvider**
3. **再实现 private `oem_attestation` verifier**
4. **最后做风险权重与灰度策略**

---

## 13. 收口结论

对于中国大陆无 GMS 设备，Leona 的正确落地方向不是把 public repo 扩成厂商 attestation 平台，而是：

> **public 保留可插拔接口与 fallback 路径，private 承接大陆 attestation 的真实实现。**

这与当前项目的收口策略一致：

- public = shell / sample / docs / fallback
- private = core detection / attestation / backend strategy

