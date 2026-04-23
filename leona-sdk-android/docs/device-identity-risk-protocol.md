# Device identity & risk protocol sketch

This document captures the current **Leona Android client → server** field
shape for the device identity / risk path that now exists in the SDK.

It is intentionally a **practical integration draft**, not a formal RFC.

---

## 1. Identity layers

Leona currently maintains three identity layers on-device:

1. **installId**
   - per-install stable UUID
   - persisted locally
   - used during secure handshake

2. **resolvedDeviceId**
   - best currently-known device identifier
   - `T...` = temporary local derived device id
   - `L...` = canonical server-issued device id

3. **fingerprintHash**
   - stable-ish hash over package / signer / androidId-or-installId /
     locale / timezone / model / selected signals
   - used as a correlation hint, not as a standalone business identifier

---

## 2. Client-side sources

### Local identity snapshot

Current local snapshot is built from:

- package name
- app version
- installer package
- Android ID (when allowed)
- signing cert SHA-256
- brand / model / manufacturer / sdkInt / abi
- locale / timezone / screen summary
- Java-side risk signals

### Native risk summary

The native payload is now decoded locally into:

- `nativeFindingIds`
- `nativeRiskTags`
- `nativeHighestSeverity`

Examples:

- `hook.frida.native`
- `hook.xposed.native`
- `environment.unidbg.native`
- `tamper.code_or_manifest.native`

---

## 3. Cloud-config request fields

Current cloud-config requests send headers:

- `X-Leona-App-Key`
- `X-Leona-Tenant`
- `X-Leona-App-Id`
- `X-Leona-Channel`
- `X-Leona-Device-Id`
- `X-Leona-Install-Id`
- `X-Leona-Fingerprint`
- `X-Leona-Risk-Signals`
- `X-Leona-Canonical-Device-Id`

### Cloud-config response fields

Current client supports these body fields:

- `disabledSignals`
- `disabledCollectors`
- `policy.disabledSignals`
- `policy.disabledCollectors`
- `config.disabledSignals`
- `config.disabledCollectors`
- `disableCollectionWindowMs`
- `disableCollectionWindow`
- `policy.disableCollectionWindowMs`
- `policy.disableCollectionWindow`
- `config.disableCollectionWindowMs`
- `config.disableCollectionWindow`
- `canonicalDeviceId`
- `deviceId`
- `device.canonicalDeviceId`
- `device.deviceId`
- `identity.canonicalDeviceId`
- `identity.deviceId`
- `deviceIdentity.canonicalDeviceId`
- `deviceIdentity.deviceId`
- `deviceIdentity.resolvedDeviceId`

And these response headers:

- `X-Leona-Canonical-Device-Id`
- `X-Leona-Device-Id`
- `X-Leona-Disabled-Signals`
- `X-Leona-Disable-Collection-Window-Ms`

---

## 4. Handshake request sketch

The private secure reporting module currently sends:

```json
{
  "clientPublicKey": "...",
  "installId": "...",
  "sdkVersion": "...",
  "deviceBinding": {
    "keyAlgorithm": "EC_P256",
    "publicKey": "...",
    "signatureAlgorithm": "SHA256withECDSA",
    "signature": "...",
    "hardwareBacked": true
  },
  "deviceIdentity": {
    "installId": "...",
    "resolvedDeviceId": "T...",
    "canonicalDeviceId": null,
    "fingerprintHash": "...",
    "riskSignals": ["root.basic"],
    "nativeRiskTags": ["environment.unidbg.native"],
    "nativeFindingIds": ["unidbg.parent.non_zygote"],
    "nativeHighestSeverity": 3,
    "installerPackage": "com.android.vending",
    "signingCertSha256": ["..."],
    "sdkInt": 34
  }
}
```

### Handshake response fields recognized by client

- `sessionId`
- `serverPublicKey`
- `tamperBaseline`
- `canonicalDeviceId`
- `device.canonicalDeviceId`
- `device.deviceId`
- `identity.canonicalDeviceId`
- `identity.deviceId`
- `deviceIdentity.canonicalDeviceId`
- `deviceIdentity.deviceId`
- `deviceIdentity.resolvedDeviceId`
- `deviceId`

Recommendation for server:

- always return a **canonical device id** once available
- keep it stable across app reinstalls when your server risk policy allows

---

## 5. Sense request fields

Current sense request sends secure headers:

- `X-Leona-App-Key`
- `X-Leona-Session-Id`
- `X-Leona-Request-Id`
- `X-Leona-Timestamp`
- `X-Leona-Nonce`
- `X-Leona-Signature`

And identity/risk headers:

- `X-Leona-Device-Id`
- `X-Leona-Install-Id`
- `X-Leona-Fingerprint`
- `X-Leona-Risk-Signals`
- `X-Leona-Canonical-Device-Id`
- `X-Leona-Native-Risk-Tags`
- `X-Leona-Native-Finding-Ids`
- `X-Leona-Native-Highest-Severity`

Body is still the encrypted native payload blob.

### Sense response fields recognized by client

- `boxId`
- `canonicalDeviceId`
- `device.canonicalDeviceId`
- `device.deviceId`
- `identity.canonicalDeviceId`
- `identity.deviceId`
- `deviceIdentity.canonicalDeviceId`
- `deviceIdentity.deviceId`
- `deviceIdentity.resolvedDeviceId`
- `deviceId`
- `decision`
- `action`
- `riskLevel`
- `riskScore`
- `riskTags`
- `verdict.decision`
- `verdict.action`
- `verdict.riskLevel`
- `verdict.riskScore`
- `verdict.riskTags`
- `risk.level`
- `risk.score`
- `risk.tags`

The SDK now normalizes these into:

- `Leona.getLastServerVerdict()`
- `Leona.getLastServerVerdictJson()`
- `Leona.getDiagnosticSnapshot()`
- `Leona.getSecureTransportSnapshot()`
- `Leona.getSecureTransportSnapshotJson()`
- `Leona.getSupportBundleJson()`

The support bundle currently includes:

- diagnostic snapshot
- standardized server verdict
- effective disabled-signal policy
- effective tamper baseline key/value snapshot
- last integrity snapshot key/value export
- cached cloud-config body + fetch timestamp
- secure transport state:
  - private-core availability
  - device-binding keystore alias presence / public-key SHA-256 / hardware-backed hint
  - cached secure session expiry / canonical device id / tamper-policy presence
  - last attestation format + token SHA-256
  - last handshake timestamp / error

---

## 6. Recommended server-side canonicalization strategy

Suggested priority:

1. trusted existing canonical mapping by device binding public key
2. existing mapping by resolved canonical device id
3. existing mapping by strong fingerprint cluster
4. existing mapping by install history + signer + package + risk continuity
5. otherwise mint new canonical device id

Recommended output:

- `canonicalDeviceId`
- `riskLevel`
- `riskScore`
- `riskTags`
- `action`

---

## 7. Important client-side rule

The debug API:

- `Leona.getDiagnosticSnapshot()`
- `Leona.getDiagnosticSnapshotJson()`
- `Leona.getSupportBundle()`
- `Leona.getSupportBundleJson()`

is for **QA / observability only**.

Do **not** use:

- local risk tags
- local native findings
- local severity

as your final in-app allow/deny decision. Final decisions should still come
from your backend using `BoxId`.
