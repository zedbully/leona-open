# Device identity and evidence protocol sketch

This document captures the current **Leona Android client -> server** field
shape for the device identity, evidence, native facts, and server verdict path
used by the SDK.

It is intentionally a **practical integration draft**, not a formal RFC.

Core rule:

- The Android SDK collects and uploads evidence.
- The Android SDK does not make final allow/deny or risk decisions.
- `riskTags` are produced only by the server verdict path.
- Any client-supplied header evidence is `source=client_header`,
  `trust=low`, and must be treated as evidence/telemetry only.

---

## 1. Identity layers

Leona currently maintains three identity layers on-device:

1. **installId**
   - per-install stable UUID
   - persisted locally
   - used during secure handshake
   - never sent in public control-plane headers as raw identity

2. **resolvedDeviceId**
   - best currently-known device identifier
   - `T...` = temporary local derived device id
   - `L...` = canonical server-issued device id
   - sent to public/control-plane services as SHA-256 only

3. **fingerprintHash**
   - stable-ish hash over package / signer / androidId-or-installId /
     locale / timezone / model / selected signals
   - used as a correlation hint, not as a standalone business identifier

Canonical identity is server-owned. Client-provided canonical values, including
legacy raw headers, are claims at most; they are not identity authority.

---

## 2. Client-side sources

### Local identity and evidence snapshot

Current local snapshot is built from:

- package name
- app version
- installer package
- Android ID when allowed, only inside local derivation / hashed summaries
- signing cert SHA-256
- brand / model / manufacturer / sdkInt / abi
- locale / timezone / screen summary
- Java-side evidence signals
- device environment evidence such as build channel, bootloader, verified boot,
  GSI/Treble, custom ROM hints, and emulator/runtime facts

The public field names are:

- `evidenceSignals`
- `deviceEnvironmentEvidence`

Compatibility aliases may still exist in SDK APIs:

- `riskSignals` is deprecated and maps to client-side evidence.
- `localRiskSignals` is deprecated and maps to client-side evidence.

These aliases must not be interpreted as final risk decisions.

### Native fact summary

The native payload is decoded locally into:

- `nativeFindingIds`
- `nativeFactTags`
- `nativeHighestSeverity`

Examples:

- `runtime.frida.evidence`
- `runtime.mapping.memfd_executable`
- `runtime.mapping.deleted_executable`
- `environment.unidbg.runtime_fact`
- `tamper.manifest_or_code_fact`

Compatibility aliases may still exist in SDK APIs:

- `nativeRiskTags` is deprecated and maps to native fact tags.

Native fact tags are evidence. They become risk only if the server verdict
policy classifies them that way.

---

## 3. Cloud-config request fields

Current cloud-config requests send public routing and hashed identity headers:

- `X-Leona-App-Key`
- `X-Leona-Tenant`
- `X-Leona-App-Id`
- `X-Leona-Channel`
- `X-Leona-Device-Id-Sha256`
- `X-Leona-Install-Id-Sha256`
- `X-Leona-Fingerprint`
- `X-Leona-Canonical-Device-Id-Sha256`

The `*-Sha256` values are full lowercase 64-hex SHA-256 digests.

Cloud-config requests must not send:

- raw `X-Leona-Device-Id`
- raw `X-Leona-Install-Id`
- raw `X-Leona-Canonical-Device-Id`
- `X-Leona-Risk-Signals`
- `X-Leona-Native-Risk-Tags`

Cloud-config is a collection-policy control plane. It is not an identity
binding authority, and the SDK does not persist canonical device ids from
mobile-config body fields or headers. Canonical ids are only accepted from the
secure reporting handshake / sense response path.

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

And these response headers:

- `X-Leona-Disabled-Signals`
- `X-Leona-Disable-Collection-Window-Ms`

---

## 4. Handshake request sketch

The private secure reporting module should send identity claims, hashes, and
client evidence as structured data:

```json
{
  "clientPublicKey": "...",
  "installIdSha256": "...",
  "sdkVersion": "...",
  "deviceBinding": {
    "keyAlgorithm": "EC_P256",
    "publicKey": "...",
    "signatureAlgorithm": "SHA256withECDSA",
    "signature": "...",
    "hardwareBacked": true
  },
  "deviceIdentity": {
    "resolvedDeviceIdSha256": "...",
    "canonicalDeviceIdSha256": null,
    "fingerprintHash": "...",
    "evidenceSignals": ["root.su_or_busybox_path_present"],
    "deviceEnvironmentEvidence": {
      "derivedEvidence": ["verified_boot.green", "bootloader.locked"]
    },
    "nativeFactTags": ["runtime.mapping.memfd_executable"],
    "nativeFindingIds": ["injection.frida.known_library"],
    "nativeHighestSeverity": 3,
    "installerPackage": "com.android.vending",
    "signingCertSha256": ["..."],
    "sdkInt": 34
  }
}
```

Legacy fields, if a mixed-version client still sends them, have this meaning:

- `installId`, `resolvedDeviceId`, and `canonicalDeviceId` are client claims.
- `riskSignals` is a deprecated alias for `evidenceSignals`.
- `nativeRiskTags` is a deprecated alias for `nativeFactTags`.
- Server ingestion must mark these legacy client-originated values as
  `source=client_header` or equivalent client telemetry with `trust=low`,
  unless they are validated by the signed native payload or server policy.

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
- bind canonical identity to server-side session/device-binding state

---

## 5. Sense request fields

Current sense request sends secure headers:

- `X-Leona-App-Key`
- `X-Leona-Session-Id`
- `X-Leona-Request-Id`
- `X-Leona-Timestamp`
- `X-Leona-Nonce`
- `X-Leona-Signature`

And hashed identity / evidence headers:

- `X-Leona-Device-Id-Sha256`
- `X-Leona-Install-Id-Sha256`
- `X-Leona-Fingerprint`
- `X-Leona-Canonical-Device-Id-Sha256`
- `X-Leona-Evidence-Signals`
- `X-Leona-Native-Fact-Tags`
- `X-Leona-Native-Finding-Ids`
- `X-Leona-Native-Highest-Severity`

Body remains the encrypted native payload blob. The signed/encrypted payload is
the preferred source for native evidence provenance.

Sense requests must not use these old headers as authoritative signal paths:

- `X-Leona-Device-Id`
- `X-Leona-Install-Id`
- `X-Leona-Canonical-Device-Id`
- `X-Leona-Risk-Signals`
- `X-Leona-Native-Risk-Tags`

Legacy receivers may accept old headers for compatibility, but they must record
them as `source=client_header`, `trust=low` telemetry. Header-only poisoning
must not produce authoritative risk tags, block tags, reject actions, or
canonical identity updates.

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
- `authoritativeRiskTags`
- `telemetryRiskTags`
- `riskTagsBySource`
- `provenance`
- `policyExplanation`
- `verdict.decision`
- `verdict.action`
- `verdict.riskLevel`
- `verdict.riskScore`
- `verdict.riskTags`
- `risk.level`
- `risk.score`
- `risk.tags`

Only server verdict fields may populate final risk outputs. In particular:

- Top-level `riskTags` means server verdict risk tags.
- `authoritativeRiskTags` may include server policy and authoritative native
  payload classifications.
- `telemetryRiskTags` may include low-trust client header observations.
- `riskTagsBySource.client_header` is telemetry, not an action source.
- `provenance` records the scoring engine, scored timestamp, event source,
  event trust, and authoritative/telemetry tag split.
- `policyExplanation` records the server-side decision, action, risk level,
  score, reasons, contributing event ids, and authoritative event ids.

The SDK normalizes server outputs into:

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
  - device-binding keystore alias presence / public-key SHA-256 /
    hardware-backed hint
  - cached secure session expiry / canonical device id / tamper-policy presence
  - last attestation format + token SHA-256
  - last handshake timestamp / error

---

## 6. Normative server-side canonicalization strategy

The server must keep the identity authority chain narrow and fail closed:

1. trusted existing canonical mapping by the device-binding public-key hash
2. existing mapping by a server-issued canonical device id already bound to the
   authenticated session
3. otherwise mint a new canonical device id

Fingerprint observations, install history, signer/package continuity, and
client-provided identity claims may be retained as correlation evidence or
manual-review context. They must **not** select, recover, merge, or silently
rewrite a canonical identity. A fingerprint match is therefore never a
substitute for a verified binding plus provider-authoritative attestation.

Conflicting binding/fingerprint observations must fail closed into a durable
review path. Cache loss must recover from the durable binding authority, not
from a fingerprint cluster. Client raw identity headers are not part of the
authority chain; if a legacy client sends a raw canonical claim, store it only
as claimed-identity telemetry and compare it against server-bound canonical
state.

Recommended output:

- `canonicalDeviceId`
- `riskLevel`
- `riskScore`
- `riskTags`
- `action`

---

## 7. Fingerprint schema compatibility

The SDK exposes fingerprint diagnostics so identity changes can be explained
without exposing raw identifiers:

- `fingerprintSchemaVersion`
- `fingerprintSource`
- `identityAnchorSource`
- `canonicalDeviceIdSource`

Current schema values:

| Field | Value | Meaning |
| --- | --- | --- |
| `fingerprintSchemaVersion` | `4` | Cache/schema version for the local fingerprint snapshot. Cached snapshots with older versions are regenerated before reuse. |
| `fingerprintSource` | `base_device_v2` | Real-device/default seed. Uses the local identity anchor plus stable build/device profile fields. |
| `fingerprintSource` | `virtual_instance_anchor_v4` | Emulator/virtual-device seed. Adds a hashed virtual-instance anchor, including app-scoped Android ID when available, so same-image virtual machines can diverge while the same instance stays stable across reboot, clear-data, and same-signer reinstall. |
| `identityAnchorSource` | `android_id` | Android ID was usable as the local real-device identity anchor. |
| `identityAnchorSource` | `device_profile` | Android ID was unavailable, so the SDK fell back to stable device profile fields. Lower confidence. |
| `identityAnchorSource` | `virtual_instance_anchor` | A virtual/emulator instance anchor hash was available and used. |
| `canonicalDeviceIdSource` | `temporary_from_fingerprint` | The SDK has no server-persisted canonical yet; `resolvedDeviceId` is a temporary `T...` value derived from the fingerprint hash. |
| `canonicalDeviceIdSource` | `server_persisted` | The SDK has accepted and persisted a server-issued `L...` canonical id from the reporting path. |

Compatibility rules:

1. `fingerprintHash` is a correlation handle, not a customer-facing stable id.
   Business integrations should store and pass `boxId`, then have the backend
   query Leona evidence and cache the returned `canonicalDeviceId` if needed.
2. `canonicalDeviceId` is server-owned. Client-side `T...` ids and client
   canonical claims are temporary or telemetry only.
3. A schema version bump may change future `fingerprintHash` values. Server
   ingestion should treat the new hash as the current correlation handle while
   retaining old hash observations as historical aliases/evidence for the same
   device when existing server-side binding or tenant policy supports it.
4. Cached SDK snapshots are reused only when their schema version matches the
   current SDK cache schema and their persisted canonical id has not changed.
   Otherwise the SDK regenerates the snapshot.
5. Virtual/emulator devices should use `virtual_instance_anchor_v4` when a
   usable anchor exists. Placeholder anchors such as `unknown`,
   `02:00:00:00:00:00`, legacy constant Android ID `9774d56d682e549c`, or
   `<redacted>` must be ignored. Network MAC addresses are observations only and
   are never promoted into an identity anchor because they rotate on some AVDs.
6. If no usable virtual anchor exists, the SDK may fall back to
   `base_device_v2`; that should be treated as lower confidence for clone
   separation and recorded in test reports.

Migration guidance for release notes:

- Do not promise that `fingerprintHash` is immutable across SDK versions.
- Do promise that `canonicalDeviceId` is the stable server-facing id when
  server evidence has converged.
- When a release changes fingerprint schema, include the old/new schema number,
  source labels, and expected impact in the changelog.
- For emulator/virtual clone regressions, capture
  `fingerprintSchemaVersion`, `fingerprintSource`, `identityAnchorSource`, and
  canonical hint/hash in the support bundle before comparing devices.

---

## 8. Provenance and trust rules

Server ingestion should preserve provenance for every evidence or risk-related
item:

| Source | Trust | May affect final `riskTags`? | Notes |
| --- | --- | --- | --- |
| `server_policy` | authoritative | Yes | Tenant policy, server-side lookup, server-side correlation. |
| `native_payload` | authoritative when signed/encrypted and bound to session | Yes | Native evidence still needs policy classification. |
| `client_header` | low | No, telemetry only | Includes evidence/fact headers and all legacy risk headers. |
| `unknown` | low | No, telemetry only | Fail closed into telemetry until provenance is known. |

`X-Leona-Evidence-Signals` and `X-Leona-Native-Fact-Tags` are useful for
observability, debugging, and transition compatibility. They are not final
risk decisions by themselves.

---

## 9. Important client-side rule

The debug API:

- `Leona.getDiagnosticSnapshot()`
- `Leona.getDiagnosticSnapshotJson()`
- `Leona.getSupportBundle()`
- `Leona.getSupportBundleJson()`

is for **QA / observability only**.

Do **not** use:

- local evidence signals
- local native fact tags
- local native finding ids
- local severity
- deprecated local risk aliases

as your final in-app allow/deny decision. Final decisions should still come
from your backend using `BoxId` and the server verdict.
