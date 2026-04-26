# Mainland / non-GMS closeout summary

> Updated: 2026-04-25

This is the shortest operational summary for the mainland / non-GMS track.

## 1. Public repo: already in place

### SDK / sample

- public `AttestationProvider` plug point exists
- sample supports modes:
  - `off`
  - `debug_fake`
  - `bridge`
  - `oem_debug_fake`
  - `oem_bridge`
- sample OEM helper exists:
  - `/Users/a/back/Game/cq/leona-sdk-android/sample-app/src/main/kotlin/io/leonasec/leona/sample/SampleMainlandAttestation.kt`
- sample OEM bridge template exists:
  - `/Users/a/back/Game/cq/leona-sdk-android/sample-app/MAINLAND_ATTESTATION_BRIDGE_TEMPLATE.md`

### Server / routing

- public ingestion verifier supports `play_integrity`
- public ingestion verifier can route `oem_attestation` into the private verifier when installed
- public fallback path supports no-attestation mode when:
  - `LEONA_HANDSHAKE_ATTESTATION_REQUIRED=false`

### Public docs / gates

- design: `/Users/a/back/Game/cq/docs/mainland-non-gms-attestation-design.md`
- staging record: `/Users/a/back/Game/cq/docs/mainland-attestation-record-2026-04-25.md`
- acceptance: `/Users/a/back/Game/cq/docs/mainland-attestation-acceptance-checklist.md`
- risk posture: `/Users/a/back/Game/cq/docs/mainland-attestation-risk-posture.md`
- sample E2E: `/Users/a/back/Game/cq/leona-sdk-android/docs/mainland-attestation-e2e.md`
- release gate: `/Users/a/back/Game/cq/leona-sdk-android/docs/mainland-attestation-release-gate.md`

## 2. Private modules: still required before production-ready

### Android private side

Still requires a real OEM bridge/provider for the chosen mainland channel:

- Huawei / Xiaomi / Honor / Oppo / Vivo / enterprise channel SDK integration
- real token generation instead of `oem_debug_fake`
- packaging and secret handling outside the public repo

### Server private side

Still requires:

- real provider trust anchors / allowlists
- provider-specific confidence rules
- final trust-tier normalization rules
- final score uplift / downgrade weights
- tenant/channel overrides
- observability dashboards split by posture bucket

## 3. Current trust posture model

Publicly normalized to four buckets:

- `gms_attested`
- `oem_attested`
- `no_attestation`
- `attestation_failed`

Required invariant:

- `oem_attested` must not be merged into `gms_attested`
- `attestation_failed` must not be silently downgraded to `no_attestation`

## 4. Commands you can run now

### Build/install sample in mainland debug mode

```bash
LEONA_API_KEY=<appKey> \
LEONA_SAMPLE_ATTESTATION_MODE=oem_debug_fake \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-live-sample.sh
```

### Emulator E2E for mainland debug mode

```bash
export LEONA_HANDSHAKE_ATTESTATION_OEM_TRUSTED_PROVIDERS=sample_mainland_debug

ADB_SERIAL=emulator-5554 \
LEONA_API_KEY=<appKey> \
LEONA_SAMPLE_ATTESTATION_MODE=oem_debug_fake \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-attestation-e2e.sh
```

Latest record:

- `/Users/a/back/Game/cq/docs/mainland-attestation-record-2026-04-25.md`

### Fallback verification without attestation

```bash
export LEONA_HANDSHAKE_ATTESTATION_REQUIRED=false
```

Expected handshake status:

- `bound-hardware/binding-without-attestation`
- or `bound-software/binding-without-attestation`

## 5. Production-ready definition

Only call mainland / non-GMS support production-ready when all are true:

- [ ] real private OEM bridge is installed on Android side
- [ ] real private OEM verifier is installed on server side
- [ ] trusted providers are configured
- [ ] one real OEM path passes staging E2E
- [ ] risk/reporting can separate all four posture buckets
- [ ] fallback path to `no_attestation` is documented and tested

## 6. Recommended reading order

1. `/Users/a/back/Game/cq/docs/mainland-closeout-summary.md`
2. `/Users/a/back/Game/cq/docs/mainland-attestation-risk-posture.md`
3. `/Users/a/back/Game/cq/leona-sdk-android/docs/mainland-attestation-release-gate.md`
4. `/Users/a/back/Game/cq/docs/mainland-attestation-acceptance-checklist.md`
5. `/Users/a/back/Game/cq/docs/mainland-non-gms-attestation-design.md`
