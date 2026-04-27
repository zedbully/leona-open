# Mainland / non-GMS attestation release gate

This addendum narrows the release/closure path for mainland Android channels.

## 1. Scope

Use this gate when either of these is true:

- the build targets devices without Google Play services/framework
- the release relies on `oem_attestation`
- the release allows `no_attestation` as a temporary market fallback

## 2. Minimum closure path

### A. Static build gate

```bash
/Users/a/back/Game/cq/leona-sdk-android/scripts/verify-closure.sh
```

Required:

- `:sdk:testDebugUnitTest`
- `:sdk-private-core:assembleDebug`
- `:sample-app:assembleDebug`

### B. Sample mainland build/install path

```bash
LEONA_API_KEY=<appKey> \
LEONA_SAMPLE_ATTESTATION_MODE=oem_debug_fake \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-live-sample.sh
```

Required:

- sample builds without Google Play dependency
- sample can initialize and run with OEM-style token mode

### C. Emulator attestation summary E2E

```bash
export LEONA_HANDSHAKE_ATTESTATION_OEM_TRUSTED_PROVIDERS=sample_mainland_debug

ADB_SERIAL=emulator-5554 \
LEONA_API_KEY=<appKey> \
LEONA_SAMPLE_ATTESTATION_MODE=oem_debug_fake \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-attestation-e2e.sh
```

Required:

- `/v1/handshake` returns provider `sample_mainland_debug`
- attestation status is `oem_attestation/oem_attested`
- attestation code is `OEM_ATTESTATION_VERIFIED`
- sample transport/support-bundle surfaces match the handshake summary

Recorded local pass:

- `/Users/a/back/Game/cq/docs/mainland-attestation-record-2026-04-25.md`

### D. Fallback path validation

```bash
LEONA_HANDSHAKE_ATTESTATION_REQUIRED=false
```

Required:

- app still completes handshake with binding only
- status becomes `binding-without-attestation`
- rollout dashboards can distinguish fallback traffic from verified traffic

## 3. Real staging gate

Before calling mainland support ready, run at least one staging pass with a
real private OEM bridge:

- private Android provider installed
- private backend verifier installed
- trusted provider allowlist configured
- handshake accepted as `oem_attested`
- downstream decisioning reflects OEM posture instead of GMS posture

## 4. Stop conditions

Do not ship mainland attestation as ready if any is true:

- OEM verifier missing in the target environment
- trusted provider allowlist is empty or not configured
- `oem_debug_fake` is the only passing path
- verified OEM posture is merged with GMS posture in reporting
- failed OEM verification is silently treated as `no_attestation`
- fallback path is enabled but operations cannot quantify its traffic share

## 5. Related documents

- `/Users/a/back/Game/cq/docs/mainland-attestation-acceptance-checklist.md`
- `/Users/a/back/Game/cq/docs/mainland-attestation-record-2026-04-25.md`
- `/Users/a/back/Game/cq/docs/mainland-attestation-risk-posture.md`
- `/Users/a/back/Game/cq/leona-sdk-android/docs/mainland-attestation-e2e.md`
- `/Users/a/back/Game/cq/docs/mainland-non-gms-attestation-design.md`
