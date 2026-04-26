# Mainland / non-GMS sample E2E

This runbook covers the public sample path for mainland / non-GMS attestation.

## 1. Build or install the sample directly

```bash
LEONA_API_KEY=<appKey> \
LEONA_SAMPLE_ATTESTATION_MODE=oem_debug_fake \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-live-sample.sh
```

Supported sample modes now include:

- `off`
- `debug_fake`
- `bridge`
- `oem_debug_fake`
- `oem_bridge`

## 2. Emulator handshake/UI E2E

For automated emulator validation, the supported modes are currently:

- `debug_fake`
- `oem_debug_fake`

### Play-style debug token

```bash
ADB_SERIAL=emulator-5554 \
LEONA_API_KEY=<appKey> \
LEONA_SAMPLE_ATTESTATION_MODE=debug_fake \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-attestation-e2e.sh
```

### Mainland OEM debug token

```bash
ADB_SERIAL=emulator-5554 \
LEONA_API_KEY=<appKey> \
LEONA_SAMPLE_ATTESTATION_MODE=oem_debug_fake \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-attestation-e2e.sh
```

Recorded pass:

- `/Users/a/back/Game/cq/docs/mainland-attestation-record-2026-04-25.md`

## 3. Backend requirement for OEM mode

When `LEONA_SAMPLE_ATTESTATION_MODE=oem_debug_fake`, the backend must satisfy
all of the following:

- private OEM verifier module installed
- `oem_attestation` routed by ingestion-service
- trusted provider allowlist includes `sample_mainland_debug`

Example:

```bash
export LEONA_HANDSHAKE_ATTESTATION_OEM_TRUSTED_PROVIDERS=sample_mainland_debug
```

## 4. Expected server/app outputs

### `debug_fake`

- provider: `play_integrity`
- status: `play_integrity/MEETS_DEVICE_INTEGRITY`
- code: `PLAY_INTEGRITY_VERIFIED`

### `oem_debug_fake`

- provider: `sample_mainland_debug`
- status: `oem_attestation/oem_attested`
- code: `OEM_ATTESTATION_VERIFIED`

The emulator E2E script verifies those values across:

- `/v1/handshake` response
- sample transport summary
- support bundle summary
- sample transport JSON
- support bundle JSON
