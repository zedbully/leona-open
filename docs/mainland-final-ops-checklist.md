# Mainland / non-GMS final ops checklist

> Updated: 2026-04-25

This is the final operational checklist for the mainland / non-GMS track.

## 1. Open-source repo keeps

### Android / sample

- `AttestationProvider` public interface
- `play_integrity` public bridge path
- `oem_attestation` public routing shell
- sample modes:
  - `off`
  - `debug_fake`
  - `bridge`
  - `oem_debug_fake`
  - `oem_bridge`
- sample OEM helper/template docs

### Server / protocol

- binding + handshake contract
- attestation summary surface in handshake response
- optional bridge to private OEM verifier
- no-attestation fallback path

### Public docs

- design / acceptance / risk posture / E2E / release gate / closeout summary

## 2. Private repo/modules keep

### Android private

- real OEM SDK integrations
- provider-specific attestation token generation
- secret material / enterprise channel adaptation

### Server private

- real OEM verifier
- provider allowlist / trust anchors
- provider confidence tuning
- exact risk uplift weights
- tenant/channel-specific policy
- internal reporting / ops views by posture bucket

## 3. Release-before-ship commands

### A. Global preflight

```bash
/Users/a/back/Game/cq/scripts/release-preflight.sh --strict leona-sdk-android leona-server
```

### B. Public-only verification

```bash
# Android
cd /Users/a/back/Game/cq/leona-sdk-android
mv private /tmp/leona-android-private-backup
./gradlew :sdk:assembleDebug :sample-app:assembleDebug
mv /tmp/leona-android-private-backup private

# Server
cd /Users/a/back/Game/cq/leona-server
mv private /tmp/leona-server-private-backup
./gradlew build
mv /tmp/leona-server-private-backup private
```

### C. Private split verification

```bash
cd /Users/a/back/Game/cq
./scripts/verify-private-modules.sh
```

### D. Mainland sample path

```bash
LEONA_API_KEY=<appKey> \
LEONA_SAMPLE_ATTESTATION_MODE=oem_debug_fake \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-live-sample.sh
```

### E. Mainland emulator attestation E2E

```bash
export LEONA_HANDSHAKE_ATTESTATION_OEM_TRUSTED_PROVIDERS=sample_mainland_debug

ADB_SERIAL=emulator-5554 \
LEONA_API_KEY=<appKey> \
LEONA_SAMPLE_ATTESTATION_MODE=oem_debug_fake \
/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-attestation-e2e.sh
```

### F. Optional fallback verification

```bash
export LEONA_HANDSHAKE_ATTESTATION_REQUIRED=false
```

Expected status:

- `bound-hardware/binding-without-attestation`
- or `bound-software/binding-without-attestation`

## 4. Final release stop conditions

Do not call mainland support ready if any is true:

- trusted OEM provider list is empty
- OEM verifier is missing in the target env
- only `oem_debug_fake` has been validated
- `oem_attested` and `gms_attested` are merged in reporting
- `attestation_failed` is silently downgraded to `no_attestation`
- fallback traffic cannot be measured separately

## 5. Read this after this file

1. `/Users/a/back/Game/cq/docs/open-vs-private-final-matrix.md`
2. `/Users/a/back/Game/cq/docs/mainland-closeout-summary.md`
3. `/Users/a/back/Game/cq/docs/mainland-attestation-risk-posture.md`
4. `/Users/a/back/Game/cq/leona-sdk-android/docs/mainland-attestation-release-gate.md`
5. `/Users/a/back/Game/cq/docs/release-final-commands.md`
