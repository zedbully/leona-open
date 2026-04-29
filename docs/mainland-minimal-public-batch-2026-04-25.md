# Mainland minimal public batch — 2026-04-25

This file defines the smallest reasonable **public-safe mainland / non-GMS
batch** that can be separated from the current dirty tree.

## 1. Goal

The goal of this batch is:

- keep only mainland / non-GMS public shell work
- avoid mixing in broader runtime / tamper / workflow / baseline changes
- produce a reviewable public-safe commit set

This is a **batching guide**, not a statement that everything below is already
staged.

## 2. Refined split after mixed-file review

After a second pass over the dirty tree, the safest practical order is:

1. **Batch A0 — docs-only mainland closeout**
2. **Batch A1 — Android mainland sample clean adds**
3. **Batch A2 — server OEM routing shell**
4. **Batch A3 — mixed files that need partial staging or follow-up refactor**

Reason:

- `SampleApp.kt` is not mainland-only anymore because it also pulls in
  `LEONA_TENANT_ID`
- `run-live-sample.sh` now mixes mainland mode flags with local-server
  auto-provisioning, tenant, and verdict-secret wiring
- server OEM routing is still public-safe, but it depends on the expanded
  `DeviceAttestationVerifier.Result` shape and should be treated as its own
  review slice

## 3. Batch A0 — recommended first public-safe mainland batch

These files are the cleanest mainland/public-safe candidates and should go
first.

### New docs

- `/Users/a/back/Game/cq/docs/mainland-attestation-acceptance-checklist.md`
- `/Users/a/back/Game/cq/docs/mainland-attestation-risk-posture.md`
- `/Users/a/back/Game/cq/docs/mainland-closeout-summary.md`
- `/Users/a/back/Game/cq/docs/mainland-final-ops-checklist.md`
- `/Users/a/back/Game/cq/docs/final-release-inspection-2026-04-25.md`
- `/Users/a/back/Game/cq/docs/mainland-minimal-public-batch-2026-04-25.md`

### New Android sample / script / doc files

- `/Users/a/back/Game/cq/leona-sdk-android/docs/mainland-attestation-e2e.md`
- `/Users/a/back/Game/cq/leona-sdk-android/docs/mainland-attestation-release-gate.md`
- `/Users/a/back/Game/cq/leona-sdk-android/sample-app/MAINLAND_ATTESTATION_BRIDGE_TEMPLATE.md`
- `/Users/a/back/Game/cq/leona-sdk-android/sample-app/src/main/kotlin/io/leonasec/leona/sample/SampleMainlandAttestation.kt`
- `/Users/a/back/Game/cq/leona-sdk-android/sample-app/src/test/kotlin/io/leonasec/leona/sample/SampleMainlandAttestationTest.kt`
- `/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-attestation-e2e.sh`

## 4. Batch A1 — Android mainland clean adds

These files are still good public-safe mainland assets, but they do not fully
activate until a later wiring change lands:

- `/Users/a/back/Game/cq/leona-sdk-android/docs/mainland-attestation-e2e.md`
- `/Users/a/back/Game/cq/leona-sdk-android/docs/mainland-attestation-release-gate.md`
- `/Users/a/back/Game/cq/leona-sdk-android/sample-app/MAINLAND_ATTESTATION_BRIDGE_TEMPLATE.md`
- `/Users/a/back/Game/cq/leona-sdk-android/sample-app/src/main/kotlin/io/leonasec/leona/sample/SampleMainlandAttestation.kt`
- `/Users/a/back/Game/cq/leona-sdk-android/sample-app/src/test/kotlin/io/leonasec/leona/sample/SampleMainlandAttestationTest.kt`
- `/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-attestation-e2e.sh`

Recommended note for review:

- these are public shell / sample artifacts
- actual production OEM SDK bridge stays private
- `SampleApp.kt` wiring can follow in a separate mixed-file commit

## 5. Batch A2 — server OEM routing shell

These files are the smallest reviewable public server slice for OEM attestation
routing:

- `/Users/a/back/Game/cq/leona-server/ingestion-service/src/main/java/io/leonasec/server/ingestion/domain/OemAttestationVerifiers.java`
- `/Users/a/back/Game/cq/leona-server/ingestion-service/src/main/java/io/leonasec/server/ingestion/domain/PermissiveDeviceAttestationVerifier.java`
- `/Users/a/back/Game/cq/leona-server/ingestion-service/src/test/java/io/leonasec/server/ingestion/domain/PermissiveDeviceAttestationVerifierTest.java`
- `/Users/a/back/Game/cq/leona-server/ingestion-service/src/main/java/io/leonasec/server/ingestion/domain/DeviceAttestationVerifier.java`

Keep this batch independent from the broader handshake response /
canonical-device-id changes unless those are being reviewed together.

## 6. Batch A3 — mixed files to defer or partially stage

These files are the main reason the first batch should stay conservative:

- `/Users/a/back/Game/cq/leona-sdk-android/sample-app/src/main/kotlin/io/leonasec/leona/sample/SampleApp.kt`
  - mainland wiring is mixed with `LEONA_TENANT_ID`
- `/Users/a/back/Game/cq/leona-sdk-android/scripts/run-live-sample.sh`
  - mainland flags are mixed with local admin auto-create, tenant, and verdict
    secret wiring

Recommendation:

- **prefer deferring them**
- if they must land early, use `git add -p` and accept only mainland-specific
  hunks

## 7. Batch B — optional rollup docs after Batch A0

These files are useful, but they are rollup/status documents and can be split
into a second docs-only commit if you want a tighter first batch.

- `/Users/a/back/Game/cq/docs/README.md`
- `/Users/a/back/Game/cq/docs/acceptance-checklist.md`
- `/Users/a/back/Game/cq/docs/current-status.md`
- `/Users/a/back/Game/cq/docs/final-acceptance-summary.md`
- `/Users/a/back/Game/cq/leona-sdk-android/README.md`

Recommendation:

- Batch A0 first
- Batch B second only if the review needs the index/summary docs updated now

## 8. Keep out of the mainland batch for now

These changes should stay out of the first mainland batch because they broaden
scope too much.

### Existing larger docs/runtime/workflow changes

- `/Users/a/back/Game/cq/docs/demo-flow.md`
- `/Users/a/back/Game/cq/docs/detection-matrix.md`
- `/Users/a/back/Game/cq/docs/local-runbook.md`
- `/Users/a/back/Game/cq/.github/workflows/android.yml`
- `/Users/a/back/Game/cq/leona-sdk-android/docs/release-closure.md`
- `/Users/a/back/Game/cq/leona-sdk-android/sample-app/src/main/kotlin/io/leonasec/leona/sample/MainActivity.kt`
- `/Users/a/back/Game/cq/leona-sdk-android/sample-app/src/main/res/values/strings.xml`
- `/Users/a/back/Game/cq/leona-sdk-android/scripts/run-alpha-closure.sh`
- `/Users/a/back/Game/cq/leona-sdk-android/scripts/run-device-e2e.sh`
- `/Users/a/back/Game/cq/leona-sdk-android/scripts/run-emulator-e2e.sh`
- `/Users/a/back/Game/cq/leona-sdk-android/scripts/verify-closure.sh`
- `/Users/a/back/Game/cq/leona-sdk-android/sdk/...`
- `/Users/a/back/Game/cq/leona-server/README.md`
- `/Users/a/back/Game/cq/leona-server/common/...`
- `/Users/a/back/Game/cq/leona-server/openapi/...`
- `/Users/a/back/Game/cq/leona-server/ingestion-service/...` unrelated tamper baseline/config files

### Untracked but not required for the first mainland batch

- `/Users/a/back/Game/cq/docs/attestation-record-2026-04-25.md`
- `/Users/a/back/Game/cq/leona-sdk-android/scripts/resolve-local-leona-server-app-key.sh`
- `/Users/a/back/Game/cq/leona-server/common/src/main/java/io/leonasec/server/common/config/TamperBaselineSchema.java`
- `/Users/a/back/Game/cq/leona-server/common/src/test/java/io/leonasec/server/common/config/TamperBaselineSchemaTest.java`
- `/Users/a/back/Game/cq/leona-server/docs/examples/handshake-tamper-baseline.example.json`
- `/Users/a/back/Game/cq/leona-server/docs/handshake-tamper-baseline.md`
- `/Users/a/back/Game/cq/leona-server/ingestion-service/src/main/java/io/leonasec/server/ingestion/domain/TamperBaselineInfoContributor.java`
- `/Users/a/back/Game/cq/leona-server/ingestion-service/src/test/java/io/leonasec/server/ingestion/domain/TamperBaselineInfoContributorTest.java`
- `/Users/a/back/Game/cq/leona-server/ingestion-service/src/test/java/io/leonasec/server/ingestion/domain/TamperBaselineProviderTest.java`

## 9. Suggested staging command for Batch A0

```bash
cd /Users/a/back/Game/cq

git add \
  docs/mainland-attestation-acceptance-checklist.md \
  docs/mainland-attestation-risk-posture.md \
  docs/mainland-closeout-summary.md \
  docs/mainland-final-ops-checklist.md \
  docs/final-release-inspection-2026-04-25.md \
  docs/mainland-minimal-public-batch-2026-04-25.md
```

Then inspect:

```bash
git diff --cached --name-only
git diff --cached
```

## 10. Suggested staging commands for later batches

### Batch A1

```bash
git add \
  leona-sdk-android/docs/mainland-attestation-e2e.md \
  leona-sdk-android/docs/mainland-attestation-release-gate.md \
  leona-sdk-android/sample-app/MAINLAND_ATTESTATION_BRIDGE_TEMPLATE.md \
  leona-sdk-android/sample-app/src/main/kotlin/io/leonasec/leona/sample/SampleMainlandAttestation.kt \
  leona-sdk-android/sample-app/src/test/kotlin/io/leonasec/leona/sample/SampleMainlandAttestationTest.kt \
  leona-sdk-android/scripts/run-emulator-attestation-e2e.sh
```

### Batch A2

```bash
git add \
  leona-server/ingestion-service/src/main/java/io/leonasec/server/ingestion/domain/OemAttestationVerifiers.java \
  leona-server/ingestion-service/src/main/java/io/leonasec/server/ingestion/domain/PermissiveDeviceAttestationVerifier.java \
  leona-server/ingestion-service/src/test/java/io/leonasec/server/ingestion/domain/PermissiveDeviceAttestationVerifierTest.java \
  leona-server/ingestion-service/src/main/java/io/leonasec/server/ingestion/domain/DeviceAttestationVerifier.java
```

### Batch A3

```bash
git add -p leona-sdk-android/sample-app/src/main/kotlin/io/leonasec/leona/sample/SampleApp.kt
git add -p leona-sdk-android/scripts/run-live-sample.sh
```

Only accept hunks that are strictly mainland attestation related.

## 11. Suggested commit split

If you want cleaner history, split like this:

### Commit 1 — mainland public docs only

- all new mainland docs only

### Commit 2 — mainland sample/public SDK shell clean adds

- sample mainland helper/template
- mainland E2E docs/script

### Commit 3 — server public OEM routing shell

- `OemAttestationVerifiers.java`
- `PermissiveDeviceAttestationVerifier.java`
- `DeviceAttestationVerifier.java`
- related test

### Commit 4 — mixed-file follow-up

- partial `SampleApp.kt`
- partial `run-live-sample.sh`

## 12. Final note

At the current repo state, the safest path is:

1. stage Batch A0 only
2. verify cached diff is docs-only and mainland-only
3. commit Batch A0 if review looks clean
4. stage A1 and A2 separately
5. leave A3 mixed files for last

That keeps momentum without forcing the whole repo into one risky public batch.
