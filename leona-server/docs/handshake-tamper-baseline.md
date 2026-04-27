# Handshake tamper baseline

`ingestion-service` can attach an operator-supplied tamper baseline to
`POST /v1/handshake` responses through:

- env: `LEONA_HANDSHAKE_TAMPER_BASELINE_PATH`
- property: `leona.handshake.tamper-baseline-path`
- env: `LEONA_HANDSHAKE_TAMPER_BASELINE_JSON`
- property: `leona.handshake.tamper-baseline-json`

Recommended for production:

- use `..._PATH` / `tamper-baseline-path`

Recommended for ad-hoc local experiments:

- use `..._JSON` / `tamper-baseline-json`

The Android SDK merges this payload with local `LeonaConfig.Builder(...)`
baselines and prefers server-provided values on key collision.

## What the server enforces

At startup, `ingestion-service` validates the configured JSON against the
shared allowlist in:

- `/Users/a/back/Game/cq/leona-server/common/src/main/java/io/leonasec/server/common/config/TamperBaselineSchema.java`

Validation is strict:

- root must be a JSON object
- unknown fields are rejected
- each field must match one of:
  - `string`
  - `array<string>`
  - `object<string,string>`
- blank entries are trimmed and dropped
- configuring both `tamper-baseline-path` and `tamper-baseline-json` at the
  same time is rejected

If validation fails, the service exits during startup instead of serving a
bad handshake baseline.

## Operator example

Reference example:

- `/Users/a/back/Game/cq/leona-server/docs/examples/handshake-tamper-baseline.example.json`

APK-side fields can be generated from a built Android artifact:

```bash
/Users/a/back/Game/cq/leona-sdk-android/scripts/generate-tamper-baseline.py \
  /path/to/app-release.apk \
  --package-name com.example.app \
  --resource-entry res/raw/leona.bin \
  --dex-section classes.dex#code_item \
  > /etc/leona/handshake-tamper-baseline.json
```

`--dex-section ENTRY#SECTION` pins fine-grained DEX regions that the Android
SDK also verifies at runtime, for example `classes.dex#code_item` or
`classes.dex#class_defs`. Use `--all-dex-sections` only for strict release
pipelines where every section drift should be treated as a baseline update.

Load it into the service, for example:

```bash
export LEONA_HANDSHAKE_TAMPER_BASELINE_PATH=/Users/a/back/Game/cq/leona-server/docs/examples/handshake-tamper-baseline.example.json
```

Inline mode is still supported:

```bash
export LEONA_HANDSHAKE_TAMPER_BASELINE_JSON="$(tr -d '\n' < /Users/a/back/Game/cq/leona-server/docs/examples/handshake-tamper-baseline.example.json)"
```

## Runtime visibility

`ingestion-service` exposes a sanitized baseline summary via:

- `GET /actuator/info`

Field path:

- `handshakeTamperBaseline`

Example shape:

```json
{
  "handshakeTamperBaseline": {
    "sourceMode": "FILE",
    "sourcePath": "/etc/leona/handshake-tamper-baseline.json",
    "configured": true,
    "totalFieldCount": 14,
    "stringFieldCount": 7,
    "stringArrayFieldCount": 1,
    "stringMapFieldCount": 6,
    "configuredFields": [
      "allowedInstallerPackages",
      "expectedApplicationFieldValues",
      "expectedApplicationRuntimeSemanticsSha256",
      "expectedApplicationSecuritySemanticsSha256",
      "expectedApkSigningBlockIdSha256",
      "expectedApkSigningBlockSha256",
      "expectedComponentAccessSemanticsSha256",
      "expectedComponentOperationalSemanticsSha256",
      "expectedPackageName",
      "expectedProviderAccessSemanticsSha256",
      "expectedResourceEntrySha256",
      "expectedResourceInventorySha256",
      "expectedResourcesArscSha256",
      "expectedSigningCertificateLineageSha256"
    ]
  }
}
```

This endpoint is intended for ops confirmation only; it does not dump full
digest values back out.
