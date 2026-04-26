# Mainland / non-GMS attestation risk posture

This document closes the policy gap between attestation transport and server
risk handling for mainland / non-GMS Android distributions.

## 1. Canonical posture buckets

Every handshake should be normalized into exactly one posture bucket:

| Posture | Meaning | Typical source |
|---|---|---|
| `gms_attested` | Verified by Play Integrity | `play_integrity` accepted |
| `oem_attested` | Verified by private mainland/OEM verifier | `oem_attestation` accepted |
| `no_attestation` | Device binding exists but no attestation attached | attestation optional fallback |
| `attestation_failed` | Attestation present but rejected / malformed / stale / unsupported | provider/verifier rejection |

## 2. Normalization rule

Suggested normalization order:

1. `play_integrity` verified -> `gms_attested`
2. `oem_attestation` verified -> `oem_attested`
3. binding present + no attestation payload + attestation optional -> `no_attestation`
4. any attestation rejection -> `attestation_failed`

Do not classify `no_attestation` as equivalent to verified trust.

## 3. Baseline risk treatment

| Posture | Trust level | Risk handling baseline | Suggested default action ceiling |
|---|---|---|---|
| `gms_attested` | highest | no extra uplift from posture alone | `allow` unless runtime risk is high |
| `oem_attested` | medium-high | small uplift or no uplift depending on provider confidence | `allow` / `challenge` |
| `no_attestation` | degraded | clear uplift versus verified devices | `challenge` |
| `attestation_failed` | low | aggressive uplift and anomaly tagging | `challenge` / `deny` |

## 4. Suggested scoring guidance

This is intentionally public-safe guidance. Exact weights should remain private.

### `gms_attested`

- no penalty by default
- only runtime detections / device identity anomalies raise score
- suitable for the lowest-friction path

### `oem_attested`

- keep lower trust than strong GMS attestation unless the private verifier has
  high confidence in the specific provider
- allow provider-specific private uplift/downlift in closed-source policy
- recommended public stance: treat as verified, but not as strongest verified

### `no_attestation`

- always mark with a posture tag such as `trust.no_attestation`
- apply a stable uplift versus verified devices
- keep product usable where market coverage matters, but avoid premium trust
  decisions based only on device binding

### `attestation_failed`

- always tag explicit failure reason family
- rejection reason should stay visible in telemetry and support bundle
- apply larger uplift than `no_attestation`
- if combined with root / injection / repackaging signals, default toward deny

## 5. Suggested decision mapping

| Posture | Low runtime risk | Medium runtime risk | High runtime risk |
|---|---|---|---|
| `gms_attested` | allow | allow/challenge | challenge/deny |
| `oem_attested` | allow | challenge | challenge/deny |
| `no_attestation` | challenge | challenge | deny |
| `attestation_failed` | challenge | deny | deny |

This table is a release baseline, not a hard protocol rule.

## 6. Telemetry requirements

At minimum, internal telemetry should preserve:

- normalized posture bucket
- attestation provider
- attestation status
- attestation code
- retryable flag
- decision / risk level / risk score after posture adjustment

Recommended tag families:

- `trust.gms_attested`
- `trust.oem_attested`
- `trust.no_attestation`
- `trust.attestation_failed`

## 7. Operational fallback policy

If the mainland OEM attestation service is degraded:

### acceptable temporary downgrade

- move from `oem_attested` path to `no_attestation`
- keep device binding required
- explicitly mark degraded trust in metrics / reports

### unacceptable silent downgrade

- silently reclassifying failed OEM verification as verified
- silently dropping provider allowlist checks
- treating malformed OEM payloads as `no_attestation`

## 8. Public vs private split

### Public repo should keep

- posture vocabulary
- acceptance / release checklists
- sample demo modes
- optional routing into private verifier
- conservative baseline guidance

### Private modules should keep

- real OEM provider integrations
- provider trust anchors / allowlists
- provider-specific confidence downgrades
- exact risk score weights / escalation rules
- tenant/channel-specific overrides

## 9. Release gate for posture policy

Do not mark mainland non-GMS support as production-ready until all are true:

- [ ] posture normalization is stable across `gms_attested / oem_attested / no_attestation / attestation_failed`
- [ ] dashboards can separate those four buckets
- [ ] `oem_attested` is not merged into `gms_attested`
- [ ] `attestation_failed` is not downgraded to `no_attestation`
- [ ] one real mainland OEM path has passed staging E2E
- [ ] rollback path to `no_attestation` is documented and tested
