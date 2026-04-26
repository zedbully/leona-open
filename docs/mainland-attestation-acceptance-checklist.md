# Mainland / Non-GMS attestation acceptance checklist

## Trust tiers

- `gms_attested`: Google Play Integrity verified
- `oem_attested`: mainland / OEM attestation verified through private backend
- `no_attestation`: device binding present but attestation intentionally omitted
- `attestation_failed`: attestation payload present but rejected / stale / malformed / unsupported

## Server rollout modes

### Mode A — public fallback only

Use when the app must run on devices without GMS and OEM attestation is not ready yet.

- client may omit `attestationProvider`
- server sets `LEONA_HANDSHAKE_ATTESTATION_REQUIRED=false`
- expected handshake status:
  - `bound-hardware/binding-without-attestation`
  - or `bound-software/binding-without-attestation`

Acceptance:

- [ ] secure handshake still succeeds
- [ ] `sense()` still uploads normally
- [ ] server can distinguish `no_attestation` from verified devices
- [ ] downstream risk policy treats `no_attestation` as degraded trust, not as verified trust

### Mode B — GMS verified

Use for Play-enabled distributions.

Acceptance:

- [ ] client sends `play_integrity`
- [ ] server returns attestation summary provider `play_integrity`
- [ ] server returns code `PLAY_INTEGRITY_VERIFIED`
- [ ] stale / challenge mismatch / weak device verdict are rejected

### Mode C — mainland OEM verified

Use for mainland / non-GMS distributions with the private OEM module installed.

Acceptance:

- [ ] client sends `oem_attestation`
- [ ] ingestion service can route to private OEM verifier
- [ ] private verifier validates challenge + installId + timestamp + provider trust
- [ ] server returns attestation summary provider `<oem_provider>`
- [ ] server returns code `OEM_ATTESTATION_VERIFIED`
- [ ] server normalizes status to `oem_attestation/oem_attested`
- [x] local staging pass recorded for `sample_mainland_debug`
  - `/Users/a/back/Game/cq/docs/mainland-attestation-record-2026-04-25.md`

### Mode D — attestation failed

Acceptance:

- [ ] malformed token returns `*_PARSE_FAILED`
- [ ] challenge mismatch returns `*_CHALLENGE_MISMATCH`
- [ ] stale token returns `*_STALE`
- [ ] unsupported / missing private verifier returns `OEM_ATTESTATION_VERIFIER_MISSING`
- [ ] rejection path increments handshake rejection metrics

## Final release gate

Only mark mainland non-GMS attestation as "ready" when all items below are true:

- [ ] public SDK can run without GMS dependency
- [ ] private Android provider is wired to the selected OEM stack
- [ ] private backend verifier is deployed with provider trust anchors / allowlist
- [ ] trusted OEM providers are configured via `leona.handshake.attestation.oem.trusted-providers` or `LEONA_HANDSHAKE_ATTESTATION_OEM_TRUSTED_PROVIDERS`
- [ ] at least one mainland OEM path passes end-to-end handshake in staging
- [ ] risk engine distinguishes `gms_attested`, `oem_attested`, `no_attestation`, `attestation_failed`
- [ ] operations docs define fallback behavior when OEM attestation service is degraded
