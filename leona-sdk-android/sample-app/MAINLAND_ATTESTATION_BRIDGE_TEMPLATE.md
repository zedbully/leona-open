# Sample app mainland OEM attestation bridge template

This sample now supports two extra attestation modes through the existing
`LEONA_SAMPLE_ATTESTATION_MODE` flag:

- `oem_debug_fake`
- `oem_bridge`

## 1. Local demo mode

Use this when you want to exercise the non-GMS handshake flow without a real
OEM SDK yet.

```bash
./gradlew :sample-app:installDebug \
  -PLEONA_SAMPLE_ATTESTATION_MODE=oem_debug_fake \
  -PLEONA_API_KEY=demo \
  -PLEONA_REPORTING_ENDPOINT=https://your-server
```

This emits a synthetic token with:

- `format = oem_attestation`
- `provider = sample_mainland_debug`
- `trustTier = oem_attested`

Only use this for local testing.

## 2. Real OEM bridge mode

Use this when your distribution channel relies on a mainland OEM attestation
SDK instead of Google Play Integrity.

```kotlin
class SampleApp : Application() {
    override fun onCreate() {
        SampleMainlandAttestation.installBridge(
            SampleMainlandAttestation.Bridge { request ->
                // Replace this block with the selected OEM SDK call.
                // Return a raw JSON token shaped like the oem_attestation envelope.
                """
                {
                  "version": 1,
                  "provider": "huawei_safetyshield",
                  "trustTier": "oem_attested",
                  "issuedAtMillis": ${'$'}{request.issuedAtMillis},
                  "challenge": "${'$'}{request.challenge}",
                  "installId": "${'$'}{request.installId}",
                  "packageName": "${'$'}{request.packageName}",
                  "evidenceLabels": ["boot_locked", "tee_key"],
                  "claims": {
                    "manufacturer": "${'$'}{request.manufacturer}",
                    "model": "${'$'}{request.model}",
                    "sdkInt": "${'$'}{request.sdkInt}"
                  }
                }
                """.trimIndent()
            }
        )
        super.onCreate()
    }
}
```

Run with:

```bash
./gradlew :sample-app:installDebug \
  -PLEONA_SAMPLE_ATTESTATION_MODE=oem_bridge \
  -PLEONA_API_KEY=demo \
  -PLEONA_REPORTING_ENDPOINT=https://your-server
```

## 3. Server requirement

For real mainland OEM verification, the server must have the private verifier
installed and a trusted provider allowlist configured:

- `leona.handshake.attestation.oem.trusted-providers`
- or `LEONA_HANDSHAKE_ATTESTATION_OEM_TRUSTED_PROVIDERS`

Example:

```bash
export LEONA_HANDSHAKE_ATTESTATION_OEM_TRUSTED_PROVIDERS=huawei_safetyshield,xiaomi_guard
```

## 4. Expected handshake outcomes

- `oem_debug_fake`: useful only with permissive / staging verification
- `oem_bridge`: should produce server status like `oem_attestation/oem_attested`
- missing private verifier: `OEM_ATTESTATION_VERIFIER_MISSING`
- untrusted provider: `OEM_ATTESTATION_PROVIDER_UNTRUSTED`
