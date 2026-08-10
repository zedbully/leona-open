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

The production private verifier intentionally rejects this unsigned fixture.
Never add `sample_mainland_debug` to a production trusted-provider allowlist.

## 2. Real OEM bridge mode

Use this when your distribution channel relies on a mainland OEM attestation
SDK instead of Google Play Integrity.

```kotlin
class SampleApp : Application() {
    override fun onCreate() {
        SampleMainlandAttestation.installBridge(
            SampleMainlandAttestation.Bridge { request ->
                // 1. Call the selected OEM SDK and obtain its opaque proof.
                // 2. Send that proof plus request.challenge/installIdSha256/packageName
                //    to your private provider over an authenticated channel.
                // 3. The private provider verifies the OEM proof and returns a compact
                //    ES256 JWS. Return that JWS here.
                //
                // Never embed the provider signing key or a server SecretKey in the APK.
                exchangeWithYourPrivateProvider(request)
            }
        )
        super.onCreate()
    }

    private fun exchangeWithYourPrivateProvider(
        request: SampleMainlandAttestation.Request
    ): String = error("Implement the private OEM SDK/provider exchange")
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
installed and all trust inputs configured out of band:

- `leona.handshake.attestation.oem.trusted-providers`
- `leona.handshake.attestation.oem.provider-public-keys`
- `leona.handshake.attestation.oem.package-names`

Equivalent environment variables are:

```bash
LEONA_HANDSHAKE_ATTESTATION_OEM_TRUSTED_PROVIDERS
LEONA_HANDSHAKE_ATTESTATION_OEM_PROVIDER_PUBLIC_KEYS
LEONA_HANDSHAKE_ATTESTATION_OEM_PACKAGE_NAMES
```

Do not place real values in public source or documentation.

## 4. Expected handshake outcomes

- `oem_debug_fake`: local collection/transport fixture; production result is `OEM_ATTESTATION_AUTHENTICATION_REQUIRED`
- `oem_bridge`: produces `oem_attestation/oem_attested` only after signature, package, challenge, install, freshness, and upstream OEM evidence checks pass
- missing private verifier: `OEM_ATTESTATION_VERIFIER_MISSING`
- untrusted provider: `OEM_ATTESTATION_PROVIDER_UNTRUSTED`
- missing provider key: `OEM_ATTESTATION_KEY_NOT_CONFIGURED`
- unauthenticated upstream OEM evidence: `OEM_ATTESTATION_UPSTREAM_EVIDENCE_UNAUTHENTICATED`
