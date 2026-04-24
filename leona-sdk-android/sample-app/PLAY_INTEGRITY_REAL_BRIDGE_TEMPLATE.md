# Sample app Play Integrity real bridge template

This sample intentionally keeps Google Play Integrity as an **optional app-side dependency**.
Leona exposes `SamplePlayIntegrity.Bridge`, and the host app is responsible for:

1. creating a `StandardIntegrityManager`
2. warming up a `StandardIntegrityTokenProvider`
3. requesting tokens with `requestHash`
4. passing the raw token string back to Leona

## Official references

- Standard request guide: <https://developer.android.com/google/play/integrity/standard>
- API reference package: <https://developer.android.com/google/play/integrity/reference/com/google/android/play/core/integrity/package-summary>
- Error codes: <https://developer.android.com/google/play/integrity/error-codes>

## Suggested dependency

Add the Play Integrity library in the embedding app that wants real attestation:

```kotlin
dependencies {
    implementation("com.google.android.play:integrity:<latest>")
}
```

Use a current version that supports **standard requests** and `StandardIntegrityManager`.

For this sample project, you can enable the dependency directly with:

```bash
-PLEONA_SAMPLE_ENABLE_REAL_PLAY_INTEGRITY_DEP=true
```

## Recommended integration pattern

Install the bridge **before** `Leona.init(...)`.

```kotlin
package io.leonasec.leona.sample

import android.content.Context
import com.google.android.gms.tasks.Task
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityManager
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

class RealPlayIntegrityBridge(
    context: Context,
    private val cloudProjectNumber: Long,
) : SamplePlayIntegrity.Bridge {

    private val appContext = context.applicationContext
    private val standardIntegrityManager: StandardIntegrityManager =
        IntegrityManagerFactory.createStandard(appContext)

    @Volatile
    private var tokenProvider: StandardIntegrityManager.StandardIntegrityTokenProvider? = null

    suspend fun warmUp() {
        tokenProvider = standardIntegrityManager.prepareIntegrityToken(
            StandardIntegrityManager.PrepareIntegrityTokenRequest.builder()
                .setCloudProjectNumber(cloudProjectNumber)
                .build()
        ).await()
    }

    override suspend fun requestToken(
        request: io.leonasec.leona.config.PlayIntegrityTokenRequest
    ): String? {
        val provider = tokenProvider ?: synchronized(this) {
            tokenProvider
        } ?: run {
            warmUp()
            tokenProvider
        } ?: error("Play Integrity token provider unavailable after warm up")

        return try {
            provider.request(
                StandardIntegrityManager.StandardIntegrityTokenRequest.builder()
                    .setRequestHash(request.requestHash)
                    .build()
            ).await().token()
        } catch (error: Exception) {
            // Recommended retry path from Google's docs:
            // if the provider expired (for example INTEGRITY_TOKEN_PROVIDER_INVALID),
            // prepare a fresh provider and retry once.
            tokenProvider = null
            warmUp()
            tokenProvider?.request(
                StandardIntegrityManager.StandardIntegrityTokenRequest.builder()
                    .setRequestHash(request.requestHash)
                    .build()
            )?.await()?.token()
        }
    }
}

private suspend fun <T> Task<T>.await(): T = suspendCancellableCoroutine { continuation ->
    addOnSuccessListener { continuation.resume(it) }
    addOnFailureListener { continuation.resumeWithException(it) }
}
```

## SampleApp wiring

```kotlin
class SampleApp : Application() {
    override fun onCreate() {
        super.onCreate()

        SamplePlayIntegrity.installBridge(
            RealPlayIntegrityBridge(
                context = this,
                cloudProjectNumber = 1234567890123L,
            )
        )

        Leona.init(
            this,
            LeonaConfig.Builder()
                .attestationProvider(SamplePlayIntegrity.createProvider())
                .build()
        )
    }
}
```

Run the sample with:

```bash
-PLEONA_SAMPLE_ATTESTATION_MODE=bridge
-PLEONA_SAMPLE_ENABLE_REAL_PLAY_INTEGRITY_DEP=true
-PLEONA_SAMPLE_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER=1234567890123
```

## Important notes

- `requestHash` should be a digest of the request you want to protect, not raw sensitive data.
- Standard token providers can expire; refresh the provider on provider-invalid style errors.
- Warm up in advance to reduce latency on the actual protected action.
- On the server side, Leona already validates:
  - handshake challenge binding
  - timestamp freshness
  - app recognition verdict
  - minimum device integrity verdict
