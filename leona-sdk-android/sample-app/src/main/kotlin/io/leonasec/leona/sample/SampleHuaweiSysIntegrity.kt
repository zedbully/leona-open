/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.sample

import android.content.Context
import io.leonasec.leona.config.AttestationException
import io.leonasec.leona.config.AttestationFailureCodes
import io.leonasec.leona.config.AttestationProvider
import io.leonasec.leona.config.AttestationStatement

/**
 * Optional Huawei SysIntegrity wiring for private domestic sample builds.
 *
 * The public sample compiles without the private module and without any HMS
 * runtime dependency. Selecting [MODE] is explicit and fail-closed: a missing
 * private provider or AppGallery app ID produces an attestation failure rather
 * than silently falling back to Play Integrity or no attestation.
 */
object SampleHuaweiSysIntegrity {
    fun createProvider(context: Context): AttestationProvider? = createProvider(
        context = context,
        mode = BuildConfig.LEONA_SAMPLE_ATTESTATION_MODE,
        appId = BuildConfig.LEONA_SAMPLE_HUAWEI_APP_ID,
    )

    internal fun createProvider(
        context: Context,
        mode: String,
        appId: String,
        providerClassName: String = PROVIDER_CLASS,
    ): AttestationProvider? {
        if (mode.trim().lowercase() != MODE) {
            return null
        }
        val normalizedAppId = appId.trim()
        if (!APP_ID.matches(normalizedAppId)) {
            return unavailable(CONFIGURATION_INVALID)
        }
        val provider = try {
            val providerClass = Class.forName(providerClassName)
            val constructor = providerClass.getConstructor(Context::class.java, String::class.java)
            constructor.newInstance(context, normalizedAppId) as? AttestationProvider
        } catch (_: Exception) {
            null
        } catch (_: LinkageError) {
            null
        }
        return provider ?: unavailable(PROVIDER_UNAVAILABLE)
    }

    private fun unavailable(reason: String): AttestationProvider = object : AttestationProvider {
        override suspend fun attest(challenge: String, installId: String): AttestationStatement? {
            throw AttestationException(
                provider = OEM_ATTESTATION_FORMAT,
                code = AttestationFailureCodes.ATTESTATION_PROVIDER_FAILED,
                retryable = false,
                message = reason,
            )
        }
    }

    internal const val MODE = "huawei_sysintegrity"
    internal const val PROVIDER_CLASS =
        "io.leonasec.leona.privatecore.attestation.HuaweiSysIntegrityAttestationProvider"
    private const val OEM_ATTESTATION_FORMAT = "oem_attestation"
    private const val CONFIGURATION_INVALID = "Huawei SysIntegrity sample configuration is unavailable"
    private const val PROVIDER_UNAVAILABLE = "Huawei SysIntegrity private provider is unavailable"
    private val APP_ID = Regex("[A-Za-z0-9._-]{1,128}")
}
