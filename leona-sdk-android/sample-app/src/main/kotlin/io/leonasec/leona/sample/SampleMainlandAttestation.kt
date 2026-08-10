/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.sample

import android.content.Context
import android.os.Build
import io.leonasec.leona.config.AttestationException
import io.leonasec.leona.config.AttestationFailureCodes
import io.leonasec.leona.config.AttestationProvider
import io.leonasec.leona.config.AttestationStatement

/**
 * Sample-app mainland / non-GMS attestation wiring.
 *
 * Modes are controlled by BuildConfig.LEONA_SAMPLE_ATTESTATION_MODE:
 * - oem_debug_fake: emit unsigned synthetic JSON for local collection/transport only;
 *   a production verifier must reject it
 * - oem_bridge: require the host app to install a real OEM attestation bridge
 */
object SampleMainlandAttestation {

    data class Request(
        val challenge: String,
        val installIdSha256: String,
        val packageName: String,
        val manufacturer: String,
        val brand: String,
        val model: String,
        val sdkInt: Int,
        val issuedAtMillis: Long,
    )

    /**
     * Host-app bridge for mainland OEM attestation.
     *
     * Real projects should call the selected OEM SDK here and return a raw JSON
     * token matching the `oem_attestation` envelope expected by the private
     * backend verifier.
     */
    fun interface Bridge {
        suspend fun requestToken(request: Request): String?
    }

    @Volatile
    private var bridge: Bridge? = null

    fun installBridge(bridge: Bridge?) {
        this.bridge = bridge
    }

    fun createProvider(context: Context): AttestationProvider? {
        val mode = BuildConfig.LEONA_SAMPLE_ATTESTATION_MODE.trim().lowercase()
        return SampleMainlandDebugAttestation.createProvider(context, mode)
            ?: when (mode) {
                MODE_OEM_BRIDGE -> bridgeProvider(context)
                else -> null
            }
    }

    private fun bridgeProvider(context: Context): AttestationProvider? {
        val installed = bridge ?: return null
        return object : AttestationProvider {
            override suspend fun attest(challenge: String, installId: String): AttestationStatement? {
                val request = Request(
                    challenge = challenge,
                    installIdSha256 = installId,
                    packageName = context.packageName,
                    manufacturer = Build.MANUFACTURER.orEmpty(),
                    brand = Build.BRAND.orEmpty(),
                    model = Build.MODEL.orEmpty(),
                    sdkInt = Build.VERSION.SDK_INT,
                    issuedAtMillis = System.currentTimeMillis(),
                )
                val token = try {
                    installed.requestToken(request)
                } catch (error: Throwable) {
                    throw if (error is AttestationException) {
                        error
                    } else {
                        AttestationException(
                            provider = OEM_ATTESTATION_FORMAT,
                            code = AttestationFailureCodes.ATTESTATION_PROVIDER_FAILED,
                            retryable = false,
                            message = error.message ?: error.javaClass.name,
                            cause = error,
                        )
                    }
                }?.trim()?.takeIf { it.isNotEmpty() } ?: return null

                return AttestationStatement(
                    format = OEM_ATTESTATION_FORMAT,
                    token = token,
                )
            }
        }
    }

    private const val OEM_ATTESTATION_FORMAT = "oem_attestation"
    private const val MODE_OEM_BRIDGE = "oem_bridge"
}
