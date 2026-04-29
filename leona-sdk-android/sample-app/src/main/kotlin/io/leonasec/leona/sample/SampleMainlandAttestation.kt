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
 * - oem_debug_fake: emit a synthetic OEM attestation JSON token for local demo only
 * - oem_bridge: require the host app to install a real OEM attestation bridge
 */
object SampleMainlandAttestation {

    data class Request(
        val challenge: String,
        val installId: String,
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
        return when (mode) {
            MODE_OEM_DEBUG_FAKE -> {
                check(BuildConfig.DEBUG) { "oem_debug_fake attestation is only available in debug builds." }
                debugProvider(context)
            }
            MODE_OEM_BRIDGE -> bridgeProvider(context)
            else -> null
        }
    }

    private fun debugProvider(context: Context): AttestationProvider = object : AttestationProvider {
        override suspend fun attest(challenge: String, installId: String): AttestationStatement =
            AttestationStatement(
                format = OEM_ATTESTATION_FORMAT,
                token = buildDebugToken(
                    Request(
                        challenge = challenge,
                        installId = installId,
                        packageName = context.packageName,
                        manufacturer = Build.MANUFACTURER.orEmpty(),
                        brand = Build.BRAND.orEmpty(),
                        model = Build.MODEL.orEmpty(),
                        sdkInt = Build.VERSION.SDK_INT,
                        issuedAtMillis = System.currentTimeMillis(),
                    ),
                ),
            )
    }

    private fun bridgeProvider(context: Context): AttestationProvider? {
        val installed = bridge ?: return null
        return object : AttestationProvider {
            override suspend fun attest(challenge: String, installId: String): AttestationStatement? {
                val request = Request(
                    challenge = challenge,
                    installId = installId,
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

    internal fun buildDebugToken(request: Request): String = buildString {
        append('{')
        append("\"version\":1,")
        append("\"provider\":\"sample_mainland_debug\",")
        append("\"trustTier\":\"oem_attested\",")
        append("\"issuedAtMillis\":").append(request.issuedAtMillis).append(',')
        append("\"challenge\":\"").append(jsonEscape(request.challenge)).append("\",")
        append("\"installId\":\"").append(jsonEscape(request.installId)).append("\",")
        append("\"packageName\":\"").append(jsonEscape(request.packageName)).append("\",")
        append("\"evidenceLabels\":[\"debug_fake\",\"non_gms_sample\"],")
        append("\"claims\":{")
        append("\"manufacturer\":\"").append(jsonEscape(request.manufacturer)).append("\",")
        append("\"brand\":\"").append(jsonEscape(request.brand)).append("\",")
        append("\"model\":\"").append(jsonEscape(request.model)).append("\",")
        append("\"sdkInt\":\"").append(request.sdkInt).append("\"")
        append("},")
        append("\"mode\":\"oem_debug_fake\"")
        append('}')
    }

    private fun jsonEscape(value: String): String = buildString(value.length + 8) {
        value.forEach { ch ->
            when (ch) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> append(ch)
            }
        }
    }

    private const val OEM_ATTESTATION_FORMAT = "oem_attestation"
    private const val MODE_OEM_DEBUG_FAKE = "oem_debug_fake"
    private const val MODE_OEM_BRIDGE = "oem_bridge"
}
