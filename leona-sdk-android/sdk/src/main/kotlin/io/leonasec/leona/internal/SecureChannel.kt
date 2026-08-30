/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal

import android.content.Context
import android.util.Log
import io.leonasec.leona.BoxId
import io.leonasec.leona.BoxIdCallback
import io.leonasec.leona.LeonaServerVerdict
import io.leonasec.leona.BuildConstants
import io.leonasec.leona.LeonaSecureTransportSnapshot
import io.leonasec.leona.config.LeonaConfig
import io.leonasec.leona.crypto.LeonaCryptoEnvelopeCodec
import io.leonasec.leona.crypto.LeonaCryptoErrorCode
import io.leonasec.leona.crypto.LeonaCryptoHttpRequest
import io.leonasec.leona.crypto.LeonaCryptoProtectedHeadersCodec
import io.leonasec.leona.internal.spi.SecureDeviceContext
import io.leonasec.leona.internal.spi.SecureReportingErrorClassification
import io.leonasec.leona.internal.spi.SecureReportingErrorCode
import io.leonasec.leona.internal.spi.SecureReportingException
import io.leonasec.leona.internal.spi.SecureReportingErrorClassifier
import io.leonasec.leona.internal.spi.SecureUploadResult
import io.leonasec.leona.internal.proto.LeonaProtectedLogicalPayloadHandoff
import io.leonasec.leona.internal.proto.LeonaProtectedPayloadCarrierV1
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.UUID

internal class SecureChannel(
    private val context: Context,
    private val config: LeonaConfig,
    private val protectedPayloadEncoder: (LeonaProtectedLogicalPayloadHandoff) -> LeonaProtectedPayloadCarrierV1.EncodeResult =
        LeonaProtectedPayloadCarrierV1::encode,
) {

    suspend fun prepareTamperContext(): TamperContext {
        val effectivePolicy = resolveEffectiveTamperPolicy()
        return TamperContext(
            integritySnapshot = AppIntegrity.capture(context, effectivePolicy),
            policySnapshot = AppIntegrity.capturePolicy(effectivePolicy),
        )
    }

    suspend fun upload(payload: ByteArray, deviceContext: SecureDeviceContext): SecureUploadResult {
        return uploadInternal(payload, deviceContext, includeDeviceContextHeaders = true)
    }

    /**
     * Existing raw compatibility uploads retain their historical protected
     * context fields. Typed LPCARR01 uploads carry all evidence and opaque
     * identity references in the authenticated body, so no identity-derived
     * ad-hoc header is emitted on that path.
     */
    private suspend fun uploadInternal(
        payload: ByteArray,
        deviceContext: SecureDeviceContext,
        includeDeviceContextHeaders: Boolean,
    ): SecureUploadResult {
        if (!config.transportEnabled) {
            throw configurationError(
                SecureReportingErrorCode.TRANSPORT_DISABLED,
                "transport disabled",
            )
        }

        val endpoint = config.reportingEndpoint
            ?: throw configurationError(
                SecureReportingErrorCode.REPORTING_ENDPOINT_REQUIRED,
                "reporting endpoint required",
            )

        val apiKey = config.apiKey
            ?: throw configurationError(
                SecureReportingErrorCode.API_KEY_REQUIRED,
                "AppKey required",
            )

        val channel = config.cryptoChannel ?: throw SecureReportingException(
            classification = SecureReportingErrorClassification(
                code = SecureReportingErrorCode.SECURE_ENGINE_REQUIRED,
            ),
            message = "Leo crypto channel required: diagnostic=secure_engine_required, retryable=false",
        )

        val request = buildReportingRequest(
            endpoint = endpoint,
            apiKey = apiKey,
            payload = payload,
            deviceContext = deviceContext,
            includeDeviceContextHeaders = includeDeviceContextHeaders,
        )
        val result = try {
            LeonaCryptoHttpClient(
                channel = channel,
                endpointUrl = endpoint,
                certificatePins = config.certificatePins,
                callTimeoutSeconds = 10,
                connectTimeoutSeconds = 3,
                readTimeoutSeconds = 8,
            ).execute(request)
        } catch (error: IllegalArgumentException) {
            throw SecureReportingErrorClassifier.exception(
                operation = "sense()",
                classification = SecureReportingErrorClassification(SecureReportingErrorCode.UNKNOWN),
                detail = "leo_crypto_invalid_endpoint",
                cause = error,
            )
        }
        val response = when (result) {
            is io.leonasec.leona.crypto.LeonaCryptoResult.Success -> result.value
            is io.leonasec.leona.crypto.LeonaCryptoResult.Failure -> throw cryptoFailure(result)
        }
        if (response.statusCode !in 200..299) {
            val body = response.body.toString(StandardCharsets.UTF_8)
            val classification = SecureReportingErrorClassifier.classifyHttpFailure(
                statusCode = response.statusCode,
                errorBody = body,
            )
            throw SecureReportingErrorClassifier.exception(
                operation = "sense()",
                classification = classification,
                detail = SecureReportingErrorClassifier.httpFailureDetail(body),
            )
        }

        val protectedHeaders = try {
            LeonaCryptoProtectedHeadersCodec.decode(response.protectedHeaders)
        } catch (_: IllegalArgumentException) {
            throw SecureReportingErrorClassifier.exception(
                operation = "sense()",
                classification = SecureReportingErrorClassification(SecureReportingErrorCode.UNKNOWN),
                detail = "leo_crypto_invalid_response_headers",
            )
        }
        val body = response.body.toString(StandardCharsets.UTF_8)
        val json = try {
            JSONObject(body)
        } catch (_: Exception) {
            throw SecureReportingErrorClassifier.exception(
                operation = "sense()",
                classification = SecureReportingErrorClassification(SecureReportingErrorCode.UNKNOWN),
                detail = "leo_crypto_invalid_response_body",
            )
        }
        val verdict = parseServerVerdict(json, protectedHeaders)
        val boxId = verdict.boxId
            ?: throw SecureReportingErrorClassifier.exception(
                operation = "sense()",
                classification = SecureReportingErrorClassification(SecureReportingErrorCode.UNKNOWN),
                detail = "leo_crypto_response_missing_box_id",
            )
        val serverInstallId = firstMeaningful(
            json.optString("installId"),
            json.optString("install_id"),
            json.optString("serverInstallId"),
            json.optJSONObject("verdict")?.optString("installId"),
            protectedHeaders["X-Leona-Install-Id"],
        )?.takeIf(::isServerInstallId)

        return SecureUploadResult(
            boxId = BoxId.of(boxId),
            canonicalDeviceId = verdict.canonicalDeviceId,
            serverVerdict = verdict,
            serverInstallId = serverInstallId,
        )
    }

    /**
     * Wraps the canonical logical Protobuf handoff in one request-only LPCARR01
     * body before it reaches the existing Leo authenticated upload boundary.
     * Descriptor values are authenticated as carrier fields, never HTTP headers.
     */
    suspend fun uploadProtectedLogicalPayload(
        handoff: LeonaProtectedLogicalPayloadHandoff,
        deviceContext: SecureDeviceContext,
    ): SecureUploadResult {
        val carrier = when (val encoded = protectedPayloadEncoder(handoff)) {
            is LeonaProtectedPayloadCarrierV1.EncodeResult.Success -> encoded.bytes
            is LeonaProtectedPayloadCarrierV1.EncodeResult.Failure -> {
                val detail = if (encoded.code == LeonaProtectedPayloadCarrierV1.FailureCode.EXTERNAL_BLOCKED) {
                    "upstream payload handoff is externally blocked"
                } else {
                    "protected payload carrier encoding failed: ${encoded.code.name.lowercase()}"
                }
                throw SecureReportingErrorClassifier.exception(
                    operation = "protected_payload_upload",
                    classification = SecureReportingErrorClassification(
                        SecureReportingErrorCode.PROTECTED_PAYLOAD_CARRIER_UNAVAILABLE,
                    ),
                    detail = detail,
                )
            }
        }
        return uploadInternal(carrier, deviceContext, includeDeviceContextHeaders = false)
    }

    private fun buildReportingRequest(
        endpoint: String,
        apiKey: String,
        payload: ByteArray,
        deviceContext: SecureDeviceContext,
        includeDeviceContextHeaders: Boolean,
    ): LeonaCryptoHttpRequest {
        val url = endpoint.toHttpUrlOrNull()
            ?: throw IllegalArgumentException("encrypted endpoint must be an absolute URL")
        val headers = linkedMapOf(
            "X-Leona-App-Key" to apiKey,
            "X-Leona-Protocol" to LeonaCryptoEnvelopeCodec.PROTOCOL_MAJOR.toString(),
            "X-Leona-Reporting-Mode" to "leo_crypto",
            "X-Leona-SDK-Version" to BuildConstants.VERSION_NAME,
            "X-Leona-Request-Id" to UUID.randomUUID().toString(),
            "X-Leona-Evidence-Ref" to sha256Hex(payload),
        )
        if (includeDeviceContextHeaders) {
            headers["X-Leona-Device-Id-Sha256"] = sha256Hex(deviceContext.resolvedDeviceId)
            headers["X-Leona-Install-Id-Sha256"] = sha256Hex(deviceContext.installId)
            headers["X-Leona-Fingerprint"] = deviceContext.fingerprintHash
            deviceContext.sessionId
                ?.trim()
                ?.takeIf { it.isNotEmpty() }
                ?.let { headers["X-Leona-Session-Id-Sha256"] = sha256Hex(it) }
            headers["X-Leona-Identity-Protection"] =
                "${deviceContext.identityProtectionLevel}:${deviceContext.identityProtectionCode}:" +
                    (if (deviceContext.identityProtectionDurable) "durable" else "ephemeral") + ":" +
                    (if (deviceContext.identityProtectionRecoverable) "recoverable" else "terminal")
        }
        config.tenantId?.let { headers["X-Leona-Tenant"] = it }
        headers["X-Leona-App-Id"] = config.appId
        config.environment?.let { headers["X-Leona-Environment"] = it }
        config.channel?.let { headers["X-Leona-Channel"] = it }
        if (includeDeviceContextHeaders) {
            deviceContext.installLifecycleSha256?.let { headers["X-Leona-Install-Lifecycle-Sha256"] = it }
            deviceContext.canonicalDeviceId?.takeIf { it.isNotBlank() }?.let {
                headers["X-Leona-Canonical-Device-Id-Sha256"] = sha256Hex(it)
            }
            deviceContext.evidenceSignals
                .takeIf { it.isNotEmpty() }
                ?.let { headers["X-Leona-Evidence-Signals"] = it.sorted().joinToString(",").take(512) }
            deviceContext.nativeFactTags
                .takeIf { it.isNotEmpty() }
                ?.let { headers["X-Leona-Native-Fact-Tags"] = it.sorted().joinToString(",").take(512) }
            deviceContext.nativeFindingIds
                .takeIf { it.isNotEmpty() }
                ?.let { headers["X-Leona-Native-Finding-Ids"] = it.joinToString(",").take(512) }
            deviceContext.nativeHighestSeverity?.let { headers["X-Leona-Native-Highest-Severity"] = it.toString() }
        }
        return LeonaCryptoHttpRequest(
            method = "POST",
            authority = url.host + if (url.port != if (url.isHttps) 443 else 80) ":${url.port}" else "",
            path = "/v1/sense",
            contentType = "application/octet-stream",
            protectedHeaders = LeonaCryptoProtectedHeadersCodec.encode(headers),
            body = payload.copyOf(),
        )
    }

    private fun parseServerVerdict(
        json: JSONObject,
        protectedHeaders: Map<String, String>,
    ): LeonaServerVerdict {
        val nestedVerdict = json.optJSONObject("verdict")
        val nestedRisk = json.optJSONObject("risk")
        val boxId = firstMeaningful(
            json.optString("boxId"),
            nestedVerdict?.optString("boxId"),
            protectedHeaders["X-Leona-Box-Id"],
        )
        val decision = firstMeaningful(
            json.optString("decision"),
            nestedVerdict?.optString("decision"),
            protectedHeaders["X-Leona-Decision"],
        )
        val action = firstMeaningful(
            json.optString("action"),
            nestedVerdict?.optString("action"),
            nestedRisk?.optString("action"),
            protectedHeaders["X-Leona-Action"],
        )
        val riskLevel = firstMeaningful(
            json.optString("riskLevel"),
            nestedVerdict?.optString("riskLevel"),
            nestedRisk?.optString("level"),
            protectedHeaders["X-Leona-Risk-Level"],
        )
        val riskScore = sequenceOf(
            json.optInt("riskScore", Int.MIN_VALUE),
            nestedVerdict?.optInt("riskScore", Int.MIN_VALUE) ?: Int.MIN_VALUE,
            nestedRisk?.optInt("score", Int.MIN_VALUE) ?: Int.MIN_VALUE,
            protectedHeaders["X-Leona-Risk-Score"]?.toIntOrNull() ?: Int.MIN_VALUE,
        ).firstOrNull { it != Int.MIN_VALUE }
        val riskTags = buildSet {
            addAll(json.optStringArray("riskTags"))
            nestedVerdict?.let { addAll(it.optStringArray("riskTags")) }
            nestedRisk?.let { addAll(it.optStringArray("tags")) }
            protectedHeaders["X-Leona-Risk-Tags"]
                ?.split(',')
                ?.mapNotNull { it.trim().ifEmpty { null } }
                ?.let(::addAll)
        }
        return LeonaServerVerdict(
            boxId = boxId,
            canonicalDeviceId = firstMeaningful(
                json.optString("canonicalDeviceId"),
                nestedVerdict?.optString("canonicalDeviceId"),
                protectedHeaders["X-Leona-Canonical-Device-Id"],
            ),
            decision = decision,
            action = action,
            riskLevel = riskLevel,
            riskScore = riskScore,
            riskTags = riskTags,
        )
    }

    private fun cryptoFailure(
        failure: io.leonasec.leona.crypto.LeonaCryptoResult.Failure,
    ): SecureReportingException = SecureReportingErrorClassifier.exception(
        operation = "sense()",
        classification = SecureReportingErrorClassification(
            code = SecureReportingErrorCode.UNKNOWN,
        ),
        detail = "leo_crypto_${failure.code.name.lowercase()}",
    )

    private fun firstMeaningful(vararg values: String?): String? =
        values.firstOrNull { value ->
            value?.trim()?.takeIf { it.isNotEmpty() && !it.equals("null", ignoreCase = true) } != null
        }?.trim()

    private fun isServerInstallId(value: String): Boolean =
        value.matches(Regex("^I[0-9a-f]{32}$"))

    private fun sha256Hex(value: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun sha256Hex(value: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(value)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun configurationError(
        code: SecureReportingErrorCode,
        operation: String,
    ): SecureReportingException = SecureReportingException(
        classification = SecureReportingErrorClassification(code = code),
        message = "$operation: diagnostic=${code.wireValue}, retryable=false",
    )

    fun debugSnapshot(): LeonaSecureTransportSnapshot = LeonaSecureTransportSnapshot(
        engineAvailable = config.cryptoChannel != null,
        engineClassName = config.cryptoChannel?.let {
            "leo-crypto/${it.transport.capabilities.adapterVersion}"
        },
        endpointConfigured = !config.reportingEndpoint.isNullOrBlank(),
        apiKeyConfigured = !config.apiKey.isNullOrBlank(),
        attestationProviderConfigured = config.attestationProvider != null,
        deviceBinding = null,
        session = null,
        lastAttestation = null,
        lastHandshakeAtMillis = null,
        lastHandshakeError = null,
        lastHandshakeErrorClass = null,
        lastHandshakeErrorCode = null,
        lastHandshakeErrorProvider = null,
        lastHandshakeRetryable = null,
    )

    private suspend fun resolveEffectiveTamperPolicy(): TamperPolicy = config.toTamperPolicy()

    companion object {
        private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

        fun launchSense(callback: BoxIdCallback, block: suspend () -> BoxId) {
            scope.launch {
                try {
                    callback.onSuccess(block())
                } catch (t: Throwable) {
                    callback.onError(t)
                }
            }
        }

        fun launchFireAndForget(block: suspend () -> Unit) {
            scope.launch {
                runCatching { block() }
                    .onFailure { Log.w(TAG, "Background Leona task failed", it) }
            }
        }

        private const val TAG = "Leona"

        private fun parseServerTamperPolicy(jsonText: String): TamperPolicy {
            val json = runCatching { JSONObject(jsonText) }.getOrNull() ?: return TamperPolicy.EMPTY
            return TamperPolicy(
                expectedPackageName = json.optString("expectedPackageName").ifBlank { null },
                allowedInstallerPackages = json.optStringArray("allowedInstallerPackages"),
                allowedSigningCertSha256 = json.optStringArray("allowedSigningCertSha256")
                    .map { it.lowercase() }
                    .toSet(),
                expectedSigningCertificateLineageSha256 =
                    json.optString("expectedSigningCertificateLineageSha256").lowercase().ifBlank { null },
                expectedApkSigningBlockSha256 =
                    json.optString("expectedApkSigningBlockSha256").lowercase().ifBlank { null },
                expectedApkSigningBlockIdSha256 = json.optStringMap("expectedApkSigningBlockIdSha256"),
                expectedApkSha256 = json.optString("expectedApkSha256").lowercase().ifBlank { null },
                expectedNativeLibSha256 = json.optStringMap("expectedNativeLibSha256"),
                expectedManifestEntrySha256 = json.optString("expectedManifestEntrySha256").lowercase().ifBlank { null },
                expectedResourcesArscSha256 =
                    json.optString("expectedResourcesArscSha256").lowercase().ifBlank { null },
                expectedResourceInventorySha256 =
                    json.optString("expectedResourceInventorySha256").lowercase().ifBlank { null },
                expectedResourceEntrySha256 = json.optStringMap("expectedResourceEntrySha256"),
                expectedDexSha256 = json.optStringMap("expectedDexSha256"),
                expectedDexSectionSha256 = json.optStringMap("expectedDexSectionSha256"),
                expectedDexMethodSha256 = json.optStringMap("expectedDexMethodSha256"),
                expectedSplitApkSha256 = json.optStringMap("expectedSplitApkSha256"),
                expectedSplitInventorySha256 =
                    json.optString("expectedSplitInventorySha256").lowercase().ifBlank { null },
                expectedDynamicFeatureSplitSha256 =
                    json.optString("expectedDynamicFeatureSplitSha256").lowercase().ifBlank { null },
                expectedDynamicFeatureSplitNameSha256 =
                    json.optString("expectedDynamicFeatureSplitNameSha256").lowercase().ifBlank { null },
                expectedConfigSplitAxisSha256 =
                    json.optString("expectedConfigSplitAxisSha256").lowercase().ifBlank { null },
                expectedConfigSplitNameSha256 =
                    json.optString("expectedConfigSplitNameSha256").lowercase().ifBlank { null },
                expectedConfigSplitAbiSha256 =
                    json.optString("expectedConfigSplitAbiSha256").lowercase().ifBlank { null },
                expectedConfigSplitLocaleSha256 =
                    json.optString("expectedConfigSplitLocaleSha256").lowercase().ifBlank { null },
                expectedConfigSplitDensitySha256 =
                    json.optString("expectedConfigSplitDensitySha256").lowercase().ifBlank { null },
                expectedElfSectionSha256 = json.optStringMap("expectedElfSectionSha256"),
                expectedElfExportSymbolSha256 = json.optStringMap("expectedElfExportSymbolSha256"),
                expectedElfExportGraphSha256 = json.optStringMap("expectedElfExportGraphSha256"),
                expectedRequestedPermissionsSha256 =
                    json.optString("expectedRequestedPermissionsSha256").lowercase().ifBlank { null },
                expectedRequestedPermissionSemanticsSha256 =
                    json.optString("expectedRequestedPermissionSemanticsSha256").lowercase().ifBlank { null },
                expectedDeclaredPermissionSemanticsSha256 =
                    json.optString("expectedDeclaredPermissionSemanticsSha256").lowercase().ifBlank { null },
                expectedDeclaredPermissionFieldValues =
                    json.optStringMap("expectedDeclaredPermissionFieldValues", normalizeValues = false),
                expectedComponentSignatureSha256 = json.optStringMap("expectedComponentSignatureSha256"),
                expectedComponentAccessSemanticsSha256 =
                    json.optStringMap("expectedComponentAccessSemanticsSha256"),
                expectedComponentOperationalSemanticsSha256 =
                    json.optStringMap("expectedComponentOperationalSemanticsSha256"),
                expectedComponentFieldValues =
                    json.optStringMap("expectedComponentFieldValues", normalizeValues = false),
                expectedProviderUriPermissionPatternsSha256 =
                    json.optStringMap("expectedProviderUriPermissionPatternsSha256"),
                expectedProviderPathPermissionsSha256 =
                    json.optStringMap("expectedProviderPathPermissionsSha256"),
                expectedProviderAuthoritySetSha256 =
                    json.optStringMap("expectedProviderAuthoritySetSha256"),
                expectedProviderSemanticsSha256 =
                    json.optStringMap("expectedProviderSemanticsSha256"),
                expectedProviderAccessSemanticsSha256 =
                    json.optStringMap("expectedProviderAccessSemanticsSha256"),
                expectedProviderOperationalSemanticsSha256 =
                    json.optStringMap("expectedProviderOperationalSemanticsSha256"),
                expectedIntentFilterSha256 = json.optStringMap("expectedIntentFilterSha256"),
                expectedIntentFilterActionSha256 = json.optStringMap("expectedIntentFilterActionSha256"),
                expectedIntentFilterCategorySha256 = json.optStringMap("expectedIntentFilterCategorySha256"),
                expectedIntentFilterDataSha256 = json.optStringMap("expectedIntentFilterDataSha256"),
                expectedIntentFilterDataSchemeSha256 =
                    json.optStringMap("expectedIntentFilterDataSchemeSha256"),
                expectedIntentFilterDataAuthoritySha256 =
                    json.optStringMap("expectedIntentFilterDataAuthoritySha256"),
                expectedIntentFilterDataPathSha256 =
                    json.optStringMap("expectedIntentFilterDataPathSha256"),
                expectedIntentFilterDataMimeTypeSha256 =
                    json.optStringMap("expectedIntentFilterDataMimeTypeSha256"),
                expectedIntentFilterSemanticsSha256 =
                    json.optStringMap("expectedIntentFilterSemanticsSha256"),
                expectedGrantUriPermissionSha256 = json.optStringMap("expectedGrantUriPermissionSha256"),
                expectedGrantUriPermissionSemanticsSha256 =
                    json.optStringMap("expectedGrantUriPermissionSemanticsSha256"),
                expectedUsesFeatureSha256 =
                    json.optString("expectedUsesFeatureSha256").lowercase().ifBlank { null },
                expectedUsesFeatureNameSha256 =
                    json.optString("expectedUsesFeatureNameSha256").lowercase().ifBlank { null },
                expectedUsesFeatureRequiredSha256 =
                    json.optString("expectedUsesFeatureRequiredSha256").lowercase().ifBlank { null },
                expectedUsesFeatureGlEsVersionSha256 =
                    json.optString("expectedUsesFeatureGlEsVersionSha256").lowercase().ifBlank { null },
                expectedUsesFeatureFieldValues =
                    json.optStringMap("expectedUsesFeatureFieldValues", normalizeValues = false),
                expectedUsesSdkSha256 =
                    json.optString("expectedUsesSdkSha256").lowercase().ifBlank { null },
                expectedUsesSdkMinSha256 =
                    json.optString("expectedUsesSdkMinSha256").lowercase().ifBlank { null },
                expectedUsesSdkTargetSha256 =
                    json.optString("expectedUsesSdkTargetSha256").lowercase().ifBlank { null },
                expectedUsesSdkMaxSha256 =
                    json.optString("expectedUsesSdkMaxSha256").lowercase().ifBlank { null },
                expectedUsesSdkFieldValues =
                    json.optStringMap("expectedUsesSdkFieldValues", normalizeValues = false),
                expectedSupportsScreensSha256 =
                    json.optString("expectedSupportsScreensSha256").lowercase().ifBlank { null },
                expectedSupportsScreensSmallScreensSha256 =
                    json.optString("expectedSupportsScreensSmallScreensSha256").lowercase().ifBlank { null },
                expectedSupportsScreensNormalScreensSha256 =
                    json.optString("expectedSupportsScreensNormalScreensSha256").lowercase().ifBlank { null },
                expectedSupportsScreensLargeScreensSha256 =
                    json.optString("expectedSupportsScreensLargeScreensSha256").lowercase().ifBlank { null },
                expectedSupportsScreensXlargeScreensSha256 =
                    json.optString("expectedSupportsScreensXlargeScreensSha256").lowercase().ifBlank { null },
                expectedSupportsScreensResizeableSha256 =
                    json.optString("expectedSupportsScreensResizeableSha256").lowercase().ifBlank { null },
                expectedSupportsScreensAnyDensitySha256 =
                    json.optString("expectedSupportsScreensAnyDensitySha256").lowercase().ifBlank { null },
                expectedSupportsScreensRequiresSmallestWidthDpSha256 =
                    json.optString("expectedSupportsScreensRequiresSmallestWidthDpSha256")
                        .lowercase()
                        .ifBlank { null },
                expectedSupportsScreensCompatibleWidthLimitDpSha256 =
                    json.optString("expectedSupportsScreensCompatibleWidthLimitDpSha256")
                        .lowercase()
                        .ifBlank { null },
                expectedSupportsScreensLargestWidthLimitDpSha256 =
                    json.optString("expectedSupportsScreensLargestWidthLimitDpSha256")
                        .lowercase()
                        .ifBlank { null },
                expectedCompatibleScreensSha256 =
                    json.optString("expectedCompatibleScreensSha256").lowercase().ifBlank { null },
                expectedCompatibleScreensScreenSizeSha256 =
                    json.optString("expectedCompatibleScreensScreenSizeSha256").lowercase().ifBlank { null },
                expectedCompatibleScreensScreenDensitySha256 =
                    json.optString("expectedCompatibleScreensScreenDensitySha256").lowercase().ifBlank { null },
                expectedUsesLibrarySha256 =
                    json.optString("expectedUsesLibrarySha256").lowercase().ifBlank { null },
                expectedUsesLibraryNameSha256 =
                    json.optString("expectedUsesLibraryNameSha256").lowercase().ifBlank { null },
                expectedUsesLibraryRequiredSha256 =
                    json.optString("expectedUsesLibraryRequiredSha256").lowercase().ifBlank { null },
                expectedUsesLibraryFieldValues =
                    json.optStringMap("expectedUsesLibraryFieldValues", normalizeValues = false),
                expectedUsesLibraryOnlySha256 =
                    json.optString("expectedUsesLibraryOnlySha256").lowercase().ifBlank { null },
                expectedUsesLibraryOnlyNameSha256 =
                    json.optString("expectedUsesLibraryOnlyNameSha256").lowercase().ifBlank { null },
                expectedUsesLibraryOnlyRequiredSha256 =
                    json.optString("expectedUsesLibraryOnlyRequiredSha256").lowercase().ifBlank { null },
                expectedUsesNativeLibrarySha256 =
                    json.optString("expectedUsesNativeLibrarySha256").lowercase().ifBlank { null },
                expectedUsesNativeLibraryNameSha256 =
                    json.optString("expectedUsesNativeLibraryNameSha256").lowercase().ifBlank { null },
                expectedUsesNativeLibraryRequiredSha256 =
                    json.optString("expectedUsesNativeLibraryRequiredSha256").lowercase().ifBlank { null },
                expectedUsesNativeLibraryFieldValues =
                    json.optStringMap("expectedUsesNativeLibraryFieldValues", normalizeValues = false),
                expectedQueriesSha256 =
                    json.optString("expectedQueriesSha256").lowercase().ifBlank { null },
                expectedQueriesPackageSha256 =
                    json.optString("expectedQueriesPackageSha256").lowercase().ifBlank { null },
                expectedQueriesPackageNameSha256 =
                    json.optString("expectedQueriesPackageNameSha256").lowercase().ifBlank { null },
                expectedQueriesPackageSemanticsSha256 =
                    json.optString("expectedQueriesPackageSemanticsSha256").lowercase().ifBlank { null },
                expectedQueriesProviderSha256 =
                    json.optString("expectedQueriesProviderSha256").lowercase().ifBlank { null },
                expectedQueriesProviderAuthoritySha256 =
                    json.optString("expectedQueriesProviderAuthoritySha256").lowercase().ifBlank { null },
                expectedQueriesProviderSemanticsSha256 =
                    json.optString("expectedQueriesProviderSemanticsSha256").lowercase().ifBlank { null },
                expectedQueriesIntentSha256 =
                    json.optString("expectedQueriesIntentSha256").lowercase().ifBlank { null },
                expectedQueriesIntentActionSha256 =
                    json.optString("expectedQueriesIntentActionSha256").lowercase().ifBlank { null },
                expectedQueriesIntentCategorySha256 =
                    json.optString("expectedQueriesIntentCategorySha256").lowercase().ifBlank { null },
                expectedQueriesIntentDataSha256 =
                    json.optString("expectedQueriesIntentDataSha256").lowercase().ifBlank { null },
                expectedQueriesIntentDataSchemeSha256 =
                    json.optString("expectedQueriesIntentDataSchemeSha256").lowercase().ifBlank { null },
                expectedQueriesIntentDataAuthoritySha256 =
                    json.optString("expectedQueriesIntentDataAuthoritySha256").lowercase().ifBlank { null },
                expectedQueriesIntentDataPathSha256 =
                    json.optString("expectedQueriesIntentDataPathSha256").lowercase().ifBlank { null },
                expectedQueriesIntentDataMimeTypeSha256 =
                    json.optString("expectedQueriesIntentDataMimeTypeSha256").lowercase().ifBlank { null },
                expectedQueriesIntentSemanticsSha256 =
                    json.optString("expectedQueriesIntentSemanticsSha256").lowercase().ifBlank { null },
                expectedApplicationSemanticsSha256 =
                    json.optString("expectedApplicationSemanticsSha256").lowercase().ifBlank { null },
                expectedApplicationSecuritySemanticsSha256 =
                    json.optString("expectedApplicationSecuritySemanticsSha256").lowercase().ifBlank { null },
                expectedApplicationRuntimeSemanticsSha256 =
                    json.optString("expectedApplicationRuntimeSemanticsSha256").lowercase().ifBlank { null },
                expectedApplicationFieldValues =
                    json.optStringMap("expectedApplicationFieldValues", normalizeValues = false),
                expectedMetaDataType =
                    json.optStringMap("expectedMetaDataType"),
                expectedMetaDataValueSha256 =
                    json.optStringMap("expectedMetaDataValueSha256"),
                expectedManifestMetaDataEntrySha256 =
                    json.optStringMap("expectedManifestMetaDataEntrySha256"),
                expectedManifestMetaDataSemanticsSha256 =
                    json.optStringMap("expectedManifestMetaDataSemanticsSha256"),
                expectedMetaData = json.optStringMap("expectedMetaData", normalizeValues = false),
            )
        }

        private fun JSONObject.optStringArray(key: String): Set<String> =
            optJSONArray(key)?.let { array ->
                buildSet {
                    for (i in 0 until array.length()) {
                        val value = array.optString(i).trim()
                        if (value.isNotEmpty()) add(value)
                    }
                }
            }.orEmpty()

        private fun JSONObject.optStringMap(key: String, normalizeValues: Boolean = true): Map<String, String> =
            optJSONObject(key)?.let { obj ->
                buildMap {
                    val keys = obj.keys()
                    while (keys.hasNext()) {
                        val entryKey = keys.next().trim()
                        val rawValue = obj.optString(entryKey).trim()
                        if (entryKey.isNotEmpty() && rawValue.isNotEmpty()) {
                            put(entryKey, if (normalizeValues) rawValue.lowercase() else rawValue)
                        }
                    }
                }
            }.orEmpty()
    }
}
