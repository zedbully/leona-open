/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal

import android.content.Context
import android.util.Log
import io.leonasec.leona.BoxId
import io.leonasec.leona.BoxIdCallback
import io.leonasec.leona.BuildConstants
import io.leonasec.leona.LeonaSecureTransportSnapshot
import io.leonasec.leona.config.LeonaConfig
import io.leonasec.leona.internal.spi.SecureDeviceContext
import io.leonasec.leona.internal.spi.SecureUploadResult
import io.leonasec.leona.internal.spi.SecureReportingEngine
import io.leonasec.leona.internal.spi.SecureReportingEngineLoader
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.IOException
import java.util.UUID

internal class SecureChannel(
    private val context: Context,
    private val config: LeonaConfig,
) {

    private val engine: SecureReportingEngine? by lazy {
        SecureReportingEngineLoader.load(
            context = context.applicationContext,
            config = config,
            sdkVersion = BuildConstants.VERSION_NAME,
        )
    }

    suspend fun prepareTamperContext(): TamperContext {
        val effectivePolicy = resolveEffectiveTamperPolicy()
        return TamperContext(
            integritySnapshot = AppIntegrity.capture(context, effectivePolicy),
            policySnapshot = AppIntegrity.capturePolicy(effectivePolicy),
        )
    }

    suspend fun upload(payload: ByteArray, deviceContext: SecureDeviceContext): SecureUploadResult {
        if (!config.transportEnabled) {
            return SecureUploadResult(BoxId.of(UUID.randomUUID().toString()))
        }

        val endpoint = config.reportingEndpoint
            ?: return SecureUploadResult(BoxId.of(UUID.randomUUID().toString()))

        val apiKey = config.apiKey
            ?: error("Leona.sense() requires apiKey when reportingEndpoint is set.")

        return engine?.upload(payload, deviceContext) ?: throw IOException(
            "Secure reporting for $endpoint requires the closed-source module :sdk-private-core on the runtime classpath (apiKey=$apiKey).",
        )
    }

    fun debugSnapshot(): LeonaSecureTransportSnapshot = engine?.debugSnapshot()
        ?: LeonaSecureTransportSnapshot(
            engineAvailable = false,
            engineClassName = null,
            endpointConfigured = !config.reportingEndpoint.isNullOrBlank(),
            apiKeyConfigured = !config.apiKey.isNullOrBlank(),
            attestationProviderConfigured = config.attestationProvider != null,
            deviceBinding = null,
            session = null,
            lastAttestation = null,
            lastHandshakeAtMillis = null,
            lastHandshakeError = null,
        )

    private suspend fun resolveEffectiveTamperPolicy(): TamperPolicy {
        val local = config.toTamperPolicy()
        config.reportingEndpoint ?: return local
        config.apiKey ?: return local
        val reportingEngine = engine ?: return local
        val remote = reportingEngine.resolveServerTamperBaselineJson()
            ?.takeIf { it.isNotBlank() }
            ?.let(::parseServerTamperPolicy)
            ?: TamperPolicy.EMPTY
        return local.merge(remote)
    }

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
                expectedApkSha256 = json.optString("expectedApkSha256").lowercase().ifBlank { null },
                expectedNativeLibSha256 = json.optStringMap("expectedNativeLibSha256"),
                expectedManifestEntrySha256 = json.optString("expectedManifestEntrySha256").lowercase().ifBlank { null },
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
                expectedGrantUriPermissionSha256 = json.optStringMap("expectedGrantUriPermissionSha256"),
                expectedUsesFeatureSha256 =
                    json.optString("expectedUsesFeatureSha256").lowercase().ifBlank { null },
                expectedUsesFeatureNameSha256 =
                    json.optString("expectedUsesFeatureNameSha256").lowercase().ifBlank { null },
                expectedUsesFeatureRequiredSha256 =
                    json.optString("expectedUsesFeatureRequiredSha256").lowercase().ifBlank { null },
                expectedUsesFeatureGlEsVersionSha256 =
                    json.optString("expectedUsesFeatureGlEsVersionSha256").lowercase().ifBlank { null },
                expectedUsesSdkSha256 =
                    json.optString("expectedUsesSdkSha256").lowercase().ifBlank { null },
                expectedUsesSdkMinSha256 =
                    json.optString("expectedUsesSdkMinSha256").lowercase().ifBlank { null },
                expectedUsesSdkTargetSha256 =
                    json.optString("expectedUsesSdkTargetSha256").lowercase().ifBlank { null },
                expectedUsesSdkMaxSha256 =
                    json.optString("expectedUsesSdkMaxSha256").lowercase().ifBlank { null },
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
                expectedQueriesSha256 =
                    json.optString("expectedQueriesSha256").lowercase().ifBlank { null },
                expectedQueriesPackageSha256 =
                    json.optString("expectedQueriesPackageSha256").lowercase().ifBlank { null },
                expectedQueriesPackageNameSha256 =
                    json.optString("expectedQueriesPackageNameSha256").lowercase().ifBlank { null },
                expectedQueriesProviderSha256 =
                    json.optString("expectedQueriesProviderSha256").lowercase().ifBlank { null },
                expectedQueriesProviderAuthoritySha256 =
                    json.optString("expectedQueriesProviderAuthoritySha256").lowercase().ifBlank { null },
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
                expectedApplicationSemanticsSha256 =
                    json.optString("expectedApplicationSemanticsSha256").lowercase().ifBlank { null },
                expectedApplicationFieldValues =
                    json.optStringMap("expectedApplicationFieldValues", normalizeValues = false),
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
