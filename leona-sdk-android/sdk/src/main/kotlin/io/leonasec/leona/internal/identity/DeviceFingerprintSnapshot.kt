/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.identity

import io.leonasec.leona.LeonaDeviceEnvironmentEvidence
import io.leonasec.leona.internal.ClientEvidenceSignalMapper
import org.json.JSONArray
import org.json.JSONObject

internal data class DeviceFingerprintSnapshot(
    val fingerprintSchemaVersion: Int = DeviceFingerprintHasher.CACHE_SCHEMA_VERSION,
    val generatedAtMillis: Long,
    val installId: String,
    val canonicalDeviceId: String?,
    val resolvedDeviceId: String,
    val fingerprintHash: String,
    val fingerprintSource: String = "unknown",
    val identityAnchorSource: String = "unknown",
    val canonicalDeviceIdSource: String = "unknown",
    val packageName: String,
    val appVersionName: String?,
    val appVersionCode: Long,
    val installerPackage: String?,
    val androidId: String?,
    val signingCertSha256: List<String>,
    val brand: String,
    val model: String,
    val manufacturer: String,
    val sdkInt: Int,
    val abis: List<String>,
    val localeTag: String,
    val timeZoneId: String,
    val screenSummary: String?,
    val riskSignals: Set<String>,
    val deviceEnvironmentEvidence: LeonaDeviceEnvironmentEvidence = LeonaDeviceEnvironmentEvidence.EMPTY,
    /** One-way app-install lifecycle handle used only for server install-id recovery. */
    val installLifecycleSha256: String? = null,
) {
    val evidenceSignals: Set<String>
        get() = ClientEvidenceSignalMapper.toEvidenceSignals(riskSignals)

    fun toJson(): String = JSONObject()
        .put("fingerprintSchemaVersion", fingerprintSchemaVersion)
        .put("generatedAtMillis", generatedAtMillis)
        .put("installId", installId)
        .put("canonicalDeviceId", canonicalDeviceId)
        .put("resolvedDeviceId", resolvedDeviceId)
        .put("fingerprintHash", fingerprintHash)
        .put("fingerprintSource", fingerprintSource)
        .put("identityAnchorSource", identityAnchorSource)
        .put("canonicalDeviceIdSource", canonicalDeviceIdSource)
        .put("packageName", packageName)
        .put("appVersionName", appVersionName)
        .put("appVersionCode", appVersionCode)
        .put("installerPackage", installerPackage)
        .put("androidId", androidId)
        .put("signingCertSha256", JSONArray(signingCertSha256))
        .put("brand", brand)
        .put("model", model)
        .put("manufacturer", manufacturer)
        .put("sdkInt", sdkInt)
        .put("abis", JSONArray(abis))
        .put("localeTag", localeTag)
        .put("timeZoneId", timeZoneId)
        .put("screenSummary", screenSummary)
        .put("riskSignals", JSONArray(riskSignals.toList().sorted()))
        .put("deviceEnvironmentEvidence", deviceEnvironmentEvidence.toPersistedJsonObject())
        .put("installLifecycleSha256", installLifecycleSha256)
        .toString()

    companion object {
        fun fromJson(json: String?): DeviceFingerprintSnapshot? {
            if (json.isNullOrBlank()) return null
            return runCatching {
                val obj = JSONObject(json)
                DeviceFingerprintSnapshot(
                    fingerprintSchemaVersion = obj.optInt("fingerprintSchemaVersion", 0),
                    generatedAtMillis = obj.optLong("generatedAtMillis", 0L),
                    installId = obj.getString("installId"),
                    canonicalDeviceId = obj.optString("canonicalDeviceId").ifBlank { null },
                    resolvedDeviceId = obj.getString("resolvedDeviceId"),
                    fingerprintHash = obj.getString("fingerprintHash"),
                    fingerprintSource = obj.optString("fingerprintSource").ifBlank { "unknown" },
                    identityAnchorSource = obj.optString("identityAnchorSource").ifBlank { "unknown" },
                    canonicalDeviceIdSource = obj.optString("canonicalDeviceIdSource").ifBlank { "unknown" },
                    packageName = obj.getString("packageName"),
                    appVersionName = obj.optString("appVersionName").ifBlank { null },
                    appVersionCode = obj.optLong("appVersionCode", 0L),
                    installerPackage = obj.optString("installerPackage").ifBlank { null },
                    androidId = obj.optString("androidId").ifBlank { null },
                    signingCertSha256 = obj.optStringArray("signingCertSha256"),
                    brand = obj.optString("brand"),
                    model = obj.optString("model"),
                    manufacturer = obj.optString("manufacturer"),
                    sdkInt = obj.optInt("sdkInt", 0),
                    abis = obj.optStringArray("abis"),
                    localeTag = obj.optString("localeTag"),
                    timeZoneId = obj.optString("timeZoneId"),
                    screenSummary = obj.optString("screenSummary").ifBlank { null },
                    riskSignals = obj.optStringArray("riskSignals").toSet(),
                    deviceEnvironmentEvidence = LeonaDeviceEnvironmentEvidence.fromJsonObject(
                        obj.optJSONObject("deviceEnvironmentEvidence"),
                    ),
                    installLifecycleSha256 = obj.optString("installLifecycleSha256").ifBlank { null },
                )
            }.getOrNull()
        }

        private fun JSONObject.optStringArray(key: String): List<String> =
            optJSONArray(key)?.let { array ->
                buildList {
                    for (index in 0 until array.length()) {
                        val value = array.optString(index).trim()
                        if (value.isNotEmpty()) add(value)
                    }
                }
            }.orEmpty()
    }
}
