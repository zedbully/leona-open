/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.identity

import org.json.JSONArray
import org.json.JSONObject

internal data class DeviceFingerprintSnapshot(
    val generatedAtMillis: Long,
    val installId: String,
    val canonicalDeviceId: String?,
    val resolvedDeviceId: String,
    val fingerprintHash: String,
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
) {
    fun toJson(): String = JSONObject()
        .put("generatedAtMillis", generatedAtMillis)
        .put("installId", installId)
        .put("canonicalDeviceId", canonicalDeviceId)
        .put("resolvedDeviceId", resolvedDeviceId)
        .put("fingerprintHash", fingerprintHash)
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
        .toString()

    companion object {
        fun fromJson(json: String?): DeviceFingerprintSnapshot? {
            if (json.isNullOrBlank()) return null
            return runCatching {
                val obj = JSONObject(json)
                DeviceFingerprintSnapshot(
                    generatedAtMillis = obj.optLong("generatedAtMillis", 0L),
                    installId = obj.getString("installId"),
                    canonicalDeviceId = obj.optString("canonicalDeviceId").ifBlank { null },
                    resolvedDeviceId = obj.getString("resolvedDeviceId"),
                    fingerprintHash = obj.getString("fingerprintHash"),
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
