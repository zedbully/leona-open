/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona

import org.json.JSONArray
import org.json.JSONObject

/**
 * Debug-oriented local diagnostic view.
 *
 * This is intended for internal verification, QA, and sample/debug UI.
 * Do not make business allow/deny decisions on the client from these fields.
 */
data class LeonaDiagnosticSnapshot(
    val deviceId: String,
    val installId: String,
    val canonicalDeviceId: String?,
    val fingerprintHash: String,
    val packageName: String,
    val appVersionName: String?,
    val appVersionCode: Long,
    val installerPackage: String?,
    val androidId: String?,
    val signingCertSha256: List<String>,
    val localeTag: String,
    val timeZoneId: String,
    val screenSummary: String?,
    val localRiskSignals: Set<String>,
    val nativeRiskTags: Set<String>,
    val nativeFindingIds: List<String>,
    val nativeHighestSeverity: Int?,
    val nativeEventCount: Int,
    val serverDecision: String?,
    val serverAction: String?,
    val serverRiskLevel: String?,
    val serverRiskScore: Int?,
    val serverRiskTags: Set<String>,
    val lastBoxId: String?,
) {
    fun toJsonObject(): JSONObject = JSONObject()
        .put("deviceId", deviceId)
        .put("installId", installId)
        .put("canonicalDeviceId", canonicalDeviceId)
        .put("fingerprintHash", fingerprintHash)
        .put("packageName", packageName)
        .put("appVersionName", appVersionName)
        .put("appVersionCode", appVersionCode)
        .put("installerPackage", installerPackage)
        .put("androidId", androidId)
        .put("signingCertSha256", JSONArray(signingCertSha256))
        .put("localeTag", localeTag)
        .put("timeZoneId", timeZoneId)
        .put("screenSummary", screenSummary)
        .put("localRiskSignals", JSONArray(localRiskSignals.toList().sorted()))
        .put("nativeRiskTags", JSONArray(nativeRiskTags.toList().sorted()))
        .put("nativeFindingIds", JSONArray(nativeFindingIds))
        .put("nativeHighestSeverity", nativeHighestSeverity)
        .put("nativeEventCount", nativeEventCount)
        .put("serverDecision", serverDecision)
        .put("serverAction", serverAction)
        .put("serverRiskLevel", serverRiskLevel)
        .put("serverRiskScore", serverRiskScore)
        .put("serverRiskTags", JSONArray(serverRiskTags.toList().sorted()))
        .put("lastBoxId", lastBoxId)

    fun toJson(): String = toJsonObject().toString(2)
}
