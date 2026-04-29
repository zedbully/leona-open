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
    val deviceEnvironmentEvidence: LeonaDeviceEnvironmentEvidence = LeonaDeviceEnvironmentEvidence.EMPTY,
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
    fun toJsonObject(view: LeonaDebugExportView = LeonaDebugExportView.REDACTED): JSONObject =
        when (view) {
            LeonaDebugExportView.FULL_DEBUG -> fullJsonObject()
            LeonaDebugExportView.REDACTED -> redactedJsonObject()
        }

    fun toJson(view: LeonaDebugExportView = LeonaDebugExportView.REDACTED): String = toJsonObject(view).toString(2)

    private fun fullJsonObject(): JSONObject = JSONObject()
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
        .put("deviceEnvironmentEvidence", deviceEnvironmentEvidence.toJsonObject(LeonaDebugExportView.FULL_DEBUG))
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

    private fun redactedJsonObject(): JSONObject = JSONObject()
        .put("deviceId", LeonaJsonRedaction.hint(deviceId))
        .put("installId", LeonaJsonRedaction.hint(installId))
        .put("canonicalDeviceId", LeonaJsonRedaction.hint(canonicalDeviceId))
        .put("fingerprintHash", LeonaJsonRedaction.hint(fingerprintHash))
        .put("packageName", packageName)
        .put("appVersionName", appVersionName)
        .put("appVersionCode", appVersionCode)
        .put("installerPackage", installerPackage)
        .put("androidIdPresent", !androidId.isNullOrBlank())
        .put("signingCertSha256", LeonaJsonRedaction.stringListHints(signingCertSha256))
        .put("localeTag", localeTag)
        .put("timeZoneId", timeZoneId)
        .put("screenSummary", screenSummary)
        .put("localRiskSignals", JSONArray(localRiskSignals.toList().sorted()))
        .put("deviceEnvironmentEvidence", deviceEnvironmentEvidence.toJsonObject(LeonaDebugExportView.REDACTED))
        .put("nativeRiskTags", JSONArray(nativeRiskTags.toList().sorted()))
        .put("nativeFindingIds", JSONArray(nativeFindingIds))
        .put("nativeHighestSeverity", nativeHighestSeverity)
        .put("nativeEventCount", nativeEventCount)
        .put("serverDecision", serverDecision)
        .put("serverAction", serverAction)
        .put("serverRiskLevel", serverRiskLevel)
        .put("serverRiskScore", serverRiskScore)
        .put("serverRiskTags", JSONArray(serverRiskTags.toList().sorted()))
        .put("lastBoxId", LeonaJsonRedaction.hint(lastBoxId))
}
