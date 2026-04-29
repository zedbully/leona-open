/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona

import org.json.JSONArray
import org.json.JSONObject

/**
 * Debug/support export payload for internal QA and backend/security triage.
 */
data class LeonaSupportBundle(
    val generatedAtMillis: Long,
    val sdkVersion: String,
    val tenantId: String?,
    val appId: String,
    val region: String,
    val transportEnabled: Boolean,
    val cloudConfigEnabled: Boolean,
    val syncInit: Boolean,
    val effectiveDisabledSignals: Set<String>,
    val effectiveDisableCollectionWindowMs: Long,
    val effectiveTamperPolicy: Map<String, String>,
    val lastIntegritySnapshot: Map<String, String>,
    val cloudConfigFetchedAtMillis: Long?,
    val cloudConfigRawJson: String?,
    val secureTransport: LeonaSecureTransportSnapshot?,
    val diagnosticSnapshot: LeonaDiagnosticSnapshot,
    val serverVerdict: LeonaServerVerdict?,
) {
    fun toJsonObject(view: LeonaDebugExportView = LeonaDebugExportView.REDACTED): JSONObject = JSONObject()
        .put("generatedAtMillis", generatedAtMillis)
        .put("sdkVersion", sdkVersion)
        .put(
            "tenantId",
            if (view == LeonaDebugExportView.FULL_DEBUG) tenantId else LeonaJsonRedaction.hint(tenantId),
        )
        .put("appId", appId)
        .put("region", region)
        .put("transportEnabled", transportEnabled)
        .put("cloudConfigEnabled", cloudConfigEnabled)
        .put("syncInit", syncInit)
        .put("effectiveDisabledSignals", JSONArray(effectiveDisabledSignals.toList().sorted()))
        .put("effectiveDisableCollectionWindowMs", effectiveDisableCollectionWindowMs)
        .put(
            "effectiveTamperPolicy",
            if (view == LeonaDebugExportView.FULL_DEBUG) {
                effectiveTamperPolicy.toJsonObject()
            } else {
                LeonaJsonRedaction.stringMapSummary(effectiveTamperPolicy)
            },
        )
        .put(
            "lastIntegritySnapshot",
            if (view == LeonaDebugExportView.FULL_DEBUG) {
                lastIntegritySnapshot.toJsonObject()
            } else {
                LeonaJsonRedaction.stringMapSummary(lastIntegritySnapshot)
            },
        )
        .put("cloudConfigFetchedAtMillis", cloudConfigFetchedAtMillis)
        .put(
            "cloudConfigRaw",
            if (view == LeonaDebugExportView.FULL_DEBUG) {
                cloudConfigRawJson.toJsonValue()
            } else {
                LeonaJsonRedaction.rawJsonSummary(cloudConfigRawJson)
            },
        )
        .put("secureTransport", secureTransport?.toJsonObject(view))
        .put("diagnosticSnapshot", diagnosticSnapshot.toJsonObject(view))
        .put("serverVerdict", serverVerdict?.toJsonObject(view))

    fun toJson(view: LeonaDebugExportView = LeonaDebugExportView.REDACTED): String = toJsonObject(view).toString(2)

    private fun Map<String, String>.toJsonObject(): JSONObject = JSONObject().also { json ->
        toSortedMap().forEach { (key, value) -> json.put(key, value) }
    }

    private fun String?.toJsonValue(): Any? {
        if (this == null) return null
        return runCatching { JSONObject(this) }
            .recoverCatching { JSONArray(this) }
            .getOrElse { this }
    }
}
