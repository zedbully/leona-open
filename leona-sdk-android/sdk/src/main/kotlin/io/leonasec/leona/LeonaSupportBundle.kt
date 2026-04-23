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
    fun toJsonObject(): JSONObject = JSONObject()
        .put("generatedAtMillis", generatedAtMillis)
        .put("sdkVersion", sdkVersion)
        .put("tenantId", tenantId)
        .put("appId", appId)
        .put("region", region)
        .put("transportEnabled", transportEnabled)
        .put("cloudConfigEnabled", cloudConfigEnabled)
        .put("syncInit", syncInit)
        .put("effectiveDisabledSignals", JSONArray(effectiveDisabledSignals.toList().sorted()))
        .put("effectiveDisableCollectionWindowMs", effectiveDisableCollectionWindowMs)
        .put("effectiveTamperPolicy", effectiveTamperPolicy.toJsonObject())
        .put("lastIntegritySnapshot", lastIntegritySnapshot.toJsonObject())
        .put("cloudConfigFetchedAtMillis", cloudConfigFetchedAtMillis)
        .put("cloudConfigRaw", cloudConfigRawJson.toJsonValue())
        .put("secureTransport", secureTransport?.toJsonObject())
        .put("diagnosticSnapshot", diagnosticSnapshot.toJsonObject())
        .put("serverVerdict", serverVerdict?.toJsonObject())

    fun toJson(): String = toJsonObject().toString(2)

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
