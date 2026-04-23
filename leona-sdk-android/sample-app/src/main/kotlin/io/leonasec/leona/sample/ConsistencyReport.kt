/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.sample

import io.leonasec.leona.LeonaDiagnosticSnapshot
import io.leonasec.leona.LeonaSecureTransportSnapshot
import io.leonasec.leona.LeonaSupportBundle
import org.json.JSONArray
import org.json.JSONObject

internal data class ConsistencyReport(
    val generatedAtMillis: Long,
    val deviceId: String,
    val diagnosticCanonical: String?,
    val transportCanonical: String?,
    val verdictCanonical: String?,
    val bundleCanonical: String?,
    val aligned: Boolean,
    val mismatchedSurfaces: List<String>,
    val effectiveDisabledSignals: Set<String>,
    val effectiveDisableCollectionWindowMs: Long,
    val cloudConfigFetchedAtMillis: Long?,
    val cloudConfigRawPresent: Boolean,
    val reportingEndpoint: String?,
    val cloudConfigEndpoint: String?,
    val demoBackendEndpoint: String?,
) {
    fun toJson(): String = toJsonObject().toString(2)

    fun toJsonObject(): JSONObject = JSONObject()
        .put("generatedAtMillis", generatedAtMillis)
        .put("deviceId", deviceId)
        .put("diagnosticCanonical", diagnosticCanonical)
        .put("transportCanonical", transportCanonical)
        .put("verdictCanonical", verdictCanonical)
        .put("bundleCanonical", bundleCanonical)
        .put("aligned", aligned)
        .put("mismatchedSurfaces", JSONArray(mismatchedSurfaces))
        .put("effectiveDisabledSignals", JSONArray(effectiveDisabledSignals.toList().sorted()))
        .put("effectiveDisableCollectionWindowMs", effectiveDisableCollectionWindowMs)
        .put("cloudConfigFetchedAtMillis", cloudConfigFetchedAtMillis)
        .put("cloudConfigRawPresent", cloudConfigRawPresent)
        .put("reportingEndpoint", reportingEndpoint)
        .put("cloudConfigEndpoint", cloudConfigEndpoint)
        .put("demoBackendEndpoint", demoBackendEndpoint)

    companion object {
        fun from(
            diagnostic: LeonaDiagnosticSnapshot,
            transport: LeonaSecureTransportSnapshot,
            bundle: LeonaSupportBundle,
            reportingEndpoint: String?,
            cloudConfigEndpoint: String?,
            demoBackendEndpoint: String?,
        ): ConsistencyReport {
            val surfaces = linkedMapOf(
                "diagnostic" to diagnostic.canonicalDeviceId,
                "transport" to transport.session?.canonicalDeviceId,
                "verdict" to bundle.serverVerdict?.canonicalDeviceId,
                "bundle" to bundle.diagnosticSnapshot.canonicalDeviceId,
            )
            val present = surfaces.values.filterNotNull().filter { it.isNotBlank() }.toSet()
            val aligned = present.size <= 1
            val mismatchedSurfaces = when {
                aligned -> emptyList()
                else -> surfaces.entries
                    .filter { !it.value.isNullOrBlank() }
                    .sortedBy { it.key }
                    .map { "${it.key}:${it.value}" }
            }
            return ConsistencyReport(
                generatedAtMillis = System.currentTimeMillis(),
                deviceId = diagnostic.deviceId,
                diagnosticCanonical = diagnostic.canonicalDeviceId,
                transportCanonical = transport.session?.canonicalDeviceId,
                verdictCanonical = bundle.serverVerdict?.canonicalDeviceId,
                bundleCanonical = bundle.diagnosticSnapshot.canonicalDeviceId,
                aligned = aligned,
                mismatchedSurfaces = mismatchedSurfaces,
                effectiveDisabledSignals = bundle.effectiveDisabledSignals,
                effectiveDisableCollectionWindowMs = bundle.effectiveDisableCollectionWindowMs,
                cloudConfigFetchedAtMillis = bundle.cloudConfigFetchedAtMillis,
                cloudConfigRawPresent = !bundle.cloudConfigRawJson.isNullOrBlank(),
                reportingEndpoint = reportingEndpoint,
                cloudConfigEndpoint = cloudConfigEndpoint,
                demoBackendEndpoint = demoBackendEndpoint,
            )
        }
    }
}
