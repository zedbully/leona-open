/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.sample

import io.leonasec.leona.LeonaDiagnosticSnapshot
import io.leonasec.leona.LeonaDebugExportView
import io.leonasec.leona.LeonaSecureTransportSnapshot
import io.leonasec.leona.LeonaSupportBundle
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

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

    fun toJsonObject(view: LeonaDebugExportView = LeonaDebugExportView.REDACTED): JSONObject = JSONObject()
        .put("generatedAtMillis", generatedAtMillis)
        .put("deviceId", redactIdentifier(deviceId, view))
        .put("diagnosticCanonical", redactIdentifier(diagnosticCanonical, view))
        .put("transportCanonical", redactIdentifier(transportCanonical, view))
        .put("verdictCanonical", redactIdentifier(verdictCanonical, view))
        .put("bundleCanonical", redactIdentifier(bundleCanonical, view))
        .put("aligned", aligned)
        .put(
            "mismatchedSurfaces",
            JSONArray(
                when (view) {
                    LeonaDebugExportView.FULL_DEBUG -> mismatchedSurfaces
                    LeonaDebugExportView.REDACTED -> mismatchedSurfaces.map { redactSurface(it) }
                },
            ),
        )
        .put("effectiveDisabledSignals", JSONArray(effectiveDisabledSignals.toList().sorted()))
        .put("effectiveDisableCollectionWindowMs", effectiveDisableCollectionWindowMs)
        .put("cloudConfigFetchedAtMillis", cloudConfigFetchedAtMillis)
        .put("cloudConfigRawPresent", cloudConfigRawPresent)
        .put("reportingEndpoint", redactEndpoint(reportingEndpoint, view))
        .put("cloudConfigEndpoint", redactEndpoint(cloudConfigEndpoint, view))
        .put("demoBackendEndpoint", redactEndpoint(demoBackendEndpoint, view))

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

internal object SampleJsonRedaction {
    fun hint(value: String?): Any {
        val text = value?.trim()?.takeIf { it.isNotEmpty() } ?: return JSONObject.NULL
        if (text.length <= 8) return "<redacted:${sha256Hex(text).take(8)}>"
        return "${text.take(4)}...${text.takeLast(4)}"
    }

    fun hash(value: String?): Any {
        val text = value?.trim()?.takeIf { it.isNotEmpty() } ?: return JSONObject.NULL
        return sha256Hex(text).take(16)
    }

    fun endpoint(value: String?): Any {
        val text = value?.trim()?.takeIf { it.isNotEmpty() } ?: return JSONObject.NULL
        return JSONObject()
            .put("present", true)
            .put("sha256", sha256Hex(text).take(16))
    }

    private fun sha256Hex(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }
}

private fun redactIdentifier(value: String?, view: LeonaDebugExportView): Any =
    when (view) {
        LeonaDebugExportView.FULL_DEBUG -> value ?: JSONObject.NULL
        LeonaDebugExportView.REDACTED -> SampleJsonRedaction.hint(value)
    }

private fun redactEndpoint(value: String?, view: LeonaDebugExportView): Any =
    when (view) {
        LeonaDebugExportView.FULL_DEBUG -> value ?: JSONObject.NULL
        LeonaDebugExportView.REDACTED -> SampleJsonRedaction.endpoint(value)
    }

private fun redactSurface(value: String): String {
    val surface = value.substringBefore(':', missingDelimiterValue = value)
    val identifier = value.substringAfter(':', missingDelimiterValue = "")
    val redacted = SampleJsonRedaction.hint(identifier)
    return if (identifier.isBlank()) surface else "$surface:$redacted"
}
