/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona

import org.json.JSONArray
import org.json.JSONObject

/**
 * Neutral device environment facts collected by the SDK.
 *
 * These fields are evidence for server-side verdict policy. Client code must
 * not treat any single value here as an allow/deny decision.
 */
data class LeonaDeviceEnvironmentEvidence(
    val evidenceIds: Set<String> = emptySet(),
    val build: Map<String, String> = emptyMap(),
    val bootloader: Map<String, String> = emptyMap(),
    val verifiedBoot: Map<String, String> = emptyMap(),
    val rom: Map<String, String> = emptyMap(),
    val gsi: Map<String, String> = emptyMap(),
) {
    fun toJsonObject(view: LeonaDebugExportView = LeonaDebugExportView.REDACTED): JSONObject = JSONObject()
        .put("evidenceIds", JSONArray(evidenceIds.toList().sorted()))
        .put("build", build.toJsonObject(view))
        .put("bootloader", bootloader.toJsonObject(view))
        .put("verifiedBoot", verifiedBoot.toJsonObject(view))
        .put("rom", rom.toJsonObject(view))
        .put("gsi", gsi.toJsonObject(view))

    internal fun toPersistedJsonObject(): JSONObject = toJsonObject(LeonaDebugExportView.FULL_DEBUG)

    companion object {
        val EMPTY = LeonaDeviceEnvironmentEvidence()

        internal fun fromJsonObject(obj: JSONObject?): LeonaDeviceEnvironmentEvidence {
            if (obj == null) return EMPTY
            return LeonaDeviceEnvironmentEvidence(
                evidenceIds = obj.optStringArray("evidenceIds").toSet(),
                build = obj.optStringMap("build"),
                bootloader = obj.optStringMap("bootloader"),
                verifiedBoot = obj.optStringMap("verifiedBoot"),
                rom = obj.optStringMap("rom"),
                gsi = obj.optStringMap("gsi"),
            )
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

        private fun JSONObject.optStringMap(key: String): Map<String, String> {
            val nested = optJSONObject(key) ?: return emptyMap()
            return buildMap {
                nested.keys().forEach { nestedKey ->
                    val value = nested.optString(nestedKey).trim()
                    if (value.isNotEmpty()) put(nestedKey, value)
                }
            }
        }
    }

    private fun Map<String, String>.toJsonObject(view: LeonaDebugExportView): JSONObject =
        when (view) {
            LeonaDebugExportView.FULL_DEBUG -> JSONObject().also { json ->
                toSortedMap().forEach { (key, value) -> json.put(key, value) }
            }
            LeonaDebugExportView.REDACTED -> LeonaJsonRedaction.stringMapSummary(this)
        }
}
