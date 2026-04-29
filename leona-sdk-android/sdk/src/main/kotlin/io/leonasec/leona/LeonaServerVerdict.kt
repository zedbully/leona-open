/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona

import org.json.JSONArray
import org.json.JSONObject

data class LeonaServerVerdict(
    val boxId: String? = null,
    val canonicalDeviceId: String? = null,
    val decision: String? = null,
    val action: String? = null,
    val riskLevel: String? = null,
    val riskScore: Int? = null,
    val riskTags: Set<String> = emptySet(),
) {
    fun toJsonObject(view: LeonaDebugExportView = LeonaDebugExportView.REDACTED): JSONObject = JSONObject()
        .put(
            "boxId",
            if (view == LeonaDebugExportView.FULL_DEBUG) boxId else LeonaJsonRedaction.hint(boxId),
        )
        .put(
            "canonicalDeviceId",
            if (view == LeonaDebugExportView.FULL_DEBUG) canonicalDeviceId else LeonaJsonRedaction.hint(canonicalDeviceId),
        )
        .put("decision", decision)
        .put("action", action)
        .put("riskLevel", riskLevel)
        .put("riskScore", riskScore)
        .put("riskTags", JSONArray(riskTags.toList().sorted()))

    fun toJson(view: LeonaDebugExportView = LeonaDebugExportView.REDACTED): String = toJsonObject(view).toString(2)
}
