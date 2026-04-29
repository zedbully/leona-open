/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona

import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

enum class LeonaDebugExportView {
    REDACTED,
    FULL_DEBUG,
}

internal object LeonaJsonRedaction {
    fun hint(value: String?): Any {
        val text = value?.trim()?.takeIf { it.isNotEmpty() } ?: return JSONObject.NULL
        if (text.length <= 8) return "<redacted:${sha256Hex(text).take(8)}>"
        return "${text.take(4)}...${text.takeLast(4)}"
    }

    fun hash(value: String?): Any {
        val text = value?.trim()?.takeIf { it.isNotEmpty() } ?: return JSONObject.NULL
        return sha256Hex(text).take(16)
    }

    fun stringListHints(values: List<String>): JSONArray =
        JSONArray(values.map { hint(it) })

    fun rawJsonSummary(raw: String?): JSONObject = JSONObject().also { json ->
        val text = raw?.trim().orEmpty()
        json.put("present", text.isNotEmpty())
        if (text.isEmpty()) return@also
        json.put("sha256", sha256Hex(text).take(16))
        val parsedObject = runCatching { JSONObject(text) }.getOrNull()
        val parsedArray = runCatching { JSONArray(text) }.getOrNull()
        when {
            parsedObject != null -> {
                val keys = parsedObject.keys().asSequence().toList().sorted()
                json.put("type", "object")
                json.put("keys", JSONArray(keys))
            }
            parsedArray != null -> {
                json.put("type", "array")
                json.put("length", parsedArray.length())
            }
            else -> json.put("type", "string")
        }
    }

    fun stringMapSummary(values: Map<String, String>): JSONObject = JSONObject().also { json ->
        json.put("entryCount", values.size)
        json.put("keys", JSONArray(values.keys.sorted()))
        val valueHashes = JSONObject()
        values.toSortedMap().forEach { (key, value) ->
            valueHashes.put(key, sha256Hex(value).take(16))
        }
        json.put("valueSha256ByKey", valueHashes)
    }

    private fun sha256Hex(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }
}
