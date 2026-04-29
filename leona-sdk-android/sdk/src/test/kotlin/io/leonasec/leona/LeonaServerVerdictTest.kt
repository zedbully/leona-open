/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class LeonaServerVerdictTest {

    @Test
    fun `server verdict serializes to json`() {
        val verdict = LeonaServerVerdict(
            boxId = "box-1",
            canonicalDeviceId = "Lcanon",
            decision = "allow",
            action = "allow",
            riskLevel = "LOW",
            riskScore = 8,
            riskTags = setOf("trusted.device", "known.install"),
        )

        val json = verdict.toJson(LeonaDebugExportView.FULL_DEBUG)
        val obj = JSONObject(json)

        assertEquals("box-1", obj.getString("boxId"))
        assertEquals("LOW", obj.getString("riskLevel"))
        assertEquals(8, obj.getInt("riskScore"))
        assertTrue(json.contains("\n"))

        val redacted = JSONObject(verdict.toJson())
        assertTrue(redacted.getString("boxId").startsWith("<redacted:"))
        assertTrue(redacted.getString("canonicalDeviceId").startsWith("<redacted:"))
    }
}
