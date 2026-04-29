/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class LeonaDiagnosticSnapshotTest {

    @Test
    fun `diagnostic snapshot serializes to pretty json`() {
        val snapshot = LeonaDiagnosticSnapshot(
            deviceId = "Tdevice",
            installId = "install-1",
            canonicalDeviceId = "Lcanon",
            fingerprintHash = "hash-1",
            packageName = "io.leonasec.demo",
            appVersionName = "1.0.0",
            appVersionCode = 1L,
            installerPackage = "com.android.vending",
            androidId = "android-1",
            signingCertSha256 = listOf("aa", "bb"),
            localeTag = "zh-CN",
            timeZoneId = "Asia/Shanghai",
            screenSummary = "1080x2400@440",
            localRiskSignals = setOf("root.basic"),
            nativeRiskTags = setOf("hook.frida.native"),
            nativeFindingIds = listOf("injection.frida.known_library"),
            nativeHighestSeverity = 3,
            nativeEventCount = 1,
            serverDecision = "allow",
            serverAction = "allow",
            serverRiskLevel = "LOW",
            serverRiskScore = 12,
            serverRiskTags = setOf("trusted.device"),
            lastBoxId = "box-1",
        )

        val json = snapshot.toJson(LeonaDebugExportView.FULL_DEBUG)
        val obj = JSONObject(json)

        assertEquals("Tdevice", obj.getString("deviceId"))
        assertEquals("Lcanon", obj.getString("canonicalDeviceId"))
        assertEquals(1, obj.getInt("nativeEventCount"))
        assertEquals("LOW", obj.getString("serverRiskLevel"))
        assertTrue(json.contains("\n"))
    }

    @Test
    fun `diagnostic snapshot redacts stable identifiers by default`() {
        val snapshot = LeonaDiagnosticSnapshot(
            deviceId = "Tdevice-1234567890",
            installId = "install-1234567890",
            canonicalDeviceId = "Lcanonical-1234567890",
            fingerprintHash = "fingerprint-1234567890",
            packageName = "io.leonasec.demo",
            appVersionName = "1.0.0",
            appVersionCode = 1L,
            installerPackage = "com.android.vending",
            androidId = "android-1",
            signingCertSha256 = listOf("abcdef1234567890"),
            localeTag = "zh-CN",
            timeZoneId = "Asia/Shanghai",
            screenSummary = "1080x2400@440",
            localRiskSignals = setOf("root.basic"),
            nativeRiskTags = setOf("hook.frida.native"),
            nativeFindingIds = listOf("injection.frida.known_library"),
            nativeHighestSeverity = 3,
            nativeEventCount = 1,
            serverDecision = "allow",
            serverAction = "allow",
            serverRiskLevel = "LOW",
            serverRiskScore = 12,
            serverRiskTags = setOf("trusted.device"),
            lastBoxId = "box-1234567890",
        )

        val obj = JSONObject(snapshot.toJson())

        assertEquals("Tdev...7890", obj.getString("deviceId"))
        assertEquals(true, obj.getBoolean("androidIdPresent"))
        assertTrue(!obj.has("androidId"))
        assertEquals("box-...7890", obj.getString("lastBoxId"))
    }
}
