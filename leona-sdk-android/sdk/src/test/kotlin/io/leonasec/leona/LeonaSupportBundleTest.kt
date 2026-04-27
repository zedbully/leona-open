/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class LeonaSupportBundleTest {

    @Test
    fun `support bundle serializes nested diagnostics and verdict`() {
        val diagnostic = LeonaDiagnosticSnapshot(
            deviceId = "Tdevice",
            installId = "install-1",
            canonicalDeviceId = "Lcanon",
            fingerprintHash = "hash-1",
            packageName = "io.leonasec.demo",
            appVersionName = "1.0.0",
            appVersionCode = 1L,
            installerPackage = "com.android.vending",
            androidId = "android-1",
            signingCertSha256 = listOf("aa"),
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
            serverRiskScore = 10,
            serverRiskTags = setOf("trusted.device"),
            lastBoxId = "box-1",
        )
        val verdict = LeonaServerVerdict(
            boxId = "box-1",
            canonicalDeviceId = "Lcanon",
            decision = "allow",
            action = "allow",
            riskLevel = "LOW",
            riskScore = 10,
            riskTags = setOf("trusted.device"),
        )
        val secureTransport = LeonaSecureTransportSnapshot(
            engineAvailable = true,
            engineClassName = "io.leonasec.leona.privatecore.DefaultSecureReportingEngine",
            endpointConfigured = true,
            apiKeyConfigured = true,
            attestationProviderConfigured = true,
            deviceBinding = LeonaDeviceBindingSnapshot(
                alias = "io.leonasec.leona.device-binding.v1",
                present = true,
                publicKeySha256 = "pkhash",
                keyAlgorithm = "EC_P256",
                signatureAlgorithm = "SHA256withECDSA",
                hardwareBacked = true,
            ),
            session = LeonaSecureSessionSnapshot(
                sessionIdHint = "sid12345…",
                expiresAtMillis = 789L,
                hasServerTamperPolicy = true,
                canonicalDeviceId = "Lcanon",
                deviceBindingStatus = "verified",
                serverAttestation = LeonaServerAttestationSnapshot(
                    provider = "play_integrity",
                    status = "verified",
                    code = "PLAY_INTEGRITY_VERIFIED",
                    retryable = false,
                ),
            ),
            lastAttestation = LeonaAttestationSnapshot(
                format = "play_integrity",
                tokenSha256 = "tokenhash",
                tokenLength = 128,
                collectedAtMillis = 999L,
            ),
            lastHandshakeAtMillis = 888L,
            lastHandshakeError = null,
            lastHandshakeErrorClass = null,
            lastHandshakeErrorCode = null,
            lastHandshakeErrorProvider = null,
            lastHandshakeRetryable = null,
        )
        val bundle = LeonaSupportBundle(
            generatedAtMillis = 123L,
            sdkVersion = "0.1.0-alpha.1",
            tenantId = "tenant-a",
            appId = "app-a",
            region = "CN_BJ",
            transportEnabled = true,
            cloudConfigEnabled = true,
            syncInit = false,
            effectiveDisabledSignals = setOf("androidId"),
            effectiveDisableCollectionWindowMs = 5000L,
            effectiveTamperPolicy = mapOf(
                "expectedPackage" to "io.leonasec.demo",
                "expectedQueriesSha256" to "abc123",
            ),
            lastIntegritySnapshot = mapOf(
                "package" to "io.leonasec.demo",
                "queriesSha256" to "abc123",
            ),
            cloudConfigFetchedAtMillis = 456L,
            cloudConfigRawJson = """{"disabledSignals":["androidId"]}""",
            secureTransport = secureTransport,
            diagnosticSnapshot = diagnostic,
            serverVerdict = verdict,
        )

        val json = bundle.toJson()
        val obj = JSONObject(json)

        assertEquals("tenant-a", obj.getString("tenantId"))
        assertEquals("Tdevice", obj.getJSONObject("diagnosticSnapshot").getString("deviceId"))
        assertEquals("LOW", obj.getJSONObject("serverVerdict").getString("riskLevel"))
        assertEquals(
            "io.leonasec.demo",
            obj.getJSONObject("effectiveTamperPolicy").getString("expectedPackage"),
        )
        assertEquals(
            "abc123",
            obj.getJSONObject("lastIntegritySnapshot").getString("queriesSha256"),
        )
        assertEquals(
            "androidId",
            obj.getJSONObject("cloudConfigRaw").getJSONArray("disabledSignals").getString(0),
        )
        assertEquals(
            "pkhash",
            obj.getJSONObject("secureTransport")
                .getJSONObject("deviceBinding")
                .getString("publicKeySha256"),
        )
        assertEquals(
            "play_integrity",
            obj.getJSONObject("secureTransport")
                .getJSONObject("lastAttestation")
                .getString("format"),
        )
        assertEquals(
            "verified",
            obj.getJSONObject("secureTransport")
                .getJSONObject("session")
                .getString("deviceBindingStatus"),
        )
        assertEquals(
            "PLAY_INTEGRITY_VERIFIED",
            obj.getJSONObject("secureTransport")
                .getJSONObject("session")
                .getJSONObject("serverAttestation")
                .getString("code"),
        )
        assertTrue(json.contains("\n"))
    }
}
