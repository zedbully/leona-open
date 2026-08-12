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
            fingerprintSchemaVersion = 3,
            fingerprintSource = "virtual_instance_anchor_v3",
            identityAnchorSource = "virtual_instance_anchor",
            canonicalDeviceIdSource = "server_persisted",
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
            evidenceSignals = setOf("root.su_or_busybox_path_present"),
            deviceEnvironmentEvidence = LeonaDeviceEnvironmentEvidence(
                evidenceIds = setOf("build.tags.test_keys", "verified_boot.orange"),
                build = mapOf("tags" to "test-keys"),
                verifiedBoot = mapOf("state" to "orange"),
            ),
            nativeRiskTags = setOf("hook.frida.native"),
            nativeFactTags = setOf("runtime.frida.evidence"),
            nativeFindingIds = listOf("injection.frida.known_library"),
            nativeHighestSeverity = 3,
            nativeEventCount = 1,
            serverDecision = "evidence_collected",
            serverAction = "business_defined",
            serverRiskLevel = "LOW",
            serverRiskScore = 10,
            serverRiskTags = setOf("trusted.device"),
            lastBoxId = "box-1",
        )
        val verdict = LeonaServerVerdict(
            boxId = "box-1",
            canonicalDeviceId = "Lcanon",
            decision = "evidence_collected",
            action = "business_defined",
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
            lastHandshakeError = "server rejected token=diagnostic-secret",
            lastHandshakeErrorClass = "java.io.IOException",
            lastHandshakeErrorCode = "AUTH_FAILED",
            lastHandshakeErrorProvider = "domestic_provider",
            lastHandshakeRetryable = false,
        )
        val bundle = LeonaSupportBundle(
            generatedAtMillis = 123L,
            sdkVersion = "0.1.0",
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

        val json = bundle.toJson(LeonaDebugExportView.FULL_DEBUG)
        val obj = JSONObject(json)

        assertEquals("tenant-a", obj.getString("tenantId"))
        assertEquals(
            3,
            obj.getJSONObject("identityDiagnostics").getInt("fingerprintSchemaVersion"),
        )
        assertEquals(
            "virtual_instance_anchor_v3",
            obj.getJSONObject("identityDiagnostics").getString("fingerprintSource"),
        )
        assertEquals(
            "virtual_instance_anchor",
            obj.getJSONObject("identityDiagnostics").getString("identityAnchorSource"),
        )
        assertEquals(
            "server_persisted",
            obj.getJSONObject("identityDiagnostics").getString("canonicalDeviceIdSource"),
        )
        assertEquals("Tdevice", obj.getJSONObject("diagnosticSnapshot").getString("deviceId"))
        assertEquals(
            "root.su_or_busybox_path_present",
            obj.getJSONObject("diagnosticSnapshot").getJSONArray("evidenceSignals").getString(0),
        )
        assertEquals(
            "root.basic",
            obj.getJSONObject("diagnosticSnapshot").getJSONArray("localRiskSignals").getString(0),
        )
        assertEquals(
            "runtime.frida.evidence",
            obj.getJSONObject("diagnosticSnapshot").getJSONArray("nativeFactTags").getString(0),
        )
        assertEquals(
            "hook.frida.native",
            obj.getJSONObject("diagnosticSnapshot").getJSONArray("nativeRiskTags").getString(0),
        )
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
        assertEquals(
            "server rejected token=diagnostic-secret",
            obj.getJSONObject("secureTransport").getString("lastHandshakeError"),
        )
        assertTrue(json.contains("\n"))

        val redacted = JSONObject(bundle.toJson())
        assertTrue(
            redacted.getJSONObject("diagnosticSnapshot").getString("deviceId").startsWith("<redacted:"),
        )
        assertEquals(true, redacted.getJSONObject("cloudConfigRaw").getBoolean("present"))
        assertEquals(
            "object",
            redacted.getJSONObject("cloudConfigRaw").getString("type"),
        )
        assertTrue(redacted.getJSONObject("lastIntegritySnapshot").has("valueSha256ByKey"))
        val redactedVerifiedBoot = redacted.getJSONObject("diagnosticSnapshot")
            .getJSONObject("deviceEnvironmentEvidence")
            .getJSONObject("verifiedBoot")
        assertTrue(redactedVerifiedBoot.has("valueSha256ByKey"))
        assertTrue(!redactedVerifiedBoot.has("state"))
        assertTrue(redacted.getJSONObject("secureTransport").isNull("lastHandshakeError"))
        assertTrue(!redacted.toString().contains("diagnostic-secret"))
    }
}
