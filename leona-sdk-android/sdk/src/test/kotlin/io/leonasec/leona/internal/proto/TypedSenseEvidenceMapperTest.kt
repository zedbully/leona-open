/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.proto

import io.leonasec.leona.config.LeonaConfig
import io.leonasec.leona.internal.NativePayloadInspector
import io.leonasec.leona.internal.identity.DeviceFingerprintSnapshot
import io.leonasec.leona.internal.identity.DeviceFingerprintHasher
import io.leonasec.leona.internal.identity.IdentityProtectionStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TypedSenseEvidenceMapperTest {

    @Test
    fun `mapper emits deterministic bounded typed observations without raw identifiers`() {
        val result = TypedSenseEvidenceMapper.map(
            config = config(),
            snapshot = snapshot(setOf("root.su_or_busybox_path_present")),
            nativeRisk = NativePayloadInspector.NativeRiskSummary(
                findings = emptyList(),
                riskTags = emptySet(),
                factTags = setOf("runtime.frida.evidence"),
                highestSeverity = 4,
            ),
            nowEpochMs = 1_700_000_000_000L,
            requestId = "request-fixed",
            nonce = ByteArray(16) { it.toByte() },
        )
        assertTrue(result is TypedSenseEvidenceMapper.Result.Success)
        val request = (result as TypedSenseEvidenceMapper.Result.Success).request
        assertEquals(request.entries.map { it.key }.sorted(), request.entries.map { it.key })
        assertEquals("123e4567-e89b-12d3-a456-426614174000", request.installId)
        assertEquals("S123e4567e89b12d3a456426614174000", request.sessionId)
        assertTrue(request.entries.all { it.quality != LeonaEvidenceQualityValue.VERIFIED })
        assertTrue(request.entries.any { it.key == "identity.fingerprint_sha256" && it.quality == LeonaEvidenceQualityValue.REDACTED })
        assertFalse(request.entries.any { entry ->
            listOf("android-id-raw", "canonical-device-id", "native-finding-message").any(entry.key::contains)
        })
    }

    @Test
    fun `mapper rejects unknown and duplicate source observations`() {
        val unknown = TypedSenseEvidenceMapper.map(config(), snapshot(setOf("future.detector.value")), emptyRisk())
        assertTrue(unknown is TypedSenseEvidenceMapper.Result.Failure)
        assertEquals(TypedSenseEvidenceMapper.Code.UNKNOWN_OBSERVATION, (unknown as TypedSenseEvidenceMapper.Result.Failure).code)

        val duplicate = TypedSenseEvidenceMapper.map(
            config(),
            snapshot(setOf("runtime.frida.evidence")),
            emptyRisk().copy(factTags = setOf("runtime.frida.evidence")),
        )
        assertTrue(duplicate is TypedSenseEvidenceMapper.Result.Failure)
        assertEquals(TypedSenseEvidenceMapper.Code.DUPLICATE_OBSERVATION, (duplicate as TypedSenseEvidenceMapper.Result.Failure).code)
    }

    @Test
    fun `mapper requires explicit protected scope`() {
        val missingTenant = TypedSenseEvidenceMapper.map(
            LeonaConfig.Builder().environment("prod").build(),
            snapshot(),
            emptyRisk(),
        )
        assertTrue(missingTenant is TypedSenseEvidenceMapper.Result.Failure)
        assertEquals(TypedSenseEvidenceMapper.Code.INVALID_SCOPE, (missingTenant as TypedSenseEvidenceMapper.Result.Failure).code)
    }

    @Test
    fun `mapper rejects malformed hash and source commitments`() {
        val malformed = TypedSenseEvidenceMapper.map(
            config(),
            snapshot().copy(fingerprintHash = "F".repeat(64)),
            emptyRisk(),
        )
        assertTrue(malformed is TypedSenseEvidenceMapper.Result.Failure)
        assertEquals(TypedSenseEvidenceMapper.Code.INVALID_IDENTITY, (malformed as TypedSenseEvidenceMapper.Result.Failure).code)

        val source = TypedSenseEvidenceMapper.map(
            config(),
            snapshot().copy(fingerprintSource = "caller-controlled"),
            emptyRisk(),
        )
        assertTrue(source is TypedSenseEvidenceMapper.Result.Failure)
        assertEquals(TypedSenseEvidenceMapper.Code.INVALID_IDENTITY, (source as TypedSenseEvidenceMapper.Result.Failure).code)
    }

    @Test
    fun `hash-only lifecycle commitment is retained as redacted bytes`() {
        val lifecycle = "a".repeat(64)
        val result = TypedSenseEvidenceMapper.map(
            config(),
            snapshot().copy(installLifecycleSha256 = lifecycle),
            emptyRisk(),
            nowEpochMs = 1_700_000_000_000L,
        ) as TypedSenseEvidenceMapper.Result.Success
        val entry = result.request.entries.single { it.key == "identity.install_lifecycle_sha256" }
        assertEquals(LeonaEvidenceQualityValue.REDACTED, entry.quality)
        assertTrue((entry.value as LeonaEvidenceValue.Bytes).value.contentEquals(ByteArray(32) { 0xaa.toByte() }))
    }

    private fun config() = LeonaConfig.Builder()
        .tenantId("tenant")
        .appId("app")
        .environment("prod")
        .build()

    private fun emptyRisk() = NativePayloadInspector.NativeRiskSummary.EMPTY

    private fun snapshot(signals: Set<String> = emptySet()) = DeviceFingerprintSnapshot(
        generatedAtMillis = 1_700_000_000_000L,
        installId = "123e4567-e89b-12d3-a456-426614174000",
        canonicalDeviceId = null,
        resolvedDeviceId = "local-resolved-id",
        fingerprintHash = "f".repeat(64),
        fingerprintSource = DeviceFingerprintHasher.FINGERPRINT_SOURCE_BASE_V2,
        identityAnchorSource = DeviceFingerprintHasher.ANCHOR_SOURCE_DEVICE_PROFILE,
        packageName = "io.example.app",
        appVersionName = "1.0",
        appVersionCode = 1,
        installerPackage = null,
        androidId = "android-id-raw",
        signingCertSha256 = emptyList(),
        brand = "brand",
        model = "model",
        manufacturer = "manufacturer",
        sdkInt = 35,
        abis = listOf("arm64-v8a"),
        localeTag = "en-US",
        timeZoneId = "UTC",
        screenSummary = null,
        riskSignals = signals,
        sessionId = "S123e4567e89b12d3a456426614174000",
        identityProtectionStatus = IdentityProtectionStatus.READY,
    )
}
