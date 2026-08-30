/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona

import io.leonasec.leona.config.LeonaConfig
import io.leonasec.leona.internal.NativePayloadInspector
import io.leonasec.leona.internal.identity.DeviceFingerprintSnapshot
import io.leonasec.leona.internal.identity.DeviceFingerprintHasher
import io.leonasec.leona.internal.identity.IdentityProtectionStatus
import io.leonasec.leona.internal.proto.LeonaProtectedPayloadCarrierV1
import io.leonasec.leona.internal.proto.LeonaEvidenceProtobufCodec
import io.leonasec.leona.internal.proto.LeonaProtobufDecodeResult
import io.leonasec.leona.internal.proto.LeonaEvidenceQualityValue
import io.leonasec.leona.internal.proto.LeonaEvidenceValue
import io.leonasec.leona.internal.spi.SecureDeviceContext
import io.leonasec.leona.internal.spi.SecureUploadResult
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LeonaTypedSensePipelineTest {

    @Test
    fun `typed sense seam hands one canonical carrier to authenticated uploader`() = runBlocking {
        var uploadCalls = 0
        var handoffBytes: ByteArray? = null
        val result = Leona.runTypedSense(
            config = config(),
            snapshot = snapshot(),
            nativeRisk = NativePayloadInspector.NativeRiskSummary.EMPTY,
            deviceContext = SecureDeviceContext(
                installId = snapshot().installId,
                resolvedDeviceId = snapshot().resolvedDeviceId,
                fingerprintHash = snapshot().fingerprintHash,
                sessionId = snapshot().sessionId,
            ),
            nowEpochMs = 1_700_000_000_000L,
            requestId = "request-fixed",
            nonce = ByteArray(16) { it.toByte() },
            upload = { handoff, _ ->
                uploadCalls += 1
                handoffBytes = (LeonaProtectedPayloadCarrierV1.encode(handoff) as LeonaProtectedPayloadCarrierV1.EncodeResult.Success).bytes
                SecureUploadResult(BoxId.of("box-typed"))
            },
        )

        assertEquals("box-typed", result.boxId.toString())
        assertEquals(1, uploadCalls)
        val carrier = handoffBytes ?: error("typed handoff missing")
        val decoded = LeonaProtectedPayloadCarrierV1.decodeRequest(carrier)
        assertTrue("carrier decode failed: $decoded", decoded is LeonaProtectedPayloadCarrierV1.DecodeResult.Success)
        val payload = (decoded as LeonaProtectedPayloadCarrierV1.DecodeResult.Success).payload
        val request = LeonaEvidenceProtobufCodec.decode(payload)
        assertTrue(request is LeonaProtobufDecodeResult.Success)
        val entries = (request as LeonaProtobufDecodeResult.Success).request.entries
        val fingerprint = entries.single { it.key == "identity.fingerprint_sha256" }
        assertEquals(LeonaEvidenceQualityValue.REDACTED, fingerprint.quality)
        assertTrue((fingerprint.value as LeonaEvidenceValue.Bytes).value.contentEquals(ByteArray(32) { 0xff.toByte() }))
        assertTrue(entries.any { it.key == "identity.install_lifecycle_sha256" && it.quality == LeonaEvidenceQualityValue.REDACTED })
        assertTrue(entries.filter { it.key != "identity.fingerprint_sha256" }.all { it.quality != LeonaEvidenceQualityValue.VERIFIED })
        assertFalse(String(payload, Charsets.UTF_8).contains("must-not-be-uploaded"))
        assertArrayEquals(carrier, handoffBytes ?: error("typed handoff missing"))
    }

    @Test
    fun `mapping failure is typed and uploader is not called`() = runBlocking {
        var uploadCalls = 0
        val error = runCatching {
            Leona.runTypedSense(
                config = LeonaConfig.Builder().build(),
                snapshot = snapshot(),
                nativeRisk = NativePayloadInspector.NativeRiskSummary.EMPTY,
                deviceContext = SecureDeviceContext(
                    installId = snapshot().installId,
                    resolvedDeviceId = snapshot().resolvedDeviceId,
                    fingerprintHash = snapshot().fingerprintHash,
                ),
                upload = { _, _ ->
                    uploadCalls += 1
                    SecureUploadResult(BoxId.of("unexpected"))
                },
            )
        }.exceptionOrNull()
        assertTrue(error is io.leonasec.leona.internal.spi.SecureReportingException)
        assertEquals(0, uploadCalls)
    }

    private fun config() = LeonaConfig.Builder()
        .tenantId("tenant")
        .appId("app")
        .environment("prod")
        .build()

    private fun snapshot() = DeviceFingerprintSnapshot(
        generatedAtMillis = 1_700_000_000_000L,
        installId = "123e4567-e89b-12d3-a456-426614174000",
        canonicalDeviceId = null,
        resolvedDeviceId = "Tlocal-only",
        fingerprintHash = "f".repeat(64),
        fingerprintSource = DeviceFingerprintHasher.FINGERPRINT_SOURCE_BASE_V2,
        identityAnchorSource = DeviceFingerprintHasher.ANCHOR_SOURCE_DEVICE_PROFILE,
        installLifecycleSha256 = "aa".repeat(32),
        packageName = "io.example.app",
        appVersionName = "1.0",
        appVersionCode = 1,
        installerPackage = null,
        androidId = "must-not-be-uploaded",
        signingCertSha256 = emptyList(),
        brand = "brand",
        model = "model",
        manufacturer = "manufacturer",
        sdkInt = 35,
        abis = listOf("arm64-v8a"),
        localeTag = "en-US",
        timeZoneId = "UTC",
        screenSummary = null,
        riskSignals = emptySet(),
        sessionId = "S123e4567e89b12d3a456426614174000",
        identityProtectionStatus = IdentityProtectionStatus.READY,
    )
}
