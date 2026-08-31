/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
@file:Suppress("DEPRECATION")

package io.leonasec.leona.internal

import android.content.Context
import android.content.SharedPreferences
import io.leonasec.leona.crypto.LeonaCryptoCapabilities
import io.leonasec.leona.crypto.LeonaCryptoChannel
import io.leonasec.leona.crypto.LeonaCryptoEnvelopeCodec
import io.leonasec.leona.crypto.LeonaCryptoHttpRequest
import io.leonasec.leona.crypto.LeonaCryptoHttpResponse
import io.leonasec.leona.crypto.LeonaCryptoPreparedAssertion
import io.leonasec.leona.crypto.LeonaCryptoRequestContext
import io.leonasec.leona.crypto.LeonaCryptoResult
import io.leonasec.leona.crypto.LeonaCryptoScopeCommitments
import io.leonasec.leona.crypto.LeonaCryptoScopeProvider
import io.leonasec.leona.crypto.LeonaCryptoAssertionProvider
import io.leonasec.leona.crypto.LeonaCryptoSealedRequest
import io.leonasec.leona.crypto.LeonaCryptoSealedResponse
import io.leonasec.leona.crypto.LeonaCryptoTransport
import io.leonasec.leona.config.LeonaConfig
import io.leonasec.leona.crypto.LeonaCryptoProtectedHeadersCodec
import io.leonasec.leona.internal.spi.SecureDeviceContext
import io.leonasec.leona.internal.spi.SecureReportingErrorCode
import io.leonasec.leona.internal.spi.SecureReportingException
import io.leonasec.leona.internal.proto.LeonaProtectedLogicalPayloadHandoff
import io.leonasec.leona.internal.proto.LeonaEvidenceEntryModel
import io.leonasec.leona.internal.proto.LeonaEvidenceIngestRequestModel
import io.leonasec.leona.internal.proto.LeonaEvidenceProtobufCodec
import io.leonasec.leona.internal.proto.LeonaEvidenceQualityValue
import io.leonasec.leona.internal.proto.LeonaEvidenceSourceValue
import io.leonasec.leona.internal.proto.LeonaEvidenceValue
import io.leonasec.leona.internal.proto.LeonaClientScopeModel
import io.leonasec.leona.internal.proto.LeonaProtobufEncodeResult
import io.leonasec.leona.internal.proto.LeonaProtectedPayloadCarrierV1
import io.leonasec.leona.internal.proto.LeonaProtectedResponseCarrierV1
import io.leonasec.leona.internal.proto.LeonaEvidenceIngestResponseModel
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okio.Buffer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock
import java.nio.charset.StandardCharsets

class SecureChannelTest {

    @Test
    fun `typed protobuf handoff stops when protected descriptor carrier is unavailable`() = runBlocking {
        val channel = SecureChannel(mockContext(), LeonaConfig.Builder().build())
        val handoff = LeonaProtectedLogicalPayloadHandoff.ExternalBlocked(
            io.leonasec.leona.internal.proto.LeonaProtobufFailureCode.EXTERNAL_BLOCKED,
        )
        val error = runCatching { channel.uploadProtectedLogicalPayload(handoff, deviceContext()) }
            .exceptionOrNull()
        assertNotNull(error)
        assertEquals(
            SecureReportingErrorCode.PROTECTED_PAYLOAD_CARRIER_UNAVAILABLE,
            (error as SecureReportingException).code,
        )
    }

    @Test
    fun `protected protobuf handoff gives Leo the exact LPCARR01 golden body`() = runBlocking {
        val server = MockWebServer()
        val responseBody = responseCarrier(
            requestId = "request-golden",
            requestDigest = java.security.MessageDigest.getInstance("SHA-256").digest(frozenCarrier),
        )
        val transport = RecordingCryptoTransport(
            response = LeonaCryptoHttpResponse(
                statusCode = 200,
                body = responseBody,
            ),
        )
        val responseEnvelope = LeonaCryptoEnvelopeCodec.encodeResponse(
            LeonaCryptoSealedResponse(byteArrayOf(9, 8, 7)),
        )
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", LeonaCryptoEnvelopeCodec.CONTENT_TYPE)
                .setBody(Buffer().write(responseEnvelope)),
        )
        server.start()
        try {
            val handoff = LeonaEvidenceProtobufCodec.encode(carrierGoldenModel())
                as LeonaProtobufEncodeResult.Success
            var encoderCalls = 0
            val channel = SecureChannel(
                context = mockContext(),
                config = LeonaConfig.Builder()
                    .reportingEndpoint(server.url("/").toString())
                    .apiKey("leona_test_app_key")
                    .cryptoChannel(testCryptoChannel(transport))
                    .build(),
                protectedPayloadEncoder = {
                    encoderCalls += 1
                    LeonaProtectedPayloadCarrierV1.encode(it)
                },
            )

            val result = channel.uploadProtectedLogicalPayload(handoff.handoff, deviceContext())

            assertEquals("box-carrier", result.boxId.toString())
            assertEquals("evidence_collected", result.serverVerdict?.decision)
            assertEquals("business_defined", result.serverVerdict?.action)
            assertEquals(null, result.serverVerdict?.riskScore)
            assertTrue(result.serverVerdict?.riskTags.orEmpty().isEmpty())
            assertEquals("I${"1".repeat(32)}", result.serverInstallId)
            assertEquals("L${"2".repeat(32)}", result.canonicalDeviceId)
            assertEquals(1, encoderCalls)
            assertEquals(1, transport.sealCount)
            assertEquals(1, transport.openResponseCount)
            val request = transport.request ?: error("Leo transport did not receive request")
            assertArrayEquals(frozenCarrier, request.body)
            val protectedHeaders = LeonaCryptoProtectedHeadersCodec.decode(request.protectedHeaders)
            val descriptorValues = setOf(
                "LEONA_PROTOBUF",
                "leona.evidence.v1",
                "leona.evidence.v1.EvidenceIngestRequest",
                "1056487dea69e58894f48aea6d04a528e1e2aaf543fc708deb7cec007aaf8703",
            )
            assertFalse(protectedHeaders.values.any { it in descriptorValues })
            assertFalse(protectedHeaders.keys.any { it.contains("payload", ignoreCase = true) || it.contains("schema", ignoreCase = true) })
            assertFalse(protectedHeaders.keys.any {
                it.equals("X-Leona-Device-Id-Sha256", ignoreCase = true) ||
                    it.equals("X-Leona-Install-Id-Sha256", ignoreCase = true) ||
                    it.equals("X-Leona-Canonical-Device-Id-Sha256", ignoreCase = true) ||
                    it.equals("X-Leona-Fingerprint", ignoreCase = true) ||
                    it.equals("X-Leona-Session-Id-Sha256", ignoreCase = true)
            })
            assertFalse(protectedHeaders.values.any {
                it.contains("install-1") || it.contains("Tdevice-1") || it.contains("fingerprint-1")
            })

            val outer = server.takeRequest()
            assertEquals(null, outer.getHeader("X-Leona-Payload-Codec"))
            assertEquals(null, outer.getHeader("X-Leo-Payload-Schema"))
            assertFalse(outer.headers.names().any { it.startsWith("X-Leona-", ignoreCase = true) || it.startsWith("X-Leo-", ignoreCase = true) })
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun `blocked protected handoff does not invoke Leo or network`() = runBlocking {
        val server = MockWebServer()
        val transport = RecordingCryptoTransport(
            response = LeonaCryptoHttpResponse(statusCode = 200),
        )
        server.start()
        try {
            val channel = SecureChannel(
                mockContext(),
                LeonaConfig.Builder()
                    .reportingEndpoint(server.url("/").toString())
                    .apiKey("leona_test_app_key")
                    .cryptoChannel(testCryptoChannel(transport))
                    .build(),
            )
            val handoff = LeonaProtectedLogicalPayloadHandoff.ExternalBlocked(
                io.leonasec.leona.internal.proto.LeonaProtobufFailureCode.EXTERNAL_BLOCKED,
            )

            val error = runCatching { channel.uploadProtectedLogicalPayload(handoff, deviceContext()) }.exceptionOrNull()

            assertEquals(SecureReportingErrorCode.PROTECTED_PAYLOAD_CARRIER_UNAVAILABLE, (error as SecureReportingException).code)
            assertEquals(0, transport.sealCount)
            assertEquals(0, server.requestCount)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun `typed response rejects legacy json without fallback`() = runBlocking {
        val server = MockWebServer()
        val transport = RecordingCryptoTransport(
            response = LeonaCryptoHttpResponse(statusCode = 200, body = "{\"boxId\":\"legacy\"}".toByteArray()),
        )
        server.enqueue(
            MockResponse().setResponseCode(200)
                .setHeader("Content-Type", LeonaCryptoEnvelopeCodec.CONTENT_TYPE)
                .setBody(Buffer().write(LeonaCryptoEnvelopeCodec.encodeResponse(LeonaCryptoSealedResponse(byteArrayOf(9)))))
        )
        server.start()
        try {
            val handoff = (LeonaEvidenceProtobufCodec.encode(carrierGoldenModel()) as LeonaProtobufEncodeResult.Success).handoff
            val channel = SecureChannel(
                mockContext(),
                LeonaConfig.Builder().reportingEndpoint(server.url("/").toString()).apiKey("key")
                    .cryptoChannel(testCryptoChannel(transport)).build(),
            )
            val error = runCatching { channel.uploadProtectedLogicalPayload(handoff, deviceContext()) }.exceptionOrNull()
            assertEquals(SecureReportingErrorCode.PROTECTED_PAYLOAD_CARRIER_UNAVAILABLE, (error as SecureReportingException).code)
            assertEquals(1, transport.sealCount)
            assertEquals(1, transport.openResponseCount)
            assertEquals(1, server.requestCount)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun `synthetic test seam carrier encode failures never invoke Leo or network`() = runBlocking {
        val server = MockWebServer()
        val transport = RecordingCryptoTransport(
            response = LeonaCryptoHttpResponse(statusCode = 200),
        )
        server.start()
        try {
            val handoff = (LeonaEvidenceProtobufCodec.encode(carrierGoldenModel())
                as LeonaProtobufEncodeResult.Success).handoff
            val failureCodes = listOf(
                LeonaProtectedPayloadCarrierV1.FailureCode.DESCRIPTOR_MISMATCH,
                LeonaProtectedPayloadCarrierV1.FailureCode.EMPTY_PAYLOAD,
                LeonaProtectedPayloadCarrierV1.FailureCode.OVERSIZE,
                LeonaProtectedPayloadCarrierV1.FailureCode.PROTOBUF_REJECTED,
                LeonaProtectedPayloadCarrierV1.FailureCode.INTERNAL_ERROR,
            )
            failureCodes.forEach { failureCode ->
                val channel = SecureChannel(
                    context = mockContext(),
                    config = LeonaConfig.Builder()
                        .reportingEndpoint(server.url("/").toString())
                        .apiKey("leona_test_app_key")
                        .cryptoChannel(testCryptoChannel(transport))
                        .build(),
                    protectedPayloadEncoder = {
                        LeonaProtectedPayloadCarrierV1.EncodeResult.Failure(failureCode)
                    },
                )

                val error = runCatching { channel.uploadProtectedLogicalPayload(handoff, deviceContext()) }.exceptionOrNull()

                assertEquals(SecureReportingErrorCode.PROTECTED_PAYLOAD_CARRIER_UNAVAILABLE, (error as SecureReportingException).code)
            }
            assertEquals(0, transport.sealCount)
            assertEquals(0, server.requestCount)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun `upload fails closed when reporting endpoint is absent`() = runBlocking {
        val ctx = mockContext()
        val channel = SecureChannel(ctx, LeonaConfig.Builder().build())

        val error = runCatching { channel.upload(byteArrayOf(1, 2, 3, 4), deviceContext()) }
            .exceptionOrNull()

        assertNotNull(error)
        assertEquals(
            SecureReportingErrorCode.REPORTING_ENDPOINT_REQUIRED,
            (error as SecureReportingException).code,
        )
        assertTrue(error.message.orEmpty().contains("diagnostic=reporting_endpoint_required"))
    }

    @Test
    fun `upload fails closed when transport is disabled`() = runBlocking {
        val ctx = mockContext()
        val channel = SecureChannel(
            ctx,
            LeonaConfig.Builder()
                .transportEnabled(false)
                .build(),
        )

        val error = runCatching { channel.upload(byteArrayOf(), deviceContext()) }
            .exceptionOrNull()

        assertNotNull(error)
        assertEquals(
            SecureReportingErrorCode.TRANSPORT_DISABLED,
            (error as SecureReportingException).code,
        )
        assertTrue(error.message.orEmpty().contains("diagnostic=transport_disabled"))
    }

    @Test
    fun `reporting requires a configured Leo channel and never uses a legacy engine`() = runBlocking {
        val server = MockWebServer()
        server.start()
        try {
            val channel = SecureChannel(
                mockContext(),
                LeonaConfig.Builder()
                    .reportingEndpoint(server.url("/").toString())
                    .apiKey("leona_test_app_key")
                    .requireSecureReportingEngine(false)
                    .build(),
            )

            val error = runCatching { channel.upload(byteArrayOf(1, 2, 3), deviceContext()) }
                .exceptionOrNull()

            assertNotNull(error)
            assertEquals(
                SecureReportingErrorCode.SECURE_ENGINE_REQUIRED,
                (error as SecureReportingException).code,
            )
            assertTrue(error.message.orEmpty().contains("diagnostic=secure_engine_required"))
            assertEquals(0, server.requestCount)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun `reporting sends only Leo envelope and protects app fields`() = runBlocking {
        val server = MockWebServer()
        val transport = RecordingCryptoTransport(
            response = LeonaCryptoHttpResponse(
                statusCode = 200,
                body = """{"boxId":"box-1","installId":"I${"a".repeat(32)}","decision":"allow"}"""
                    .toByteArray(StandardCharsets.UTF_8),
            ),
        )
        val responseEnvelope = LeonaCryptoEnvelopeCodec.encodeResponse(
            LeonaCryptoSealedResponse(byteArrayOf(9, 8, 7)),
        )
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", LeonaCryptoEnvelopeCodec.CONTENT_TYPE)
                .setBody(Buffer().write(responseEnvelope)),
        )
        server.start()
        try {
            val cryptoChannel = testCryptoChannel(transport)
            val channel = SecureChannel(
                mockContext(),
                LeonaConfig.Builder()
                    .reportingEndpoint(server.url("/").toString())
                    .apiKey("leona_test_app_key")
                    .environment("staging")
                    .cryptoChannel(cryptoChannel)
                    .build(),
            )
            val payload = byteArrayOf(1, 2, 3, 4)

            val result = channel.upload(payload, deviceContext("e".repeat(64), sessionId = "session-1"))

            assertEquals("box-1", result.boxId.toString())
            assertEquals("I${"a".repeat(32)}", result.serverInstallId)
            val captured = transport.request ?: error("Leo transport did not receive request")
            assertEquals("POST", captured.method)
            assertEquals("/v1/sense", captured.path)
            assertEquals(payload.toList(), captured.body.toList())
            assertFalse(captured.body.contentEquals(frozenCarrier))
            val protectedHeaders = LeonaCryptoProtectedHeadersCodec.decode(captured.protectedHeaders)
            assertEquals("leona_test_app_key", protectedHeaders["X-Leona-App-Key"])
            assertEquals("leo_crypto", protectedHeaders["X-Leona-Reporting-Mode"])
            assertEquals("staging", protectedHeaders["X-Leona-Environment"])
            assertFalse(protectedHeaders.values.any { it == "install-1" || it == "Tdevice-1" })
            assertTrue(protectedHeaders["X-Leona-Session-Id-Sha256"].orEmpty().matches(Regex("[0-9a-f]{64}")))
            assertFalse(protectedHeaders.values.any { it == "session-1" })

            val outer = server.takeRequest()
            assertEquals(LeonaCryptoEnvelopeCodec.CONTENT_TYPE, outer.getHeader("Content-Type"))
            assertEquals(LeonaCryptoEnvelopeCodec.CONTENT_TYPE, outer.getHeader("Accept"))
            assertEquals(null, outer.getHeader("X-Leona-Environment"))
            assertEquals(null, outer.getHeader("X-Leona-Session-Id-Sha256"))
            assertEquals(null, outer.getHeader("X-Leona-Identity-Protection"))
            assertFalse(outer.body.readByteArray().toString(StandardCharsets.UTF_8).contains("leona_test_app_key"))
            assertFalse(outer.path!!.contains("/v1/sense"))
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun `server tamper parser keeps component provider and application semantic baselines`() {
        val policy = parseServerTamperPolicy(
            """
            {
              "expectedQueriesPackageSemanticsSha256": "11AB",
              "expectedQueriesProviderSemanticsSha256": "22BC",
              "expectedQueriesIntentSemanticsSha256": "33CD",
              "expectedSigningCertificateLineageSha256": "66FA",
              "expectedApkSigningBlockSha256": "88BC",
              "expectedApkSigningBlockIdSha256": {
                "0x7109871a": "99CD"
              },
              "expectedResourcesArscSha256": "44DE",
              "expectedResourceInventorySha256": "77AB",
              "expectedResourceEntrySha256": {
                "res/raw/leona.bin": "55EF"
              },
              "expectedComponentAccessSemanticsSha256": {
                "activity:com.example.MainActivity": "AA11"
              },
              "expectedComponentOperationalSemanticsSha256": {
                "service:com.example.SyncService": "BB22"
              },
              "expectedProviderAccessSemanticsSha256": {
                "provider:com.example.DataProvider": "CC33"
              },
              "expectedProviderOperationalSemanticsSha256": {
                "provider:com.example.DataProvider": "DD44"
              },
              "expectedIntentFilterSemanticsSha256": {
                "activity:com.example.MainActivity": "ABCD"
              },
              "expectedGrantUriPermissionSemanticsSha256": {
                "provider:com.example.DataProvider": "DCBA"
              },
              "expectedMetaDataType": {
                "channel": "STRING"
              },
              "expectedMetaDataValueSha256": {
                "channel": "A1B2"
              },
              "expectedManifestMetaDataEntrySha256": {
                "channel": "B1C2"
              },
              "expectedManifestMetaDataSemanticsSha256": {
                "channel": "C1D2"
              },
              "expectedUsesFeatureFieldValues": {
                "uses-feature:android.hardware.camera#required": "false"
              },
              "expectedUsesSdkFieldValues": {
                "uses-sdk#targetSdkVersion": "34"
              },
              "expectedUsesLibraryFieldValues": {
                "uses-library:org.apache.http.legacy#required": "true"
              },
              "expectedUsesNativeLibraryFieldValues": {
                "uses-native-library:com.example.sec#required": "false"
              },
              "expectedApplicationSecuritySemanticsSha256": "EE55",
              "expectedApplicationRuntimeSemanticsSha256": "FF66",
              "expectedApplicationFieldValues": {
                "application#usesCleartextTraffic": "false"
              }
            }
            """.trimIndent(),
        )

        assertEquals(
            mapOf("activity:com.example.MainActivity" to "aa11"),
            policy.expectedComponentAccessSemanticsSha256,
        )
        assertEquals("11ab", policy.expectedQueriesPackageSemanticsSha256)
        assertEquals("22bc", policy.expectedQueriesProviderSemanticsSha256)
        assertEquals("33cd", policy.expectedQueriesIntentSemanticsSha256)
        assertEquals("66fa", policy.expectedSigningCertificateLineageSha256)
        assertEquals("88bc", policy.expectedApkSigningBlockSha256)
        assertEquals(mapOf("0x7109871a" to "99cd"), policy.expectedApkSigningBlockIdSha256)
        assertEquals("44de", policy.expectedResourcesArscSha256)
        assertEquals("77ab", policy.expectedResourceInventorySha256)
        assertEquals(mapOf("res/raw/leona.bin" to "55ef"), policy.expectedResourceEntrySha256)
        assertEquals(
            mapOf("service:com.example.SyncService" to "bb22"),
            policy.expectedComponentOperationalSemanticsSha256,
        )
        assertEquals(
            mapOf("provider:com.example.DataProvider" to "cc33"),
            policy.expectedProviderAccessSemanticsSha256,
        )
        assertEquals(
            mapOf("provider:com.example.DataProvider" to "dd44"),
            policy.expectedProviderOperationalSemanticsSha256,
        )
        assertEquals(
            mapOf("activity:com.example.MainActivity" to "abcd"),
            policy.expectedIntentFilterSemanticsSha256,
        )
        assertEquals(
            mapOf("provider:com.example.DataProvider" to "dcba"),
            policy.expectedGrantUriPermissionSemanticsSha256,
        )
        assertEquals(mapOf("channel" to "string"), policy.expectedMetaDataType)
        assertEquals(mapOf("channel" to "a1b2"), policy.expectedMetaDataValueSha256)
        assertEquals(mapOf("channel" to "b1c2"), policy.expectedManifestMetaDataEntrySha256)
        assertEquals(mapOf("channel" to "c1d2"), policy.expectedManifestMetaDataSemanticsSha256)
        assertEquals(
            mapOf("uses-feature:android.hardware.camera#required" to "false"),
            policy.expectedUsesFeatureFieldValues,
        )
        assertEquals(mapOf("uses-sdk#targetSdkVersion" to "34"), policy.expectedUsesSdkFieldValues)
        assertEquals(
            mapOf("uses-library:org.apache.http.legacy#required" to "true"),
            policy.expectedUsesLibraryFieldValues,
        )
        assertEquals(
            mapOf("uses-native-library:com.example.sec#required" to "false"),
            policy.expectedUsesNativeLibraryFieldValues,
        )
        assertEquals("ee55", policy.expectedApplicationSecuritySemanticsSha256)
        assertEquals("ff66", policy.expectedApplicationRuntimeSemanticsSha256)
        assertEquals(
            mapOf("application#usesCleartextTraffic" to "false"),
            policy.expectedApplicationFieldValues,
        )
    }

    private val frozenCarrier: ByteArray
        get() = javaClass.getResourceAsStream("/leona/evidence/v1/valid-carrier.bin")!!.readBytes()

    private fun responseCarrier(requestId: String, requestDigest: ByteArray): ByteArray {
        val response = LeonaEvidenceIngestResponseModel(
            protocolMajor = 1,
            requestId = requestId,
            requestCarrierSha256 = requestDigest,
            responseId = ByteArray(16) { it.toByte() },
            boxId = "box-carrier",
            serverInstallId = "I${"1".repeat(32)}",
            canonicalDeviceId = "L${"2".repeat(32)}",
            issuedAtEpochMs = 1_700_000_000_000L,
            boxExpiresAtEpochMs = 1_700_000_100_000L,
        )
        return (LeonaProtectedResponseCarrierV1.encode(response) as LeonaProtectedResponseCarrierV1.EncodeResult.Success).bytes
    }

    private fun carrierGoldenModel() = LeonaEvidenceIngestRequestModel(
        protocolMajor = 1,
        tenantId = "tenant-golden",
        appId = "app-golden",
        environmentId = "prod",
        installId = "install-ref",
        sessionId = "session-ref",
        requestId = "request-golden",
        nonce = ByteArray(16) { it.toByte() },
        idempotencyKey = "idem-golden",
        issuedAtEpochMs = 1_700_000_000_000L,
        clientScope = LeonaClientScopeModel("tenant-golden", "app-golden", "prod"),
        entries = listOf(
            LeonaEvidenceEntryModel(
                "integrity.status",
                1_700_000_000_000L,
                LeonaEvidenceSourceValue.ANDROID,
                LeonaEvidenceQualityValue.VERIFIED,
                LeonaEvidenceValue.Bool(true),
            ),
        ),
    )

    private fun deviceContext(
        installLifecycleSha256: String? = null,
        sessionId: String? = null,
    ): SecureDeviceContext = SecureDeviceContext(
        installId = "install-1",
        resolvedDeviceId = "Tdevice-1",
        fingerprintHash = "fingerprint-1",
        installLifecycleSha256 = installLifecycleSha256,
        sessionId = sessionId,
    )

    @Test
    fun `secure device context keeps deprecated risk aliases separate from evidence fields`() {
        val context = SecureDeviceContext(
            installId = "install-1",
            resolvedDeviceId = "Tdevice-1",
            fingerprintHash = "fingerprint-1",
            riskSignals = setOf("root.basic"),
            nativeRiskTags = setOf("hook.frida.native"),
            evidenceSignals = setOf("root.su_or_busybox_path_present"),
            nativeFactTags = setOf("runtime.frida.evidence"),
        )

        assertEquals(setOf("root.su_or_busybox_path_present"), context.evidenceSignals)
        assertEquals(setOf("runtime.frida.evidence"), context.nativeFactTags)
        assertEquals(setOf("root.basic"), context.riskSignals)
        assertEquals(setOf("hook.frida.native"), context.nativeRiskTags)
    }

    private fun parseServerTamperPolicy(json: String): TamperPolicy {
        val companion = SecureChannel::class.java.getDeclaredField("Companion").get(null)
        val method = companion.javaClass.getDeclaredMethod("parseServerTamperPolicy", String::class.java)
        method.isAccessible = true
        return method.invoke(companion, json) as TamperPolicy
    }

    private fun testCryptoChannel(transport: RecordingCryptoTransport): LeonaCryptoChannel = LeonaCryptoChannel(
        transport = transport,
        assertions = object : LeonaCryptoAssertionProvider {
            override fun prepare(request: LeonaCryptoRequestContext) = LeonaCryptoPreparedAssertion(
                format = "test",
                audience = "test",
                challenge = byteArrayOf(1),
                issuedAtMs = 1,
                expiresAtMs = 2,
            )

            override fun issue(
                request: LeonaCryptoRequestContext,
                prepared: LeonaCryptoPreparedAssertion,
                contextDigest: ByteArray,
            ): ByteArray = byteArrayOf(1)
        },
        scopes = LeonaCryptoScopeProvider { commitments() },
        responseCommitments = { commitments() },
    )

    private fun commitments() = LeonaCryptoScopeCommitments(
        deployment = ByteArray(32) { 1 },
        tenant = ByteArray(32) { 2 },
        policy = ByteArray(32) { 3 },
    )

    private class RecordingCryptoTransport(
        private val response: LeonaCryptoHttpResponse,
    ) : LeonaCryptoTransport {
        var request: LeonaCryptoHttpRequest? = null
        var sealCount: Int = 0
            private set
        var openResponseCount: Int = 0
            private set

        override val capabilities = LeonaCryptoCapabilities(
            protocolMajor = LeonaCryptoEnvelopeCodec.PROTOCOL_MAJOR,
            adapterVersion = "test",
            providerVersion = "13.0.0",
            features = setOf(
                "request-seal",
                "response-open",
                "protected-headers",
                "protected-body",
            ),
        )

        override fun seal(
            request: LeonaCryptoHttpRequest,
            assertions: LeonaCryptoAssertionProvider,
            scopes: LeonaCryptoScopeProvider,
        ): LeonaCryptoResult<LeonaCryptoSealedRequest> {
            sealCount += 1
            this.request = request
            return LeonaCryptoResult.Success(
                LeonaCryptoSealedRequest(
                    encryptedWire = byteArrayOf(1, 2, 3),
                    assertionEnvelope = io.leonasec.leona.crypto.LeonaCryptoAssertionEnvelope(
                        context = LeonaCryptoPreparedAssertion(
                            format = "test",
                            audience = "test",
                            challenge = byteArrayOf(1),
                            issuedAtMs = 1,
                            expiresAtMs = 2,
                        ),
                        contextDigest = ByteArray(32),
                        assertion = byteArrayOf(4),
                    ),
                ),
            )
        }

        override fun openResponse(
            encryptedWire: ByteArray,
            commitments: LeonaCryptoScopeCommitments,
            nowMs: Long,
        ): LeonaCryptoResult<LeonaCryptoHttpResponse> {
            openResponseCount += 1
            return LeonaCryptoResult.Success(response)
        }

        override fun close() = Unit
    }

    private fun mockContext(): Context {
        val ctx = mock(Context::class.java)
        val prefs = mock(SharedPreferences::class.java)
        val editor = mock(SharedPreferences.Editor::class.java)
        `when`(ctx.applicationContext).thenReturn(ctx)
        `when`(ctx.getSharedPreferences("io.leonasec.leona.session", Context.MODE_PRIVATE))
            .thenReturn(prefs)
        `when`(prefs.edit()).thenReturn(editor)
        `when`(editor.putString(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString()))
            .thenReturn(editor)
        `when`(editor.remove(org.mockito.ArgumentMatchers.anyString())).thenReturn(editor)
        return ctx
    }
}
