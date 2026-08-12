/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
@file:Suppress("DEPRECATION")

package io.leonasec.leona.internal

import android.content.Context
import android.content.SharedPreferences
import io.leonasec.leona.config.LeonaConfig
import io.leonasec.leona.internal.spi.SecureReportingErrorCode
import io.leonasec.leona.internal.spi.SecureReportingException
import io.leonasec.leona.internal.spi.SecureDeviceContext
import okhttp3.OkHttpClient
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.json.JSONObject
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock
import java.io.IOException
import java.security.cert.CertPathValidatorException
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLHandshakeException

class SecureChannelTest {

    @Test
    fun `public hosted transport rejects cleartext endpoints`() {
        val error = runCatching {
            PublicHostedReportingClient.validatedPublicSenseUrl("http://api.example.test")
        }.exceptionOrNull()
        assertTrue(error is IllegalArgumentException)
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
    fun `commercial reporting profile fails closed without secure engine`() = runBlocking {
        val ctx = mockContext()
        val channel = SecureChannel(
            ctx,
            LeonaConfig.Builder()
                .reportingEndpoint("https://api.example.test/v1/sense")
                .apiKey("leona_test_app_key")
                .requireSecureReportingEngine(true)
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
    }

    @Test
    fun `public hosted reporting posts evidence envelope and returns BoxId`() = runBlocking {
        val server = MockWebServer()
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(
                    """
                    {
                      "boxId": "box-public-1",
                      "canonicalDeviceId": "L11112222333344445555666677778888",
                      "decision": "evidence_collected",
                      "action": "business_defined",
                      "risk": {
                        "level": "LOW",
                        "score": 0,
                        "tags": ["evidence.received"]
                      }
                    }
                    """.trimIndent(),
                ),
        )
        server.start()
        try {
            val ctx = mockContext()
            val secret = "leona_live_secret_should_not_leak"
            val channel = SecureChannel(
                ctx,
                LeonaConfig.Builder()
                    .reportingEndpoint(server.url("/").toString())
                    .apiKey(secret)
                    .build(),
            )

            val result = channel.upload(byteArrayOf(1, 2, 3), deviceContext())
            val request = server.takeRequest()
            val body = JSONObject(request.body.readUtf8())
            val deviceContext = body.getJSONObject("deviceContext")

            assertEquals("box-public-1", result.boxId.toString())
            assertEquals("L11112222333344445555666677778888", result.canonicalDeviceId)
            assertEquals("evidence_collected", result.serverVerdict?.decision)
            assertEquals("business_defined", result.serverVerdict?.action)
            assertEquals("/v1/sense/public", request.path)
            assertEquals(secret, request.getHeader("X-Leona-App-Key"))
            assertEquals("public_hosted", request.getHeader("X-Leona-Reporting-Mode"))
            assertEquals("public_hosted", body.getString("mode"))
            assertEquals("base64", body.getString("payloadEncoding"))
            assertEquals("AQID", body.getString("payload"))
            assertEquals("fingerprint-1", deviceContext.getString("fingerprintHash"))
            assertTrue(deviceContext.has("installIdSha256"))
            assertFalse(body.toString().contains("install-1"))
            assertFalse(body.toString().contains("Tdevice-1"))
            assertFalse(body.toString().contains(secret))
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun `public hosted reporting ignores raw device ids when resolving canonical`() = runBlocking {
        val server = MockWebServer()
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setHeader("X-Leona-Canonical-Device-Id", "raw-header-device")
                .setBody(
                    """
                    {
                      "boxId": "box-public-raw",
                      "deviceId": "Tdevice-raw",
                      "canonicalDeviceId": "Tdevice-claimed",
                      "device": {
                        "canonicalDeviceId": "Tdevice-nested",
                        "deviceId": "raw-device-id",
                        "id": "raw-id"
                      },
                      "identity": {
                        "canonicalDeviceId": "raw-identity",
                        "deviceId": "Tidentity"
                      },
                      "deviceIdentity": {
                        "canonicalDeviceId": "raw-device-identity",
                        "deviceId": "Tdevice-identity",
                        "resolvedDeviceId": "Tresolved"
                      },
                      "verdict": {
                        "canonicalDeviceId": "Tverdict-claimed"
                      }
                    }
                    """.trimIndent(),
                ),
        )
        server.start()
        try {
            val ctx = mockContext()
            val channel = SecureChannel(
                ctx,
                LeonaConfig.Builder()
                    .reportingEndpoint(server.url("/").toString())
                    .apiKey("leona_test_app_key")
                    .build(),
            )

            val result = channel.upload(byteArrayOf(1, 2, 3), deviceContext())
            server.takeRequest()

            assertEquals("box-public-raw", result.boxId.toString())
            assertEquals(null, result.canonicalDeviceId)
            assertEquals(null, result.serverVerdict?.canonicalDeviceId)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun `public hosted reporting error does not leak api key`() = runBlocking {
        val server = MockWebServer()
        server.enqueue(
            MockResponse()
                .setResponseCode(401)
                .setHeader("Content-Type", "application/json")
                .setBody("""{"error":"bad key leona_live_secret_should_not_leak"}"""),
        )
        server.start()
        try {
            val ctx = mockContext()
            val secret = "leona_live_secret_should_not_leak"
            val channel = SecureChannel(
                ctx,
                LeonaConfig.Builder()
                    .reportingEndpoint(server.url("/").toString())
                    .apiKey(secret)
                    .build(),
            )

            val error = runCatching { channel.upload(byteArrayOf(1, 2, 3), deviceContext()) }
                .exceptionOrNull()

            assertNotNull(error)
            assertFalse(error!!.message.orEmpty().contains(secret))
            assertTrue(error.message.orEmpty().contains("responseBodySha256="))
            assertEquals(SecureReportingErrorCode.AUTH_FAILED, (error as SecureReportingException).code)
            assertTrue(error.message.orEmpty().contains("diagnostic=auth_failed"))
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun `public hosted reporting classifies timestamp skew response`() = runBlocking {
        val server = MockWebServer()
        server.enqueue(
            MockResponse()
                .setResponseCode(401)
                .setHeader("Content-Type", "application/json")
                .setBody("""{"code":"LEONA_TIMESTAMP_SKEW","message":"Request timestamp outside acceptable window"}"""),
        )
        server.start()
        try {
            val ctx = mockContext()
            val channel = SecureChannel(
                ctx,
                LeonaConfig.Builder()
                    .reportingEndpoint(server.url("/").toString())
                    .apiKey("leona_test_app_key")
                    .build(),
            )

            val error = runCatching { channel.upload(byteArrayOf(1, 2, 3), deviceContext()) }
                .exceptionOrNull()

            assertNotNull(error)
            assertEquals(SecureReportingErrorCode.TIMESTAMP_SKEW, (error as SecureReportingException).code)
            assertTrue(error.message.orEmpty().contains("diagnostic=timestamp_skew"))
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun `public hosted reporting classifies generic server error without timestamp skew`() = runBlocking {
        val server = MockWebServer()
        server.enqueue(
            MockResponse()
                .setResponseCode(500)
                .setHeader("Content-Type", "application/json")
                .setBody("""{"error":"internal server error"}"""),
        )
        server.start()
        try {
            val ctx = mockContext()
            val channel = SecureChannel(
                ctx,
                LeonaConfig.Builder()
                    .reportingEndpoint(server.url("/").toString())
                    .apiKey("leona_test_app_key")
                    .build(),
            )

            val error = runCatching { channel.upload(byteArrayOf(1, 2, 3), deviceContext()) }
                .exceptionOrNull()

            assertNotNull(error)
            assertEquals(SecureReportingErrorCode.SERVER_5XX, (error as SecureReportingException).code)
            assertTrue(error.message.orEmpty().contains("diagnostic=server_5xx"))
            assertFalse(error.message.orEmpty().contains("diagnostic=timestamp_skew"))
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun `public hosted reporting classifies network timeout`() = runBlocking {
        val server = MockWebServer()
        server.enqueue(
            MockResponse()
                .setHeadersDelay(1, TimeUnit.SECONDS)
                .setBody("""{"boxId":"late"}"""),
        )
        server.start()
        try {
            val timeoutClient = OkHttpClient.Builder()
                .callTimeout(200, TimeUnit.MILLISECONDS)
                .connectTimeout(50, TimeUnit.MILLISECONDS)
                .readTimeout(50, TimeUnit.MILLISECONDS)
                .build()
            val client = PublicHostedReportingClient(LeonaConfig.Builder().build(), timeoutClient)

            val error = runCatching {
                client.upload(
                    endpoint = server.url("/").toString(),
                    apiKey = "leona_test_app_key",
                    sdkVersion = "test",
                    payload = byteArrayOf(1, 2, 3),
                    deviceContext = deviceContext(),
                )
            }.exceptionOrNull()

            assertNotNull(error)
            assertEquals(SecureReportingErrorCode.NETWORK_TIMEOUT, (error as SecureReportingException).code)
            assertTrue(error.message.orEmpty().contains("diagnostic=network_timeout"))
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun `public hosted reporting unknown network failure includes safe cause class`() = runBlocking {
        val client = PublicHostedReportingClient(
            LeonaConfig.Builder().build(),
            OkHttpClient.Builder()
                .addInterceptor {
                    throw IOException("broken transport ct_0123456789abcdef0123456789")
                }
                .build(),
        )

        val error = runCatching {
            client.upload(
                endpoint = "https://example.invalid",
                apiKey = "leona_test_app_key",
                sdkVersion = "test",
                payload = byteArrayOf(1, 2, 3),
                deviceContext = deviceContext(),
            )
        }.exceptionOrNull()

        assertNotNull(error)
        assertEquals(SecureReportingErrorCode.UNKNOWN, (error as SecureReportingException).code)
        assertTrue(error.message.orEmpty().contains("diagnostic=unknown"))
        assertTrue(error.message.orEmpty().contains("cause=java.io.IOException"))
        assertFalse(error.message.orEmpty().contains("ct_0123456789abcdef0123456789"))
        assertTrue(error.message.orEmpty().contains("messageSha256="))
    }

    @Test
    fun `public hosted reporting classifies tls trust anchor failure`() = runBlocking {
        val tlsError = SSLHandshakeException("handshake failed").apply {
            initCause(CertPathValidatorException("Trust anchor for certification path not found."))
        }
        val client = PublicHostedReportingClient(
            LeonaConfig.Builder().build(),
            OkHttpClient.Builder()
                .addInterceptor {
                    throw tlsError
                }
                .build(),
        )

        val error = runCatching {
            client.upload(
                endpoint = "https://example.invalid",
                apiKey = "leona_test_app_key",
                sdkVersion = "test",
                payload = byteArrayOf(1, 2, 3),
                deviceContext = deviceContext(),
            )
        }.exceptionOrNull()

        assertNotNull(error)
        assertEquals(SecureReportingErrorCode.TLS_TRUST_ANCHOR, (error as SecureReportingException).code)
        assertTrue(error.message.orEmpty().contains("diagnostic=tls_trust_anchor"))
        assertFalse(error.message.orEmpty().contains("diagnostic=unknown"))
    }

    @Test
    fun `public hosted reporting enables trust fallback only for leona hosted endpoint`() {
        assertTrue(
            PublicHostedReportingClient.shouldUseHostedTrustFallback("https://leona.xiyanshan.com"),
        )
        assertTrue(
            PublicHostedReportingClient.shouldUseHostedTrustFallback("https://leona.xiyanshan.com/v1/sense"),
        )
        assertFalse(
            PublicHostedReportingClient.shouldUseHostedTrustFallback("https://api.example.test"),
        )
        assertFalse(
            PublicHostedReportingClient.shouldUseHostedTrustFallback(""),
        )
    }

    @Test
    fun `public hosted reporting accepts endpoint already pointing at v1 sense`() = runBlocking {
        val server = MockWebServer()
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setHeader("X-Leona-Canonical-Device-Id", "Laaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .setBody("""{"boxId":"box-public-2"}"""),
        )
        server.start()
        try {
            val ctx = mockContext()
            val channel = SecureChannel(
                ctx,
                LeonaConfig.Builder()
                    .reportingEndpoint(server.url("/v1/sense").toString())
                    .apiKey("leona_test_app_key")
                    .build(),
            )

            val result = channel.upload(byteArrayOf(1, 2, 3), deviceContext())
            val request = server.takeRequest()

            assertEquals("box-public-2", result.boxId.toString())
            assertEquals("Laaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", result.canonicalDeviceId)
            assertEquals("/v1/sense/public", request.path)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun `missing api key for hosted reporting fails before upload`() = runBlocking {
        val ctx = mockContext()
        val channel = SecureChannel(
            ctx,
            LeonaConfig.Builder()
                .reportingEndpoint("https://api.example.test/v1/sense")
                .build(),
        )

        val error = runCatching { channel.upload(byteArrayOf(1, 2, 3), deviceContext()) }
            .exceptionOrNull()

        assertNotNull(error)
        assertEquals(SecureReportingErrorCode.API_KEY_REQUIRED, (error as SecureReportingException).code)
        assertTrue(error.message.orEmpty().contains("diagnostic=api_key_required"))
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

    private fun deviceContext(): SecureDeviceContext = SecureDeviceContext(
        installId = "install-1",
        resolvedDeviceId = "Tdevice-1",
        fingerprintHash = "fingerprint-1",
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
