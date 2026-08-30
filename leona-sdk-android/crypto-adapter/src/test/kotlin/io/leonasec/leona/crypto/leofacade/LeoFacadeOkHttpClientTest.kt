package io.leonasec.leona.crypto.leofacade

import io.leonasec.leona.crypto.LeonaCryptoAssertionProvider
import io.leonasec.leona.crypto.LeonaCryptoCapabilities
import io.leonasec.leona.crypto.LeonaCryptoEnvelopeCodec
import io.leonasec.leona.crypto.LeonaCryptoHttpRequest
import io.leonasec.leona.crypto.LeonaCryptoHttpResponse
import io.leonasec.leona.crypto.LeonaCryptoPreparedAssertion
import io.leonasec.leona.crypto.LeonaCryptoRequestContext
import io.leonasec.leona.crypto.LeonaCryptoResult
import io.leonasec.leona.crypto.LeonaCryptoScopeCommitments
import io.leonasec.leona.crypto.LeonaCryptoScopeProvider
import io.leonasec.leona.crypto.LeonaCryptoSealedRequest
import io.leonasec.leona.crypto.LeonaCryptoTransport
import okhttp3.OkHttpClient
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.HttpUrl.Companion.toHttpUrl
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class LeoFacadeOkHttpClientTest {
    @Test
    fun `client sends one encrypted envelope to fixed endpoint and opens response`() {
        val server = MockWebServer()
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", LeonaCryptoEnvelopeCodec.CONTENT_TYPE)
                .setBody(
                    okio.Buffer().write(
                        LeonaCryptoEnvelopeCodec.encodeResponse(
                            io.leonasec.leona.crypto.LeonaCryptoSealedResponse(byteArrayOf(7)),
                        ),
                    ),
                ),
        )
        server.start()
        try {
            val transport = FakeTransport()
            val scope = LeonaCryptoScopeCommitments(ByteArray(32), ByteArray(32), ByteArray(32))
            val client = LeoFacadeOkHttpClient(
                transport = transport,
                assertions = neverAssertion,
                scopes = neverScopes,
                responseCommitments = { scope },
                endpoint = server.url("/v1/crypto"),
            )

            val result = client.execute(
                LeonaCryptoHttpRequest(
                    method = "POST",
                    authority = "api.example.test",
                    path = "/customer/action",
                    query = "opaque=value",
                    contentType = "application/json",
                    protectedHeaders = byteArrayOf(1),
                    body = byteArrayOf(2, 3),
                ),
            )

            val request = server.takeRequest()
            assertEquals("POST", request.method)
            assertEquals("/v1/crypto", request.path)
            assertEquals(LeonaCryptoEnvelopeCodec.CONTENT_TYPE, request.getHeader("Content-Type"))
            val envelope = LeonaCryptoEnvelopeCodec.decodeRequest(request.body.readByteArray())
            assertArrayEquals(byteArrayOf(9), envelope.encryptedWire)
            assertEquals("/customer/action", transport.lastRequest?.path)
            assertArrayEquals(byteArrayOf(7), transport.lastOpenedWire)
            assertTrue(result is LeonaCryptoResult.Success)
            assertEquals(201, (result as LeonaCryptoResult.Success).value.statusCode)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun `client sends encrypted envelope over local HTTPS API`() {
        val serverCertificate = HeldCertificate.Builder()
            .addSubjectAlternativeName("localhost")
            .build()
        val serverCertificates = HandshakeCertificates.Builder()
            .heldCertificate(serverCertificate)
            .build()
        val clientCertificates = HandshakeCertificates.Builder()
            .addTrustedCertificate(serverCertificate.certificate)
            .build()
        val server = MockWebServer()
        server.useHttps(serverCertificates.sslSocketFactory(), false)
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", LeonaCryptoEnvelopeCodec.CONTENT_TYPE)
                .setBody(
                    okio.Buffer().write(
                        LeonaCryptoEnvelopeCodec.encodeResponse(
                            io.leonasec.leona.crypto.LeonaCryptoSealedResponse(byteArrayOf(7)),
                        ),
                    ),
                ),
        )
        server.start()
        try {
            val transport = FakeTransport()
            val scope = LeonaCryptoScopeCommitments(ByteArray(32), ByteArray(32), ByteArray(32))
            val client = LeoFacadeOkHttpClient(
                transport = transport,
                assertions = neverAssertion,
                scopes = neverScopes,
                responseCommitments = { scope },
                endpoint = server.url("/v1/crypto"),
                httpClient = OkHttpClient.Builder()
                    .sslSocketFactory(
                        clientCertificates.sslSocketFactory(),
                        clientCertificates.trustManager,
                    )
                    .build(),
            )

            val result = client.execute(
                LeonaCryptoHttpRequest(
                    method = "POST",
                    authority = "api.example.test",
                    path = "/customer/action",
                    query = "opaque=value",
                    contentType = "application/json",
                    protectedHeaders = byteArrayOf(1),
                    body = byteArrayOf(2, 3),
                ),
            )

            val request = server.takeRequest()
            assertTrue(server.url("/").isHttps)
            assertEquals("https", request.requestUrl?.scheme)
            assertEquals("/v1/crypto", request.path)
            assertEquals(LeonaCryptoEnvelopeCodec.CONTENT_TYPE, request.getHeader("Content-Type"))
            assertArrayEquals(
                byteArrayOf(9),
                LeonaCryptoEnvelopeCodec.decodeRequest(request.body.readByteArray()).encryptedWire,
            )
            assertArrayEquals(byteArrayOf(7), transport.lastOpenedWire)
            assertTrue(result is LeonaCryptoResult.Success)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun `remote plaintext endpoint is rejected before any request`() {
        try {
            LeoFacadeOkHttpClient(
                transport = FakeTransport(),
                assertions = neverAssertion,
                scopes = neverScopes,
                responseCommitments = { LeonaCryptoScopeCommitments(ByteArray(32), ByteArray(32), ByteArray(32)) },
                endpoint = "http://example.invalid/v1/crypto".toHttpUrl(),
            )
            throw AssertionError("remote plaintext endpoint must be rejected")
        } catch (expected: IllegalArgumentException) {
            assertTrue(expected.message.orEmpty().contains("HTTPS"))
        }
    }
}

private class FakeTransport : LeonaCryptoTransport {
    override val capabilities = LeonaCryptoCapabilities(1, "test", "test", emptySet())
    var lastRequest: LeonaCryptoHttpRequest? = null
    var lastOpenedWire: ByteArray = ByteArray(0)

    override fun seal(
        request: LeonaCryptoHttpRequest,
        assertions: LeonaCryptoAssertionProvider,
        scopes: LeonaCryptoScopeProvider,
    ): LeonaCryptoResult<LeonaCryptoSealedRequest> {
        lastRequest = request
        return LeonaCryptoResult.Success(
            LeonaCryptoSealedRequest(
                byteArrayOf(9),
                io.leonasec.leona.crypto.LeonaCryptoAssertionEnvelope(
                    LeonaCryptoPreparedAssertion("test", "test", byteArrayOf(1), 1, 2),
                    ByteArray(32),
                    byteArrayOf(2),
                ),
            ),
        )
    }

    override fun openResponse(
        encryptedWire: ByteArray,
        commitments: LeonaCryptoScopeCommitments,
        nowMs: Long,
    ): LeonaCryptoResult<LeonaCryptoHttpResponse> {
        lastOpenedWire = encryptedWire
        return LeonaCryptoResult.Success(LeonaCryptoHttpResponse(201, byteArrayOf(4), byteArrayOf(5)))
    }

    override fun close() = Unit
}

private val neverAssertion = object : LeonaCryptoAssertionProvider {
    override fun prepare(request: LeonaCryptoRequestContext): LeonaCryptoPreparedAssertion =
        error("must not be called")

    override fun issue(
        request: LeonaCryptoRequestContext,
        prepared: LeonaCryptoPreparedAssertion,
        contextDigest: ByteArray,
    ): ByteArray = error("must not be called")
}

private val neverScopes = LeonaCryptoScopeProvider { error("must not be called") }
