/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.crypto.leofacade

import com.leo.crypto.facade.AssertionProvider
import com.leo.crypto.facade.AssertionRequestContext
import com.leo.crypto.facade.LeoAssertionClient
import com.leo.crypto.facade.LeoAssertionSession
import com.leo.crypto.facade.LeoResult
import com.leo.crypto.facade.PreparedAssertionContext
import com.leo.crypto.facade.ProtectedRequest
import com.leo.crypto.facade.ScopeCommitments
import com.leo.crypto.facade.ScopeProvider
import io.leonasec.leona.crypto.LeonaCryptoEnvelopeCodec
import io.leonasec.leona.crypto.LeonaCryptoAssertionProvider
import io.leonasec.leona.crypto.LeonaCryptoCapabilities
import io.leonasec.leona.crypto.LeonaCryptoErrorCode
import io.leonasec.leona.crypto.LeonaCryptoHttpRequest
import io.leonasec.leona.crypto.LeonaCryptoHttpResponse
import io.leonasec.leona.crypto.LeonaCryptoPreparedAssertion
import io.leonasec.leona.crypto.LeonaCryptoRequestContext
import io.leonasec.leona.crypto.LeonaCryptoResult
import io.leonasec.leona.crypto.LeonaCryptoScopeCommitments
import io.leonasec.leona.crypto.LeonaCryptoScopeProvider
import io.leonasec.leona.crypto.LeonaCryptoSealedRequest
import io.leonasec.leona.crypto.LeonaCryptoTransport
import okhttp3.HttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/**
 * Compile-time adapter for the optional Leo Android facade AAR. This module is
 * not included by default; callers must add the same external AAR directly to
 * the application so its `leo_android_facade` JNI library is packaged.
 */
object LeoFacadeCryptoCompatibility {
    const val ADAPTER_VERSION = "1.0.0"
    const val PROTOCOL_MAJOR = 1
    const val SUPPORTED_EXTERNAL_MAJOR = 13
    const val FEATURE_REQUEST_SEAL = "request-seal"
    const val FEATURE_RESPONSE_OPEN = "response-open"
    const val FEATURE_PROTECTED_HEADERS = "protected-headers"
    const val FEATURE_PROTECTED_BODY = "protected-body"

    private val versionPattern = Regex("^(\\d+)\\.(\\d+)(?:\\.(\\d+))?(?:[-+].*)?$")

    fun isSupportedProviderVersion(version: String): Boolean {
        val match = versionPattern.matchEntire(version.trim()) ?: return false
        return match.groupValues[1].toIntOrNull() == SUPPORTED_EXTERNAL_MAJOR
    }
}

/** Factory is fail-closed for missing, incompatible, or unusable external material. */
object LeoFacadeCryptoTransportFactory {
    fun create(
        nativeConfiguration: ByteArray,
        bootstrap: ByteArray,
        providerVersion: String,
        assertions: LeonaCryptoAssertionProvider,
        scopes: LeonaCryptoScopeProvider,
    ): LeonaCryptoResult<LeonaCryptoTransport> {
        if (nativeConfiguration.isEmpty() || bootstrap.isEmpty()) {
            return LeonaCryptoResult.Failure(LeonaCryptoErrorCode.INVALID_INPUT)
        }
        if (!LeoFacadeCryptoCompatibility.isSupportedProviderVersion(providerVersion)) {
            return LeonaCryptoResult.Failure(LeonaCryptoErrorCode.SDK_INCOMPATIBLE)
        }

        return try {
            val client = LeoAssertionClient.fromNativeConfiguration(nativeConfiguration.copyOf())
            when (val result = client.openSession(bootstrap.copyOf())) {
                is LeoResult.Success -> LeonaCryptoResult.Success(
                    LeoFacadeCryptoTransport(
                        client = client,
                        session = result.value,
                        providerVersion = providerVersion.trim(),
                    ),
                )

                is LeoResult.Failure -> {
                    client.close()
                    externalFailure(result)
                }
            }
        } catch (_: NoClassDefFoundError) {
            LeonaCryptoResult.Failure(LeonaCryptoErrorCode.SDK_MISSING)
        } catch (_: UnsatisfiedLinkError) {
            LeonaCryptoResult.Failure(LeonaCryptoErrorCode.SDK_MISSING)
        } catch (_: UnsupportedOperationException) {
            LeonaCryptoResult.Failure(LeonaCryptoErrorCode.SDK_INCOMPATIBLE)
        } catch (_: IllegalArgumentException) {
            LeonaCryptoResult.Failure(LeonaCryptoErrorCode.INVALID_INPUT)
        }
    }
}

private class LeoFacadeCryptoTransport(
    private val client: LeoAssertionClient,
    private val session: LeoAssertionSession,
    providerVersion: String,
) : LeonaCryptoTransport {
    private var closed = false

    override val capabilities = LeonaCryptoCapabilities(
        protocolMajor = LeoFacadeCryptoCompatibility.PROTOCOL_MAJOR,
        adapterVersion = LeoFacadeCryptoCompatibility.ADAPTER_VERSION,
        providerVersion = providerVersion,
        features = setOf(
            LeoFacadeCryptoCompatibility.FEATURE_REQUEST_SEAL,
            LeoFacadeCryptoCompatibility.FEATURE_RESPONSE_OPEN,
            LeoFacadeCryptoCompatibility.FEATURE_PROTECTED_HEADERS,
            LeoFacadeCryptoCompatibility.FEATURE_PROTECTED_BODY,
        ),
    )

    override fun seal(
        request: LeonaCryptoHttpRequest,
        assertions: LeonaCryptoAssertionProvider,
        scopes: LeonaCryptoScopeProvider,
    ): LeonaCryptoResult<LeonaCryptoSealedRequest> {
        if (closed) return LeonaCryptoResult.Failure(LeonaCryptoErrorCode.CLOSED)
        return try {
            val externalRequest = ProtectedRequest(
                request.method,
                request.authority,
                request.path,
                request.query,
                request.contentType,
                request.protectedHeaders.copyOf(),
                request.body.copyOf(),
            )
            when (val result = session.seal(
                externalRequest,
                assertionProvider(assertions),
                scopeProvider(scopes),
            )) {
                is LeoResult.Success -> LeonaCryptoResult.Success(result.value.toStable())
                is LeoResult.Failure -> externalFailure(result)
            }
        } catch (_: IllegalArgumentException) {
            LeonaCryptoResult.Failure(LeonaCryptoErrorCode.INVALID_INPUT)
        } catch (_: Exception) {
            LeonaCryptoResult.Failure(LeonaCryptoErrorCode.PROVIDER_FAILURE)
        }
    }

    override fun openResponse(
        encryptedWire: ByteArray,
        commitments: LeonaCryptoScopeCommitments,
        nowMs: Long,
    ): LeonaCryptoResult<LeonaCryptoHttpResponse> {
        if (closed) return LeonaCryptoResult.Failure(LeonaCryptoErrorCode.CLOSED)
        if (encryptedWire.isEmpty() || nowMs < 0) {
            return LeonaCryptoResult.Failure(LeonaCryptoErrorCode.INVALID_INPUT)
        }
        return try {
            when (val result = session.openResponse(encryptedWire.copyOf(), commitments.toExternal(), nowMs)) {
                is LeoResult.Success -> LeonaCryptoResult.Success(
                    LeonaCryptoHttpResponse(
                        result.value.statusCode,
                        result.value.protectedHeaders.copyOf(),
                        result.value.body.copyOf(),
                    ),
                )

                is LeoResult.Failure -> externalFailure(result)
            }
        } catch (_: IllegalArgumentException) {
            LeonaCryptoResult.Failure(LeonaCryptoErrorCode.INVALID_INPUT)
        } catch (_: Exception) {
            LeonaCryptoResult.Failure(LeonaCryptoErrorCode.CRYPTO_FAILURE)
        }
    }

    override fun close() {
        if (closed) return
        closed = true
        session.close()
        client.close()
    }

    private fun assertionProvider(provider: LeonaCryptoAssertionProvider): AssertionProvider =
        object : AssertionProvider {
            override fun prepare(request: AssertionRequestContext): PreparedAssertionContext =
                provider.prepare(request.toStable()).toExternal()

            override fun issue(
                request: AssertionRequestContext,
                prepared: PreparedAssertionContext,
                contextDigest: ByteArray,
            ): ByteArray = provider.issue(
                request.toStable(),
                prepared.toStable(),
                contextDigest.copyOf(),
            ).copyOf()
        }

    private fun scopeProvider(provider: LeonaCryptoScopeProvider): ScopeProvider = ScopeProvider { context ->
        provider.commitments(context.toStable()).toExternal()
    }
}

/**
 * Small opt-in API client for the encrypted endpoint. It posts one outer
 * envelope to a fixed routing endpoint; the original path/query are protected
 * fields inside the Leo request and are not copied into the cleartext URL.
 */
class LeoFacadeOkHttpClient(
    private val transport: LeonaCryptoTransport,
    private val assertions: LeonaCryptoAssertionProvider,
    private val scopes: LeonaCryptoScopeProvider,
    private val responseCommitments: () -> LeonaCryptoScopeCommitments,
    private val endpoint: HttpUrl,
    private val httpClient: OkHttpClient = OkHttpClient(),
    private val clockMs: () -> Long = System::currentTimeMillis,
) {
    init {
        require(endpoint.query == null && endpoint.fragment == null) {
            "encrypted endpoint must not contain query or fragment"
        }
        require(endpoint.isHttps || endpoint.host in setOf("127.0.0.1", "localhost", "::1")) {
            "encrypted endpoint must use HTTPS; HTTP is only allowed for loopback tests"
        }
    }

    fun execute(request: LeonaCryptoHttpRequest): LeonaCryptoResult<LeonaCryptoHttpResponse> {
        val sealed = when (val result = transport.seal(request, assertions, scopes)) {
            is LeonaCryptoResult.Success -> result.value
            is LeonaCryptoResult.Failure -> return result
        }
        val body = LeonaCryptoEnvelopeCodec.encodeRequest(sealed)
            .toRequestBody(LeonaCryptoEnvelopeCodec.CONTENT_TYPE.toMediaType())
        val outbound = Request.Builder()
            .url(endpoint)
            .header("Content-Type", LeonaCryptoEnvelopeCodec.CONTENT_TYPE)
            .header("Accept", LeonaCryptoEnvelopeCodec.CONTENT_TYPE)
            .post(body)
            .build()
        return try {
            httpClient.newCall(outbound).execute().use { response ->
                if (!response.isSuccessful) {
                    return LeonaCryptoResult.Failure(LeonaCryptoErrorCode.NETWORK_FAILURE)
                }
                val responseBody = response.body?.bytes()
                    ?: return LeonaCryptoResult.Failure(LeonaCryptoErrorCode.PROTOCOL_ERROR)
                val sealedResponse = try {
                    LeonaCryptoEnvelopeCodec.decodeResponse(responseBody)
                } catch (_: IllegalArgumentException) {
                    return LeonaCryptoResult.Failure(LeonaCryptoErrorCode.PROTOCOL_ERROR)
                }
                transport.openResponse(
                    sealedResponse.encryptedWire,
                    responseCommitments(),
                    clockMs(),
                )
            }
        } catch (_: Exception) {
            LeonaCryptoResult.Failure(LeonaCryptoErrorCode.NETWORK_FAILURE)
        }
    }
}

private fun AssertionRequestContext.toStable() = LeonaCryptoRequestContext(
    method = method,
    authority = authority,
    path = path,
    query = query,
    contentType = contentType,
    protectedHeaders = protectedHeaders.copyOf(),
    body = body.copyOf(),
)

private fun LeonaCryptoPreparedAssertion.toExternal() = PreparedAssertionContext(
    format,
    audience,
    challenge.copyOf(),
    issuedAtMs,
    expiresAtMs,
)

private fun PreparedAssertionContext.toStable() = LeonaCryptoPreparedAssertion(
    format,
    audience,
    challenge.copyOf(),
    issuedAtMs,
    expiresAtMs,
)

private fun LeonaCryptoScopeCommitments.toExternal() = ScopeCommitments(
    deployment.copyOf(),
    tenant.copyOf(),
    policy.copyOf(),
)

private fun com.leo.crypto.facade.SealedRequestPacket.toStable() = LeonaCryptoSealedRequest(
    encryptedWire = encryptedWire.copyOf(),
    assertionEnvelope = io.leonasec.leona.crypto.LeonaCryptoAssertionEnvelope(
        context = assertionEnvelope.context.toStable(),
        contextDigest = assertionEnvelope.contextDigest.copyOf(),
        assertion = assertionEnvelope.assertion.copyOf(),
    ),
)

private fun externalFailure(result: LeoResult<*>): LeonaCryptoResult.Failure = when (result) {
    is LeoResult.Failure -> LeonaCryptoResult.Failure(
        code = LeonaCryptoErrorCode.CRYPTO_FAILURE,
        providerStatus = result.diagnostic.status.name,
    )

    is LeoResult.Success -> LeonaCryptoResult.Failure(LeonaCryptoErrorCode.PROTOCOL_ERROR)
}
