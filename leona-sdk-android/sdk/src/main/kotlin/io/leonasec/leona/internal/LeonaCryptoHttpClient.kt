/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal

import io.leonasec.leona.crypto.LeonaCryptoChannel
import io.leonasec.leona.crypto.LeonaCryptoEnvelopeCodec
import io.leonasec.leona.crypto.LeonaCryptoErrorCode
import io.leonasec.leona.crypto.LeonaCryptoHttpRequest
import io.leonasec.leona.crypto.LeonaCryptoHttpResponse
import io.leonasec.leona.crypto.LeonaCryptoProtectedHeadersCodec
import io.leonasec.leona.crypto.LeonaCryptoRequestContext
import io.leonasec.leona.crypto.LeonaCryptoResult
import okhttp3.CertificatePinner
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.MediaType.Companion.toMediaType
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * The only SDK HTTP framing implementation. It sends routing-only headers and
 * delegates all application fields/body encryption and response verification to
 * the caller-owned Leo channel.
 */
internal class LeonaCryptoHttpClient(
    private val channel: LeonaCryptoChannel,
    endpointUrl: String,
    certificatePins: Map<String, Set<String>>,
    callTimeoutSeconds: Long,
    connectTimeoutSeconds: Long,
    readTimeoutSeconds: Long,
) {
    private val endpoint: HttpUrl = endpointUrl.toHttpUrlOrNull()
        ?: throw IllegalArgumentException("encrypted endpoint must be an absolute URL")
    private val httpClient: OkHttpClient = buildHttpClient(
        certificatePins = certificatePins,
        callTimeoutSeconds = callTimeoutSeconds,
        connectTimeoutSeconds = connectTimeoutSeconds,
        readTimeoutSeconds = readTimeoutSeconds,
    )

    init {
        require(endpoint.query == null && endpoint.fragment == null) {
            "encrypted endpoint must not contain query or fragment"
        }
        require(endpoint.isHttps || endpoint.host in LOOPBACK_HOSTS) {
            "encrypted endpoint must use HTTPS; HTTP is only allowed for loopback tests"
        }
    }

    fun execute(request: LeonaCryptoHttpRequest): LeonaCryptoResult<LeonaCryptoHttpResponse> {
        val context = request.toContext()
        val sealed = try {
            channel.transport.seal(
                request,
                channel.assertions,
                channel.scopes,
            )
        } catch (_: IllegalArgumentException) {
            return LeonaCryptoResult.Failure(LeonaCryptoErrorCode.INVALID_INPUT)
        } catch (_: Exception) {
            return LeonaCryptoResult.Failure(LeonaCryptoErrorCode.PROVIDER_FAILURE)
        }
        val packet = when (sealed) {
            is LeonaCryptoResult.Success -> sealed.value
            is LeonaCryptoResult.Failure -> return sealed
        }
        val encodedRequest = try {
            LeonaCryptoEnvelopeCodec.encodeRequest(packet)
        } catch (_: IllegalArgumentException) {
            return LeonaCryptoResult.Failure(LeonaCryptoErrorCode.PROTOCOL_ERROR)
        }
        val outbound = Request.Builder()
            .url(endpoint)
            .header("Content-Type", LeonaCryptoEnvelopeCodec.CONTENT_TYPE)
            .header("Accept", LeonaCryptoEnvelopeCodec.CONTENT_TYPE)
            .post(encodedRequest.toRequestBody(ENVELOPE_MEDIA_TYPE))
            .build()

        return try {
            httpClient.newCall(outbound).execute().use { response ->
                val mediaType = response.header("Content-Type")
                    ?.substringBefore(';')
                    ?.trim()
                    ?.lowercase()
                if (mediaType != LeonaCryptoEnvelopeCodec.CONTENT_TYPE) {
                    return@use LeonaCryptoResult.Failure(LeonaCryptoErrorCode.PROTOCOL_ERROR)
                }
                val encodedResponse = response.body?.bytes()
                    ?: return@use LeonaCryptoResult.Failure(LeonaCryptoErrorCode.PROTOCOL_ERROR)
                if (encodedResponse.size > LeonaCryptoEnvelopeCodec.MAX_TOTAL_BYTES) {
                    return@use LeonaCryptoResult.Failure(LeonaCryptoErrorCode.PROTOCOL_ERROR)
                }
                val sealedResponse = try {
                    LeonaCryptoEnvelopeCodec.decodeResponse(encodedResponse)
                } catch (_: IllegalArgumentException) {
                    return@use LeonaCryptoResult.Failure(LeonaCryptoErrorCode.PROTOCOL_ERROR)
                }
                val commitments = try {
                    channel.responseCommitments.commitments(context)
                } catch (_: IllegalArgumentException) {
                    return@use LeonaCryptoResult.Failure(LeonaCryptoErrorCode.INVALID_INPUT)
                } catch (_: Exception) {
                    return@use LeonaCryptoResult.Failure(LeonaCryptoErrorCode.PROVIDER_FAILURE)
                }
                try {
                    channel.transport.openResponse(
                        sealedResponse.encryptedWire,
                        commitments,
                        System.currentTimeMillis(),
                    )
                } catch (_: IllegalArgumentException) {
                    LeonaCryptoResult.Failure(LeonaCryptoErrorCode.INVALID_INPUT)
                } catch (_: Exception) {
                    LeonaCryptoResult.Failure(LeonaCryptoErrorCode.CRYPTO_FAILURE)
                }
            }
        } catch (_: IOException) {
            LeonaCryptoResult.Failure(LeonaCryptoErrorCode.NETWORK_FAILURE)
        } catch (_: Exception) {
            LeonaCryptoResult.Failure(LeonaCryptoErrorCode.NETWORK_FAILURE)
        }
    }

    private fun buildHttpClient(
        certificatePins: Map<String, Set<String>>,
        callTimeoutSeconds: Long,
        connectTimeoutSeconds: Long,
        readTimeoutSeconds: Long,
    ): OkHttpClient {
        val builder = OkHttpClient.Builder()
            .callTimeout(callTimeoutSeconds, TimeUnit.SECONDS)
            .connectTimeout(connectTimeoutSeconds, TimeUnit.SECONDS)
            .readTimeout(readTimeoutSeconds, TimeUnit.SECONDS)
            .retryOnConnectionFailure(false)
            .followRedirects(false)
            .followSslRedirects(false)
        if (certificatePins.isNotEmpty()) {
            val pinner = CertificatePinner.Builder()
            certificatePins.forEach { (host, pins) ->
                pins.forEach { pin -> pinner.add(host, pin) }
            }
            builder.certificatePinner(pinner.build())
        }
        return builder.build()
    }

    private companion object {
        val LOOPBACK_HOSTS = setOf("127.0.0.1", "localhost", "::1")
        val ENVELOPE_MEDIA_TYPE = LeonaCryptoEnvelopeCodec.CONTENT_TYPE.toMediaType()

        fun LeonaCryptoHttpRequest.toContext() = LeonaCryptoRequestContext(
            method = method,
            authority = authority,
            path = path,
            query = query,
            contentType = contentType,
            protectedHeaders = protectedHeaders.copyOf(),
            body = body.copyOf(),
        )
    }
}
