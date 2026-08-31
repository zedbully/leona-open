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
import okhttp3.CookieJar
import okhttp3.Headers
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.MediaType.Companion.toMediaType
import okio.Buffer
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
                val declaredLength = declaredContentLength(response.headers)
                val encodedResponse = response.body?.use { body ->
                    readBoundedBody(body, declaredLength)
                }
                    ?: return@use LeonaCryptoResult.Failure(LeonaCryptoErrorCode.PROTOCOL_ERROR)
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
        } catch (_: StrictOuterResponseException) {
            LeonaCryptoResult.Failure(LeonaCryptoErrorCode.PROTOCOL_ERROR)
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
            .cookieJar(CookieJar.NO_COOKIES)
            .addNetworkInterceptor(StrictOuterResponseInterceptor())
        if (certificatePins.isNotEmpty()) {
            val pinner = CertificatePinner.Builder()
            certificatePins.forEach { (host, pins) ->
                pins.forEach { pin -> pinner.add(host, pin) }
            }
            builder.certificatePinner(pinner.build())
        }
        return builder.build()
    }

    private fun readBoundedBody(body: ResponseBody, declaredLength: Long?): ByteArray? {
        val buffer = Buffer()
        var total = 0L
        val source = body.source()
        while (true) {
            val read = source.read(buffer, BODY_READ_CHUNK_BYTES.toLong())
            if (read == -1L) break
            total += read
            if (total > LeonaCryptoEnvelopeCodec.MAX_TOTAL_BYTES) return null
        }
        if (declaredLength != null && total != declaredLength) {
            throw StrictOuterResponseException("content-length does not match body bytes")
        }
        return buffer.readByteArray()
    }

    private fun declaredContentLength(headers: Headers): Long? {
        val values = headers.values("Content-Length")
        if (values.isEmpty()) return null
        if (values.size > 1) {
            throw StrictOuterResponseException("duplicate content-length")
        }
        val value = values.single()
        if (!value.matches(DECIMAL_LENGTH)) {
            throw StrictOuterResponseException("invalid content-length")
        }
        val length = value.toLongOrNull()
            ?: throw StrictOuterResponseException("content-length overflow")
        if (length > LeonaCryptoEnvelopeCodec.MAX_TOTAL_BYTES) {
            throw StrictOuterResponseException("content-length exceeds envelope limit")
        }
        return length
    }

    private class StrictOuterResponseException(message: String) : IOException(message)

    private inner class StrictOuterResponseInterceptor : Interceptor {
        override fun intercept(chain: Interceptor.Chain): Response {
            val response = chain.proceed(chain.request())
            try {
                validate(response)
                return response
            } catch (error: StrictOuterResponseException) {
                response.close()
                throw error
            }
        }

        private fun validate(response: Response) {
            val headers = response.headers
            for (index in 0 until headers.size) {
                rejectControlCharacters(headers.name(index), "header name")
                rejectControlCharacters(headers.value(index), "header value")
            }

            val contentTypes = headers.values("Content-Type")
            if (contentTypes.size != 1 || contentTypes.single() != LeonaCryptoEnvelopeCodec.CONTENT_TYPE) {
                throw StrictOuterResponseException("strict content-type cardinality/value violation")
            }

            if (headers.values("Content-Encoding").isNotEmpty()) {
                throw StrictOuterResponseException("content-encoding is forbidden")
            }
            if (headers.values("Set-Cookie").isNotEmpty()) {
                throw StrictOuterResponseException("set-cookie is forbidden")
            }

            declaredContentLength(headers)
        }

        private fun rejectControlCharacters(value: String, field: String) {
            if (value.any { it.code < 0x20 || it.code == 0x7f }) {
                throw StrictOuterResponseException("control character in $field")
            }
        }

    }

    private companion object {
        val LOOPBACK_HOSTS = setOf("127.0.0.1", "localhost", "::1")
        val ENVELOPE_MEDIA_TYPE = LeonaCryptoEnvelopeCodec.CONTENT_TYPE.toMediaType()
        const val BODY_READ_CHUNK_BYTES = 8 * 1024
        val DECIMAL_LENGTH = Regex("^[0-9]+$")

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
