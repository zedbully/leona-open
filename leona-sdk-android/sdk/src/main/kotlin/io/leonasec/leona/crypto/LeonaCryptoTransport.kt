/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.crypto

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/** Stable, evidence-agnostic request model passed to an optional crypto provider. */
data class LeonaCryptoHttpRequest(
    val method: String,
    val authority: String,
    val path: String,
    val query: String = "",
    val contentType: String = "",
    val protectedHeaders: ByteArray = ByteArray(0),
    val body: ByteArray = ByteArray(0),
) {
    init {
        require(method.isNotBlank()) { "method is required" }
        require(authority.isNotBlank()) { "authority is required" }
        require(path.isNotBlank()) { "path is required" }
        require(protectedHeaders.size <= LeonaCryptoEnvelopeCodec.MAX_TOTAL_BYTES) {
            "protectedHeaders exceeds input limit"
        }
        require(body.size <= LeonaCryptoEnvelopeCodec.MAX_TOTAL_BYTES) {
            "body exceeds input limit"
        }
        require(protectedHeaders.size.toLong() + body.size <= LeonaCryptoEnvelopeCodec.MAX_TOTAL_BYTES) {
            "request exceeds input limit"
        }
    }
}

/** Provider input; bytes are opaque to this SDK and are never interpreted as device identity. */
data class LeonaCryptoRequestContext(
    val method: String,
    val authority: String,
    val path: String,
    val query: String,
    val contentType: String,
    val protectedHeaders: ByteArray,
    val body: ByteArray,
)

data class LeonaCryptoPreparedAssertion(
    val format: String,
    val audience: String,
    val challenge: ByteArray,
    val issuedAtMs: Long,
    val expiresAtMs: Long,
) {
    init {
        require(format.isNotBlank() && format.toByteArray(StandardCharsets.UTF_8).size <= 128) {
            "invalid assertion format"
        }
        require(audience.isNotBlank() && audience.toByteArray(StandardCharsets.UTF_8).size <= 4096) {
            "invalid assertion audience"
        }
        require(challenge.isNotEmpty() && challenge.size <= 4096) { "invalid assertion challenge" }
        require(issuedAtMs >= 0 && expiresAtMs > issuedAtMs) { "invalid assertion lifetime" }
    }
}

/** Three opaque 32-byte commitments. They are locally expected values, not client claims. */
data class LeonaCryptoScopeCommitments(
    val deployment: ByteArray,
    val tenant: ByteArray,
    val policy: ByteArray,
) {
    init {
        require(deployment.size == SCOPE_COMMITMENT_BYTES) { "deployment commitment must be 32 bytes" }
        require(tenant.size == SCOPE_COMMITMENT_BYTES) { "tenant commitment must be 32 bytes" }
        require(policy.size == SCOPE_COMMITMENT_BYTES) { "policy commitment must be 32 bytes" }
    }

    companion object {
        const val SCOPE_COMMITMENT_BYTES = 32
    }
}

data class LeonaCryptoAssertionEnvelope(
    val context: LeonaCryptoPreparedAssertion,
    val contextDigest: ByteArray,
    val assertion: ByteArray,
) {
    init {
        require(contextDigest.size == CONTEXT_DIGEST_BYTES) { "context digest must be 32 bytes" }
        require(assertion.isNotEmpty()) { "assertion is required" }
    }

    companion object {
        const val CONTEXT_DIGEST_BYTES = 32
    }
}

data class LeonaCryptoSealedRequest(
    val encryptedWire: ByteArray,
    val assertionEnvelope: LeonaCryptoAssertionEnvelope,
) {
    init {
        require(encryptedWire.isNotEmpty()) { "encrypted wire is required" }
        require(
            encryptedWire.size.toLong() + assertionEnvelope.assertion.size <=
                LeonaCryptoEnvelopeCodec.MAX_TOTAL_BYTES,
        ) { "request exceeds input limit" }
    }
}

data class LeonaCryptoHttpResponse(
    val statusCode: Int,
    val protectedHeaders: ByteArray = ByteArray(0),
    val body: ByteArray = ByteArray(0),
) {
    init {
        require(statusCode in 100..599) { "statusCode must be an HTTP status" }
    }
}

/** Outer response envelope. Status, headers, and body remain inside the encrypted wire. */
data class LeonaCryptoSealedResponse(val encryptedWire: ByteArray) {
    init {
        require(encryptedWire.isNotEmpty()) { "encrypted response wire is required" }
        require(encryptedWire.size <= LeonaCryptoEnvelopeCodec.MAX_TOTAL_BYTES) {
            "encrypted response wire exceeds input limit"
        }
    }
}

data class LeonaCryptoCapabilities(
    val protocolMajor: Int,
    val adapterVersion: String,
    val providerVersion: String,
    val features: Set<String>,
)

interface LeonaCryptoAssertionProvider {
    fun prepare(request: LeonaCryptoRequestContext): LeonaCryptoPreparedAssertion

    /** Returns opaque assertion bytes for the provider-computed context digest. */
    fun issue(
        request: LeonaCryptoRequestContext,
        prepared: LeonaCryptoPreparedAssertion,
        contextDigest: ByteArray,
    ): ByteArray
}

fun interface LeonaCryptoScopeProvider {
    /** The server derives its own expected values; the client never serializes these commitments. */
    fun commitments(context: LeonaCryptoRequestContext): LeonaCryptoScopeCommitments
}

enum class LeonaCryptoErrorCode {
    INVALID_INPUT,
    NETWORK_FAILURE,
    SDK_MISSING,
    SDK_INCOMPATIBLE,
    PROTOCOL_ERROR,
    PROVIDER_FAILURE,
    CRYPTO_FAILURE,
    CLOSED,
}

sealed class LeonaCryptoResult<out T> {
    data class Success<T>(val value: T) : LeonaCryptoResult<T>()

    /** Deliberately bounded and non-sensitive; provider exception text is never propagated. */
    data class Failure(
        val code: LeonaCryptoErrorCode,
        val providerStatus: String? = null,
    ) : LeonaCryptoResult<Nothing>()
}

/** Optional transport boundary. The default Leona SDK never instantiates an implementation. */
interface LeonaCryptoTransport : AutoCloseable {
    val capabilities: LeonaCryptoCapabilities

    fun seal(
        request: LeonaCryptoHttpRequest,
        assertions: LeonaCryptoAssertionProvider,
        scopes: LeonaCryptoScopeProvider,
    ): LeonaCryptoResult<LeonaCryptoSealedRequest>

    fun openResponse(
        encryptedWire: ByteArray,
        commitments: LeonaCryptoScopeCommitments,
        nowMs: Long,
    ): LeonaCryptoResult<LeonaCryptoHttpResponse>
}

/**
 * Caller-owned HTTP framing for the optional Leo facade. It is a versioned binary
 * envelope beside the encrypted wire; scope commitments are intentionally absent.
 *
 * Cleartext HTTP headers may carry routing metadata only. Application headers and
 * body bytes must be supplied through [LeonaCryptoHttpRequest.protectedHeaders] and
 * [LeonaCryptoHttpRequest.body].
 */
object LeonaCryptoEnvelopeCodec {
    const val CONTENT_TYPE = "application/vnd.leona.crypto.v1+octet-stream"
    const val PROTOCOL_MAJOR = 1
    const val MAX_TOTAL_BYTES = 8 * 1024 * 1024
    const val MAX_ASSERTION_BYTES = 1024 * 1024

    private const val REQUEST_KIND = 1
    private const val RESPONSE_KIND = 2
    private const val MAX_TEXT_BYTES = 4096
    private const val MAX_FORMAT_BYTES = 128
    private const val MAX_CHALLENGE_BYTES = 4096
    private val MAGIC = "LEONA-CRYPTO".toByteArray(StandardCharsets.US_ASCII)

    fun encodeRequest(packet: LeonaCryptoSealedRequest): ByteArray {
        val writer = Writer()
        writer.header(REQUEST_KIND)
        writer.bytes(packet.encryptedWire, MAX_TOTAL_BYTES)
        val context = packet.assertionEnvelope.context
        writer.text(context.format, MAX_FORMAT_BYTES)
        writer.text(context.audience, MAX_TEXT_BYTES)
        writer.bytes(context.challenge, MAX_CHALLENGE_BYTES)
        writer.long(context.issuedAtMs)
        writer.long(context.expiresAtMs)
        writer.fixed(packet.assertionEnvelope.contextDigest, LeonaCryptoAssertionEnvelope.CONTEXT_DIGEST_BYTES)
        writer.bytes(packet.assertionEnvelope.assertion, MAX_ASSERTION_BYTES)
        return writer.finish(MAX_TOTAL_BYTES)
    }

    fun decodeRequest(encoded: ByteArray): LeonaCryptoSealedRequest {
        val reader = Reader(encoded)
        reader.header(REQUEST_KIND)
        val wire = reader.bytes(MAX_TOTAL_BYTES, required = true)
        val context = LeonaCryptoPreparedAssertion(
            format = reader.text(MAX_FORMAT_BYTES, required = true),
            audience = reader.text(MAX_TEXT_BYTES, required = true),
            challenge = reader.bytes(MAX_CHALLENGE_BYTES, required = true),
            issuedAtMs = reader.long(),
            expiresAtMs = reader.long(),
        )
        require(context.issuedAtMs >= 0 && context.expiresAtMs > context.issuedAtMs) {
            "invalid assertion lifetime"
        }
        val digest = reader.fixed(LeonaCryptoAssertionEnvelope.CONTEXT_DIGEST_BYTES)
        val assertion = reader.bytes(MAX_ASSERTION_BYTES, required = true)
        reader.finish()
        require(wire.size.toLong() + assertion.size <= MAX_TOTAL_BYTES) { "request exceeds input limit" }
        return LeonaCryptoSealedRequest(
            encryptedWire = wire,
            assertionEnvelope = LeonaCryptoAssertionEnvelope(context, digest, assertion),
        )
    }

    fun encodeResponse(response: LeonaCryptoSealedResponse): ByteArray {
        val writer = Writer()
        writer.header(RESPONSE_KIND)
        writer.bytes(response.encryptedWire, MAX_TOTAL_BYTES)
        return writer.finish(MAX_TOTAL_BYTES)
    }

    fun decodeResponse(encoded: ByteArray): LeonaCryptoSealedResponse {
        val reader = Reader(encoded)
        reader.header(RESPONSE_KIND)
        val wire = reader.bytes(MAX_TOTAL_BYTES, required = true)
        reader.finish()
        return LeonaCryptoSealedResponse(wire)
    }

    private class Writer {
        private val output = ByteArrayOutputStream()

        fun header(kind: Int) {
            output.write(MAGIC)
            output.write(PROTOCOL_MAJOR)
            output.write(kind)
            output.write(0)
            output.write(0)
        }

        fun text(value: String, maxBytes: Int) = bytes(value.toByteArray(StandardCharsets.UTF_8), maxBytes)

        fun bytes(value: ByteArray, maxBytes: Int) {
            require(value.size <= maxBytes) { "field exceeds input limit" }
            int(value.size)
            output.write(value)
        }

        fun fixed(value: ByteArray, expectedBytes: Int) {
            require(value.size == expectedBytes) { "fixed field has wrong length" }
            output.write(value)
        }

        fun int(value: Int) {
            output.write((value ushr 24) and 0xff)
            output.write((value ushr 16) and 0xff)
            output.write((value ushr 8) and 0xff)
            output.write(value and 0xff)
        }

        fun long(value: Long) {
            val buffer = ByteBuffer.allocate(Long.SIZE_BYTES).order(ByteOrder.BIG_ENDIAN)
            buffer.putLong(value)
            output.write(buffer.array())
        }

        fun finish(maxBytes: Int): ByteArray {
            val result = output.toByteArray()
            require(result.size <= maxBytes) { "envelope exceeds input limit" }
            return result
        }
    }

    private class Reader(private val encoded: ByteArray) {
        private var offset = 0

        init {
            require(encoded.size <= MAX_TOTAL_BYTES) { "envelope exceeds input limit" }
        }

        fun header(expectedKind: Int) {
            require(read(MAGIC.size).contentEquals(MAGIC)) { "invalid envelope magic" }
            require(u8() == PROTOCOL_MAJOR) { "unsupported envelope version" }
            require(u8() == expectedKind) { "unexpected envelope kind" }
            require(u8() == 0 && u8() == 0) { "invalid envelope flags" }
        }

        fun text(maxBytes: Int, required: Boolean = false): String {
            val value = decodeUtf8(bytes(maxBytes, required))
            if (required) require(value.isNotBlank()) { "required text is blank" }
            return value
        }

        fun bytes(maxBytes: Int, required: Boolean = false): ByteArray {
            val length = int()
            require(length >= 0 && length <= maxBytes) { "field exceeds input limit" }
            if (required) require(length > 0) { "required bytes are empty" }
            return read(length)
        }

        fun fixed(expectedBytes: Int): ByteArray = read(expectedBytes)

        fun int(): Int {
            val value = read(4)
            return ((value[0].toInt() and 0xff) shl 24) or
                ((value[1].toInt() and 0xff) shl 16) or
                ((value[2].toInt() and 0xff) shl 8) or
                (value[3].toInt() and 0xff)
        }

        fun long(): Long {
            return ByteBuffer.wrap(read(Long.SIZE_BYTES)).order(ByteOrder.BIG_ENDIAN).long
        }

        fun finish() = require(offset == encoded.size) { "trailing envelope bytes" }

        private fun u8(): Int = read(1)[0].toInt() and 0xff

        private fun read(length: Int): ByteArray {
            require(length >= 0 && encoded.size - offset >= length) { "truncated envelope" }
            return encoded.copyOfRange(offset, offset + length).also { offset += length }
        }

        private fun decodeUtf8(value: ByteArray): String {
            return try {
                StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(value))
                    .toString()
            } catch (_: CharacterCodingException) {
                throw IllegalArgumentException("invalid UTF-8")
            }
        }
    }
}
