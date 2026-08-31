/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.proto

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/** The only response value accepted by the typed sense path. */
internal data class LeonaEvidenceIngestResponseModel(
    val protocolMajor: Int,
    val requestId: String,
    val requestCarrierSha256: ByteArray,
    val responseId: ByteArray,
    val boxId: String,
    val serverInstallId: String,
    val canonicalDeviceId: String,
    val issuedAtEpochMs: Long,
    val boxExpiresAtEpochMs: Long,
    val collectionStatus: LeonaCollectionStatus = LeonaCollectionStatus.ACCEPTED,
) {
    fun requestDigest(): ByteArray = requestCarrierSha256.copyOf()
    fun responseIdentifier(): ByteArray = responseId.copyOf()
}

internal enum class LeonaCollectionStatus { ACCEPTED }

internal enum class LeonaResponseProtobufFailureCode {
    INVALID_INPUT,
    OVERSIZE,
    MALFORMED_WIRE,
    UNKNOWN_FIELD,
    DUPLICATE_FIELD,
    OUT_OF_ORDER_FIELD,
    NON_MINIMAL_VARINT,
    UNKNOWN_ENUM,
    INVALID_UTF8,
    REQUEST_ID_MISMATCH,
    REQUEST_DIGEST_MISMATCH,
}

internal data class LeonaResponseProtobufFailure(
    val code: LeonaResponseProtobufFailureCode,
    val detail: String,
)

internal sealed interface LeonaResponseProtobufDecodeResult {
    data class Success(val response: LeonaEvidenceIngestResponseModel) : LeonaResponseProtobufDecodeResult
    data class Failure(val error: LeonaResponseProtobufFailure) : LeonaResponseProtobufDecodeResult
}

internal sealed interface LeonaResponseProtobufEncodeResult {
    data class Success(val bytes: ByteArray) : LeonaResponseProtobufEncodeResult {
        override fun toString(): String = "Success(${bytes.size} bytes)"
    }
    data class Failure(val error: LeonaResponseProtobufFailure) : LeonaResponseProtobufEncodeResult
}

/** Strict, deterministic codec for response.proto (not a business verdict codec). */
internal object LeonaEvidenceResponseProtobufCodec {
    const val MAX_PAYLOAD_BYTES = 65_536
    const val MAX_STRING_BYTES = 128
    const val PAYLOAD_CODEC = "LEONA_PROTOBUF"
    const val PAYLOAD_SCHEMA = "leona.evidence.response.v1"
    const val MESSAGE_TYPE = "leona.evidence.response.v1.EvidenceIngestResponse"
    const val DESCRIPTOR_SHA256_HEX = "01ca791bcbd4e7727da47e8d0351538c32e4f40394927676372a4d8d23ca6e73"
    private val descriptorBytes = hex(DESCRIPTOR_SHA256_HEX)
    val DESCRIPTOR_SHA256: ByteArray get() = descriptorBytes.copyOf()

    fun encode(response: LeonaEvidenceIngestResponseModel): LeonaResponseProtobufEncodeResult {
        val failure = validate(response)
        if (failure != null) return LeonaResponseProtobufEncodeResult.Failure(failure)
        return try {
            val out = ByteArrayOutputStream()
            fieldVarint(out, 1, response.protocolMajor.toLong())
            fieldString(out, 2, response.requestId)
            fieldBytes(out, 3, response.requestCarrierSha256)
            fieldBytes(out, 4, response.responseId)
            fieldString(out, 5, response.boxId)
            fieldString(out, 6, response.serverInstallId)
            fieldString(out, 7, response.canonicalDeviceId)
            fieldVarint(out, 8, response.issuedAtEpochMs)
            fieldVarint(out, 9, response.boxExpiresAtEpochMs)
            fieldVarint(out, 10, 1L)
            val bytes = out.toByteArray()
            if (bytes.size > MAX_PAYLOAD_BYTES) {
                LeonaResponseProtobufEncodeResult.Failure(
                    LeonaResponseProtobufFailure(LeonaResponseProtobufFailureCode.OVERSIZE, "response exceeds 65536 bytes"),
                )
            } else {
                LeonaResponseProtobufEncodeResult.Success(bytes)
            }
        } catch (_: RuntimeException) {
            LeonaResponseProtobufEncodeResult.Failure(
                LeonaResponseProtobufFailure(LeonaResponseProtobufFailureCode.INVALID_INPUT, "response encoding failed"),
            )
        }
    }

    fun encodeResponse(response: LeonaEvidenceIngestResponseModel): LeonaResponseProtobufEncodeResult = encode(response)

    fun decode(
        bytes: ByteArray,
        expectedRequestId: String? = null,
        expectedCarrierDigest: ByteArray? = null,
    ): LeonaResponseProtobufDecodeResult {
        if (bytes.isEmpty() || bytes.size > MAX_PAYLOAD_BYTES) {
            return failure(LeonaResponseProtobufFailureCode.OVERSIZE, "response payload outside 1..65536 bytes")
        }
        return try {
            val reader = Reader(bytes)
            var protocol: Long? = null
            var requestId: String? = null
            var requestDigest: ByteArray? = null
            var responseId: ByteArray? = null
            var boxId: String? = null
            var serverInstallId: String? = null
            var canonicalDeviceId: String? = null
            var issued: Long? = null
            var expires: Long? = null
            var status: Long? = null
            var previousField = 0
            val seen = HashSet<Int>()
            while (reader.hasRemaining()) {
                val tag = reader.varint()
                if (tag > Int.MAX_VALUE.toULong()) throw ParseFailure(LeonaResponseProtobufFailureCode.UNKNOWN_FIELD, "tag overflow")
                val field = (tag.toInt() ushr 3)
                val wire = tag.toInt() and 7
                if (field <= 0) throw ParseFailure(LeonaResponseProtobufFailureCode.UNKNOWN_FIELD, "field zero")
                if (!seen.add(field)) throw ParseFailure(LeonaResponseProtobufFailureCode.DUPLICATE_FIELD, "duplicate singular field")
                if (field < previousField) throw ParseFailure(LeonaResponseProtobufFailureCode.OUT_OF_ORDER_FIELD, "fields must be ascending")
                previousField = field
                when (field) {
                    1 -> { requireWire(wire, 0); protocol = reader.varint().toLong() }
                    2 -> { requireWire(wire, 2); requestId = reader.string(MAX_STRING_BYTES) }
                    3 -> { requireWire(wire, 2); requestDigest = reader.bytes(32) }
                    4 -> { requireWire(wire, 2); responseId = reader.bytes(16) }
                    5 -> { requireWire(wire, 2); boxId = reader.string(MAX_STRING_BYTES) }
                    6 -> { requireWire(wire, 2); serverInstallId = reader.string(MAX_STRING_BYTES) }
                    7 -> { requireWire(wire, 2); canonicalDeviceId = reader.string(MAX_STRING_BYTES) }
                    8 -> { requireWire(wire, 0); issued = reader.varint().toLong() }
                    9 -> { requireWire(wire, 0); expires = reader.varint().toLong() }
                    10 -> { requireWire(wire, 0); status = reader.varint().toLong() }
                    else -> throw ParseFailure(LeonaResponseProtobufFailureCode.UNKNOWN_FIELD, "unknown or reserved field")
                }
            }
            val model = LeonaEvidenceIngestResponseModel(
                protocolMajor = protocol?.takeIf { it <= Int.MAX_VALUE }?.toInt() ?: throw ParseFailure(LeonaResponseProtobufFailureCode.INVALID_INPUT, "protocol missing"),
                requestId = requestId ?: throw ParseFailure(LeonaResponseProtobufFailureCode.INVALID_INPUT, "request id missing"),
                requestCarrierSha256 = requestDigest ?: throw ParseFailure(LeonaResponseProtobufFailureCode.INVALID_INPUT, "request digest missing"),
                responseId = responseId ?: throw ParseFailure(LeonaResponseProtobufFailureCode.INVALID_INPUT, "response id missing"),
                boxId = boxId ?: throw ParseFailure(LeonaResponseProtobufFailureCode.INVALID_INPUT, "box id missing"),
                serverInstallId = serverInstallId ?: throw ParseFailure(LeonaResponseProtobufFailureCode.INVALID_INPUT, "server install id missing"),
                canonicalDeviceId = canonicalDeviceId ?: throw ParseFailure(LeonaResponseProtobufFailureCode.INVALID_INPUT, "canonical id missing"),
                issuedAtEpochMs = issued ?: throw ParseFailure(LeonaResponseProtobufFailureCode.INVALID_INPUT, "issued timestamp missing"),
                boxExpiresAtEpochMs = expires ?: throw ParseFailure(LeonaResponseProtobufFailureCode.INVALID_INPUT, "expiry timestamp missing"),
                collectionStatus = when (status) {
                    1L -> LeonaCollectionStatus.ACCEPTED
                    else -> throw ParseFailure(LeonaResponseProtobufFailureCode.UNKNOWN_ENUM, "collection status is not ACCEPTED")
                },
            )
            validate(model)?.let { return LeonaResponseProtobufDecodeResult.Failure(it) }
            if (expectedRequestId != null && model.requestId != expectedRequestId) {
                return failure(LeonaResponseProtobufFailureCode.REQUEST_ID_MISMATCH, "response request id does not bind to request")
            }
            if (expectedCarrierDigest != null &&
                (!expectedCarrierDigest.contentEquals(model.requestCarrierSha256) || expectedCarrierDigest.size != 32)
            ) {
                return failure(LeonaResponseProtobufFailureCode.REQUEST_DIGEST_MISMATCH, "response request digest does not bind to carrier")
            }
            LeonaResponseProtobufDecodeResult.Success(model)
        } catch (error: ParseFailure) {
            failure(error.code, error.message ?: "malformed response")
        } catch (_: RuntimeException) {
            failure(LeonaResponseProtobufFailureCode.MALFORMED_WIRE, "malformed response protobuf")
        }
    }

    fun decodeResponse(
        bytes: ByteArray,
        expectedRequestId: String? = null,
        expectedCarrierDigest: ByteArray? = null,
    ): LeonaResponseProtobufDecodeResult = decode(bytes, expectedRequestId, expectedCarrierDigest)

    fun validate(response: LeonaEvidenceIngestResponseModel): LeonaResponseProtobufFailure? {
        if (response.protocolMajor != 1) return invalid("protocol major must be 1")
        if (!safeAscii(response.requestId, MAX_STRING_BYTES)) return invalid("invalid request id")
        if (response.requestCarrierSha256.size != 32) return invalid("request digest must be 32 bytes")
        if (response.responseId.size != 16) return invalid("response id must be 16 bytes")
        if (!printableAscii(response.boxId, MAX_STRING_BYTES)) return invalid("invalid box id")
        if (!Regex("^I[0-9a-f]{32}$").matches(response.serverInstallId)) return invalid("invalid server install id")
        if (!Regex("^L[0-9a-f]{32}$").matches(response.canonicalDeviceId)) return invalid("invalid canonical id")
        if (response.issuedAtEpochMs <= 0 || response.boxExpiresAtEpochMs <= response.issuedAtEpochMs) return invalid("invalid response lifetime")
        if (response.collectionStatus != LeonaCollectionStatus.ACCEPTED) return invalid("collection status must be ACCEPTED")
        return null
    }

    private fun safeAscii(value: String, maxBytes: Int): Boolean {
        val bytes = value.toByteArray(StandardCharsets.UTF_8)
        return value.isNotEmpty() && bytes.size <= maxBytes && bytes.all { it.toInt() in 0x21..0x7e }
    }

    private fun printableAscii(value: String, maxBytes: Int): Boolean {
        val bytes = value.toByteArray(StandardCharsets.UTF_8)
        return value.isNotEmpty() && bytes.size <= maxBytes && bytes.all { it.toInt() in 0x20..0x7e }
    }

    private fun fieldString(out: ByteArrayOutputStream, field: Int, value: String) = fieldBytes(out, field, value.toByteArray(StandardCharsets.UTF_8))
    private fun fieldBytes(out: ByteArrayOutputStream, field: Int, value: ByteArray) {
        out.write((field shl 3) or 2)
        varint(out, value.size.toLong())
        out.write(value)
    }
    private fun fieldVarint(out: ByteArrayOutputStream, field: Int, value: Long) {
        out.write(field shl 3)
        varint(out, value)
    }
    private fun varint(out: ByteArrayOutputStream, value: Long) {
        var current = value
        while (current and -0x80L != 0L) {
            out.write((current.toInt() and 0x7f) or 0x80)
            current = current ushr 7
        }
        out.write(current.toInt() and 0x7f)
    }
    private fun requireWire(actual: Int, expected: Int) {
        if (actual != expected) throw ParseFailure(LeonaResponseProtobufFailureCode.MALFORMED_WIRE, "wrong wire type")
    }
    private fun failure(code: LeonaResponseProtobufFailureCode, detail: String) =
        LeonaResponseProtobufDecodeResult.Failure(LeonaResponseProtobufFailure(code, detail))
    private fun invalid(detail: String) = LeonaResponseProtobufFailure(LeonaResponseProtobufFailureCode.INVALID_INPUT, detail)
    private fun hex(value: String): ByteArray = ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private class ParseFailure(val code: LeonaResponseProtobufFailureCode, message: String) : IllegalArgumentException(message)

    private class Reader(private val bytes: ByteArray) {
        private var offset = 0
        fun hasRemaining() = offset < bytes.size
        fun varint(): ULong {
            val start = offset
            var result = 0UL
            for (index in 0 until 10) {
                if (offset >= bytes.size) throw ParseFailure(LeonaResponseProtobufFailureCode.MALFORMED_WIRE, "truncated varint")
                val byte = bytes[offset++].toInt() and 0xff
                if (index == 9 && byte > 1) throw ParseFailure(LeonaResponseProtobufFailureCode.MALFORMED_WIRE, "varint overflow")
                result = result or ((byte and 0x7f).toULong() shl (index * 7))
                if ((byte and 0x80) == 0) {
                    if (offset - start > 1 && (byte and 0x7f) == 0) {
                        throw ParseFailure(LeonaResponseProtobufFailureCode.NON_MINIMAL_VARINT, "non-minimal varint")
                    }
                    return result
                }
            }
            throw ParseFailure(LeonaResponseProtobufFailureCode.MALFORMED_WIRE, "varint too long")
        }
        fun bytes(max: Int): ByteArray {
            val length = varint()
            if (length > max.toULong() || length > Int.MAX_VALUE.toULong()) throw ParseFailure(LeonaResponseProtobufFailureCode.OVERSIZE, "length exceeds bound")
            val end = offset + length.toInt()
            if (end < offset || end > bytes.size) throw ParseFailure(LeonaResponseProtobufFailureCode.MALFORMED_WIRE, "truncated bytes")
            return bytes.copyOfRange(offset, end).also { offset = end }
        }
        fun string(max: Int): String {
            val value = bytes(max)
            return try {
                StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(value)).toString()
            } catch (_: CharacterCodingException) {
                throw ParseFailure(LeonaResponseProtobufFailureCode.INVALID_UTF8, "invalid UTF-8")
            }
        }
    }
}
