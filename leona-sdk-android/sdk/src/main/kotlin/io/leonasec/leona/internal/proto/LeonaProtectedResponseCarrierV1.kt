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

/** Response-only LPRESP01 authenticated-body carrier. LPCARR01 is never accepted here. */
internal object LeonaProtectedResponseCarrierV1 {
    const val MAX_PAYLOAD_BYTES = 65_536
    const val FIXED_BYTES_EXCLUDING_PAYLOAD = 173
    const val MAX_CARRIER_BYTES = 65_709
    private const val VERSION = 1
    private const val FIELD_COUNT = 5
    private const val TLV_HEADER_BYTES = 8
    private val MAGIC = "LPRESP01".toByteArray(StandardCharsets.US_ASCII)
    private val CODEC = LeonaEvidenceResponseProtobufCodec.PAYLOAD_CODEC.toByteArray(StandardCharsets.US_ASCII)
    private val SCHEMA = LeonaEvidenceResponseProtobufCodec.PAYLOAD_SCHEMA.toByteArray(StandardCharsets.US_ASCII)
    private val MESSAGE = LeonaEvidenceResponseProtobufCodec.MESSAGE_TYPE.toByteArray(StandardCharsets.US_ASCII)

    sealed interface DecodeResult {
        data class Success(private val carrier: ByteArray, private val protobuf: ByteArray) : DecodeResult {
            val bytes: ByteArray get() = carrier.copyOf()
            val payload: ByteArray get() = protobuf.copyOf()
        }
        data class Failure(val code: FailureCode) : DecodeResult
    }

    sealed interface EncodeResult {
        data class Success(private val carrier: ByteArray) : EncodeResult {
            val bytes: ByteArray get() = carrier.copyOf()
        }
        data class Failure(val code: FailureCode) : EncodeResult
    }

    enum class FailureCode {
        BAD_MAGIC, UNSUPPORTED_VERSION, FIELD_COUNT_MISMATCH, NONZERO_RESERVED,
        UNKNOWN_TAG, DUPLICATE_TAG, OUT_OF_ORDER_TAG, NONZERO_FLAGS, TRUNCATED,
        TRAILING_BYTES, INVALID_UTF8, DESCRIPTOR_MISMATCH, EMPTY_PAYLOAD,
        OVERSIZE, PROTOBUF_REJECTED, INTERNAL_ERROR,
    }

    fun encode(response: LeonaEvidenceIngestResponseModel): EncodeResult = when (val encoded = LeonaEvidenceResponseProtobufCodec.encode(response)) {
        is LeonaResponseProtobufEncodeResult.Success -> encodePayload(encoded.bytes)
        is LeonaResponseProtobufEncodeResult.Failure -> EncodeResult.Failure(
            if (encoded.error.code == LeonaResponseProtobufFailureCode.OVERSIZE) FailureCode.OVERSIZE else FailureCode.PROTOBUF_REJECTED,
        )
    }

    fun encodeResponse(response: LeonaEvidenceIngestResponseModel): EncodeResult = encode(response)

    fun encodePayload(payload: ByteArray): EncodeResult {
        if (payload.isEmpty()) return EncodeResult.Failure(FailureCode.EMPTY_PAYLOAD)
        if (payload.size > MAX_PAYLOAD_BYTES) return EncodeResult.Failure(FailureCode.OVERSIZE)
        if (LeonaEvidenceResponseProtobufCodec.decode(payload) !is LeonaResponseProtobufDecodeResult.Success) {
            return EncodeResult.Failure(FailureCode.PROTOBUF_REJECTED)
        }
        val total = checkedTotal(payload.size) ?: return EncodeResult.Failure(FailureCode.OVERSIZE)
        val output = ByteArrayOutputStream(total)
        output.write(MAGIC)
        output.write(VERSION)
        output.write(FIELD_COUNT)
        writeU16(output, 0)
        writeTlv(output, 1, CODEC)
        writeTlv(output, 2, SCHEMA)
        writeTlv(output, 3, MESSAGE)
        writeTlv(output, 4, LeonaEvidenceResponseProtobufCodec.DESCRIPTOR_SHA256)
        writeTlv(output, 5, payload)
        val carrier = output.toByteArray()
        return if (carrier.size == total && carrier.size <= MAX_CARRIER_BYTES) EncodeResult.Success(carrier)
        else EncodeResult.Failure(FailureCode.INTERNAL_ERROR)
    }

    fun decode(carrier: ByteArray): DecodeResult {
        if (carrier.size > MAX_CARRIER_BYTES) return DecodeResult.Failure(FailureCode.OVERSIZE)
        if (carrier.size < 12) return DecodeResult.Failure(FailureCode.TRUNCATED)
        if (!carrier.copyOfRange(0, MAGIC.size).contentEquals(MAGIC)) return DecodeResult.Failure(FailureCode.BAD_MAGIC)
        if (carrier[8].unsigned() != VERSION) return DecodeResult.Failure(FailureCode.UNSUPPORTED_VERSION)
        if (carrier[9].unsigned() != FIELD_COUNT) return DecodeResult.Failure(FailureCode.FIELD_COUNT_MISMATCH)
        if (u16(carrier, 10) != 0) return DecodeResult.Failure(FailureCode.NONZERO_RESERVED)
        var offset = 12
        var previousTag = 0
        var codec: ByteArray? = null
        var schema: ByteArray? = null
        var message: ByteArray? = null
        var digest: ByteArray? = null
        var payload: ByteArray? = null
        repeat(FIELD_COUNT) {
            if (carrier.size - offset < TLV_HEADER_BYTES) return DecodeResult.Failure(FailureCode.TRUNCATED)
            val tag = carrier[offset].unsigned()
            if (tag !in 1..FIELD_COUNT) return DecodeResult.Failure(FailureCode.UNKNOWN_TAG)
            if (tag == previousTag) return DecodeResult.Failure(FailureCode.DUPLICATE_TAG)
            if (tag < previousTag) return DecodeResult.Failure(FailureCode.OUT_OF_ORDER_TAG)
            if (carrier[offset + 1].unsigned() != 0) return DecodeResult.Failure(FailureCode.NONZERO_FLAGS)
            if (u16(carrier, offset + 2) != 0) return DecodeResult.Failure(FailureCode.NONZERO_RESERVED)
            val length = u32(carrier, offset + 4)
            val valueStart = checkedAdd(offset.toLong(), TLV_HEADER_BYTES.toLong()) ?: return DecodeResult.Failure(FailureCode.OVERSIZE)
            val valueEnd = checkedAdd(valueStart, length) ?: return DecodeResult.Failure(FailureCode.OVERSIZE)
            if (valueEnd > carrier.size.toLong()) return DecodeResult.Failure(FailureCode.TRUNCATED)
            if (length > Int.MAX_VALUE.toLong()) return DecodeResult.Failure(FailureCode.OVERSIZE)
            val value = carrier.copyOfRange(valueStart.toInt(), valueEnd.toInt())
            when (tag) {
                1 -> codec = value
                2 -> schema = value
                3 -> message = value
                4 -> digest = value
                5 -> payload = value
            }
            previousTag = tag
            offset = valueEnd.toInt()
        }
        if (offset != carrier.size) return DecodeResult.Failure(FailureCode.TRAILING_BYTES)
        if (codec == null || schema == null || message == null || digest == null || payload == null) {
            return DecodeResult.Failure(FailureCode.FIELD_COUNT_MISMATCH)
        }
        if (!strictUtf8(codec) || !strictUtf8(schema) || !strictUtf8(message)) return DecodeResult.Failure(FailureCode.INVALID_UTF8)
        if (!codec.contentEquals(CODEC) || !schema.contentEquals(SCHEMA) || !message.contentEquals(MESSAGE) ||
            digest.size != 32 || !digest.contentEquals(LeonaEvidenceResponseProtobufCodec.DESCRIPTOR_SHA256)
        ) return DecodeResult.Failure(FailureCode.DESCRIPTOR_MISMATCH)
        if (payload.isEmpty()) return DecodeResult.Failure(FailureCode.EMPTY_PAYLOAD)
        if (payload.size > MAX_PAYLOAD_BYTES) return DecodeResult.Failure(FailureCode.OVERSIZE)
        if (LeonaEvidenceResponseProtobufCodec.decode(payload) !is LeonaResponseProtobufDecodeResult.Success) {
            return DecodeResult.Failure(FailureCode.PROTOBUF_REJECTED)
        }
        return DecodeResult.Success(carrier, payload)
    }

    fun decodeResponse(carrier: ByteArray): DecodeResult = decode(carrier)

    private fun checkedTotal(payloadLength: Int): Int? {
        if (payloadLength !in 1..MAX_PAYLOAD_BYTES) return null
        return try {
            var total = Math.addExact(MAGIC.size, 4)
            for (length in intArrayOf(CODEC.size, SCHEMA.size, MESSAGE.size, 32, payloadLength)) {
                total = Math.addExact(total, TLV_HEADER_BYTES)
                total = Math.addExact(total, length)
            }
            total.takeIf { it <= MAX_CARRIER_BYTES }
        } catch (_: ArithmeticException) { null }
    }

    private fun writeTlv(output: ByteArrayOutputStream, tag: Int, value: ByteArray) {
        output.write(tag)
        output.write(0)
        writeU16(output, 0)
        writeU32(output, value.size)
        output.write(value)
    }
    private fun writeU16(output: ByteArrayOutputStream, value: Int) {
        output.write((value ushr 8) and 0xff)
        output.write(value and 0xff)
    }
    private fun writeU32(output: ByteArrayOutputStream, value: Int) {
        output.write((value ushr 24) and 0xff)
        output.write((value ushr 16) and 0xff)
        output.write((value ushr 8) and 0xff)
        output.write(value and 0xff)
    }
    private fun strictUtf8(bytes: ByteArray): Boolean = try {
        StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes))
        true
    } catch (_: CharacterCodingException) { false }
    private fun u16(bytes: ByteArray, offset: Int): Int = (bytes[offset].unsigned() shl 8) or bytes[offset + 1].unsigned()
    private fun u32(bytes: ByteArray, offset: Int): Long =
        (bytes[offset].unsigned().toLong() shl 24) or (bytes[offset + 1].unsigned().toLong() shl 16) or
            (bytes[offset + 2].unsigned().toLong() shl 8) or bytes[offset + 3].unsigned().toLong()
    private fun checkedAdd(left: Long, right: Long): Long? = if (right > Long.MAX_VALUE - left) null else left + right
    private fun Byte.unsigned(): Int = toInt() and 0xff
}
