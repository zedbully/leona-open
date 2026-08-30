/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.proto

import com.google.protobuf.ByteString
import io.leonasec.proto.v1.ClientScopeDeclaration
import io.leonasec.proto.v1.EvidenceBatch
import io.leonasec.proto.v1.EvidenceEntry
import io.leonasec.proto.v1.EvidenceEnum
import io.leonasec.proto.v1.EvidenceIngestRequest
import io.leonasec.proto.v1.EvidenceQuality
import io.leonasec.proto.v1.EvidenceSource
import java.nio.charset.StandardCharsets

private val LEONA_SCHEMA_DIGEST = ByteArray(32) { index ->
    "1056487dea69e58894f48aea6d04a528e1e2aaf543fc708deb7cec007aaf8703"
        .substring(index * 2, index * 2 + 2).toInt(16).toByte()
}

/** The four logical descriptor values authenticated by the Leo channel. */
class LeonaProtectedPayloadDescriptor private constructor(
    val payloadCodec: String,
    val payloadSchema: String,
    val messageType: String,
    digest: ByteArray,
) {
    init {
        require(payloadCodec == LeonaEvidenceProtobufCodec.PAYLOAD_CODEC)
        require(payloadSchema == LeonaEvidenceProtobufCodec.PAYLOAD_SCHEMA)
        require(messageType == LeonaEvidenceProtobufCodec.MESSAGE_TYPE)
        require(digest.contentEquals(LEONA_SCHEMA_DIGEST))
    }
    private val digestBytes = digest.copyOf()
    val schemaDigestSha256: ByteArray
        get() = digestBytes.copyOf()

    override fun equals(other: Any?): Boolean = other is LeonaProtectedPayloadDescriptor &&
        payloadCodec == other.payloadCodec && payloadSchema == other.payloadSchema &&
        messageType == other.messageType && digestBytes.contentEquals(other.digestBytes)

    override fun hashCode(): Int = 31 * (31 * (31 * payloadCodec.hashCode() + payloadSchema.hashCode()) + messageType.hashCode()) + digestBytes.contentHashCode()

    companion object {
        internal fun canonical(codec: String, schema: String, message: String, digest: ByteArray): LeonaProtectedPayloadDescriptor {
            require(codec == LeonaEvidenceProtobufCodec.PAYLOAD_CODEC)
            require(schema == LeonaEvidenceProtobufCodec.PAYLOAD_SCHEMA)
            require(message == LeonaEvidenceProtobufCodec.MESSAGE_TYPE)
            require(digest.contentEquals(LEONA_SCHEMA_DIGEST))
            return LeonaProtectedPayloadDescriptor(codec, schema, message, digest)
        }
    }
}

/** Typed handoff. The descriptor is not serialized as a clear HTTP header by this SDK. */
sealed interface LeonaProtectedLogicalPayloadHandoff {
    val bytes: ByteArray
    val descriptor: LeonaProtectedPayloadDescriptor

    data class ExternalBlocked(val reason: LeonaProtobufFailureCode) : LeonaProtectedLogicalPayloadHandoff {
        override val bytes: ByteArray get() = ByteArray(0)
        override val descriptor: LeonaProtectedPayloadDescriptor get() = LeonaEvidenceProtobufCodec.descriptor
    }
}

private class CanonicalProtobufHandoff(
    bytes: ByteArray,
    override val descriptor: LeonaProtectedPayloadDescriptor,
) : LeonaProtectedLogicalPayloadHandoff {
    private val payload = bytes.copyOf().also {
        require(it.isNotEmpty() && it.size <= LeonaEvidenceProtobufCodec.DEFAULT_APP_CAP_BYTES)
    }
    override val bytes: ByteArray
        get() = payload.copyOf()
}

enum class LeonaProtobufFailureCode {
    INVALID_INPUT,
    OVERSIZE,
    COUNT_EXCEEDED,
    UNKNOWN_ENUM,
    INVALID_ONEOF,
    MALFORMED_WIRE,
    SCHEMA_MISMATCH,
    EXTERNAL_BLOCKED,
}

data class LeonaProtobufFailure(
    val code: LeonaProtobufFailureCode,
    val detail: String,
)

sealed interface LeonaProtobufEncodeResult {
    data class Success(val handoff: LeonaProtectedLogicalPayloadHandoff) : LeonaProtobufEncodeResult
    data class Failure(val error: LeonaProtobufFailure) : LeonaProtobufEncodeResult
}

sealed interface LeonaProtobufDecodeResult {
    data class Success(val request: LeonaEvidenceIngestRequestModel) : LeonaProtobufDecodeResult
    data class Failure(val error: LeonaProtobufFailure) : LeonaProtobufDecodeResult
}

enum class LeonaEvidenceSourceValue { ANDROID, LEO_PROVIDER, PLATFORM }
enum class LeonaEvidenceQualityValue { RAW, VERIFIED, REDACTED }
enum class LeonaEvidenceEnumValue { TRUE, FALSE, UNKNOWN }

sealed interface LeonaEvidenceValue {
    data class Bool(val value: Boolean) : LeonaEvidenceValue
    data class Int(val value: Long) : LeonaEvidenceValue
    data class UInt(val value: ULong) : LeonaEvidenceValue
    data class StringValue(val value: String) : LeonaEvidenceValue
    data class Bytes(val value: ByteArray) : LeonaEvidenceValue
    data class EnumValue(val value: LeonaEvidenceEnumValue) : LeonaEvidenceValue
}

data class LeonaEvidenceEntryModel(
    val key: String,
    val observedAtEpochMs: Long,
    val source: LeonaEvidenceSourceValue,
    val quality: LeonaEvidenceQualityValue,
    val value: LeonaEvidenceValue,
)

data class LeonaClientScopeModel(
    val tenantId: String,
    val appId: String,
    val environmentId: String,
)

data class LeonaEvidenceIngestRequestModel(
    val protocolMajor: Int,
    val tenantId: String,
    val appId: String,
    val environmentId: String,
    val installId: String,
    val sessionId: String,
    val requestId: String,
    val nonce: ByteArray,
    val idempotencyKey: String,
    val issuedAtEpochMs: Long,
    val clientScope: LeonaClientScopeModel,
    val entries: List<LeonaEvidenceEntryModel>,
)

/** Exact API-v1 protobuf codec. It is evidence-only and does not make a verdict. */
object LeonaEvidenceProtobufCodec {
    const val DEFAULT_APP_CAP_BYTES = 128 * 1024
    const val MAX_ENTRIES = 1024
    const val MAX_STRING_BYTES = 4096
    const val MAX_KEY_BYTES = 512
    const val MAX_BYTES_VALUE = 16 * 1024
    const val PAYLOAD_CODEC = "LEONA_PROTOBUF"
    const val PAYLOAD_SCHEMA = "leona.evidence.v1"
    const val MESSAGE_TYPE = "leona.evidence.v1.EvidenceIngestRequest"
    val descriptor: LeonaProtectedPayloadDescriptor
        get() = LeonaProtectedPayloadDescriptor.canonical(PAYLOAD_CODEC, PAYLOAD_SCHEMA, MESSAGE_TYPE, LEONA_SCHEMA_DIGEST)

    fun encode(request: LeonaEvidenceIngestRequestModel, appCapBytes: Int = DEFAULT_APP_CAP_BYTES): LeonaProtobufEncodeResult {
        val failure = validateModel(request, appCapBytes)
        if (failure != null) return LeonaProtobufEncodeResult.Failure(failure)
        return try {
            val scope = ClientScopeDeclaration.newBuilder()
                .setTenantId(request.clientScope.tenantId)
                .setAppId(request.clientScope.appId)
                .setEnvironmentId(request.clientScope.environmentId)
                .build()
            val batch = EvidenceBatch.newBuilder().apply {
                request.entries.forEach { addEntries(encodeEntry(it)) }
            }.build()
            val encoded = EvidenceIngestRequest.newBuilder()
                .setProtocolMajor(request.protocolMajor)
                .setTenantId(request.tenantId)
                .setAppId(request.appId)
                .setEnvironmentId(request.environmentId)
                .setInstallId(request.installId)
                .setSessionId(request.sessionId)
                .setRequestId(request.requestId)
                .setNonce(ByteString.copyFrom(request.nonce))
                .setIdempotencyKey(request.idempotencyKey)
                .setIssuedAtEpochMs(request.issuedAtEpochMs)
                .setClientScope(scope)
                .setEvidenceBatch(batch)
                .build()
                .toByteArray()
            if (encoded.size > appCapBytes) {
                LeonaProtobufEncodeResult.Failure(LeonaProtobufFailure(LeonaProtobufFailureCode.OVERSIZE, "encoded payload exceeds app cap"))
            } else {
                LeonaProtobufEncodeResult.Success(CanonicalProtobufHandoff(encoded, descriptor))
            }
        } catch (_: RuntimeException) {
            LeonaProtobufEncodeResult.Failure(LeonaProtobufFailure(LeonaProtobufFailureCode.INVALID_INPUT, "protobuf encoding failed"))
        }
    }

    fun decode(bytes: ByteArray, appCapBytes: Int = DEFAULT_APP_CAP_BYTES): LeonaProtobufDecodeResult {
        if (bytes.isEmpty()) {
            return LeonaProtobufDecodeResult.Failure(LeonaProtobufFailure(LeonaProtobufFailureCode.INVALID_INPUT, "empty payload"))
        }
        if (appCapBytes <= 0 || appCapBytes > DEFAULT_APP_CAP_BYTES || bytes.size > appCapBytes) {
            return LeonaProtobufDecodeResult.Failure(LeonaProtobufFailure(LeonaProtobufFailureCode.OVERSIZE, "payload outside bounded input"))
        }
        return try {
            WireValidator(bytes).validateRequest()
            val parsed = EvidenceIngestRequest.parseFrom(bytes)
            val model = decodeModel(parsed)
            val failure = validateModel(model, appCapBytes)
            if (failure != null) LeonaProtobufDecodeResult.Failure(failure)
            else LeonaProtobufDecodeResult.Success(model)
        } catch (error: WireFailure) {
            LeonaProtobufDecodeResult.Failure(LeonaProtobufFailure(error.code, error.message ?: "malformed protobuf"))
        } catch (_: Exception) {
            LeonaProtobufDecodeResult.Failure(LeonaProtobufFailure(LeonaProtobufFailureCode.MALFORMED_WIRE, "protobuf parse failed"))
        }
    }

    private fun encodeEntry(entry: LeonaEvidenceEntryModel): EvidenceEntry = EvidenceEntry.newBuilder()
        .setKey(entry.key)
        .setObservedAtEpochMs(entry.observedAtEpochMs)
        .setSourceValue(entry.source.number)
        .setQualityValue(entry.quality.number)
        .apply {
            when (val value = entry.value) {
                is LeonaEvidenceValue.Bool -> setBoolValue(value.value)
                is LeonaEvidenceValue.Int -> setIntValue(value.value)
                is LeonaEvidenceValue.UInt -> setUintValue(value.value.toLong())
                is LeonaEvidenceValue.StringValue -> setStringValue(value.value)
                is LeonaEvidenceValue.Bytes -> setBytesValue(ByteString.copyFrom(value.value))
                is LeonaEvidenceValue.EnumValue -> setEnumValueValue(value.value.number)
            }
        }.build()

    private fun decodeModel(parsed: EvidenceIngestRequest): LeonaEvidenceIngestRequestModel {
        val scope = parsed.clientScope
        return LeonaEvidenceIngestRequestModel(
            protocolMajor = parsed.protocolMajor,
            tenantId = parsed.tenantId,
            appId = parsed.appId,
            environmentId = parsed.environmentId,
            installId = parsed.installId,
            sessionId = parsed.sessionId,
            requestId = parsed.requestId,
            nonce = parsed.nonce.toByteArray(),
            idempotencyKey = parsed.idempotencyKey,
            issuedAtEpochMs = parsed.issuedAtEpochMs,
            clientScope = LeonaClientScopeModel(scope.tenantId, scope.appId, scope.environmentId),
            entries = (0 until parsed.evidenceBatch.entriesCount).map { index ->
                val entry = parsed.evidenceBatch.getEntries(index)
                val value = when (entry.valueCase) {
                    EvidenceEntry.ValueCase.BOOL_VALUE -> LeonaEvidenceValue.Bool(entry.boolValue)
                    EvidenceEntry.ValueCase.INT_VALUE -> LeonaEvidenceValue.Int(entry.intValue)
                    EvidenceEntry.ValueCase.UINT_VALUE -> LeonaEvidenceValue.UInt(entry.uintValue.toULong())
                    EvidenceEntry.ValueCase.STRING_VALUE -> LeonaEvidenceValue.StringValue(entry.stringValue)
                    EvidenceEntry.ValueCase.BYTES_VALUE -> LeonaEvidenceValue.Bytes(entry.bytesValue.toByteArray())
                    EvidenceEntry.ValueCase.ENUM_VALUE -> LeonaEvidenceValue.EnumValue(enumValue(entry.enumValueValue))
                    EvidenceEntry.ValueCase.VALUE_NOT_SET, null -> throw WireFailure(LeonaProtobufFailureCode.INVALID_ONEOF, "evidence value is not set")
                }
                LeonaEvidenceEntryModel(
                    key = entry.key,
                    observedAtEpochMs = entry.observedAtEpochMs,
                    source = sourceValue(entry.sourceValue),
                    quality = qualityValue(entry.qualityValue),
                    value = value,
                )
            },
        )
    }

    private fun validateModel(request: LeonaEvidenceIngestRequestModel, appCapBytes: Int): LeonaProtobufFailure? {
        if (appCapBytes <= 0 || appCapBytes > DEFAULT_APP_CAP_BYTES) return LeonaProtobufFailure(LeonaProtobufFailureCode.OVERSIZE, "invalid app cap")
        if (request.protocolMajor != 1 || request.issuedAtEpochMs < 0) return LeonaProtobufFailure(LeonaProtobufFailureCode.INVALID_INPUT, "invalid protocol or timestamp")
        val strings = listOf(request.tenantId, request.appId, request.environmentId, request.installId, request.sessionId, request.requestId, request.idempotencyKey)
        if (strings.any { !validString(it, MAX_STRING_BYTES) }) return LeonaProtobufFailure(LeonaProtobufFailureCode.INVALID_INPUT, "invalid required string")
        if (request.nonce.size !in 16..128) return LeonaProtobufFailure(LeonaProtobufFailureCode.INVALID_INPUT, "nonce outside bounds")
        val idempotencyBytes = request.idempotencyKey.toByteArray(StandardCharsets.UTF_8)
        if (idempotencyBytes.size !in 8..128 || idempotencyBytes.any { it.toInt() !in 0x21..0x7e }) return LeonaProtobufFailure(LeonaProtobufFailureCode.INVALID_INPUT, "idempotency key outside bounds")
        val scope = request.clientScope
        if (!validString(scope.tenantId, MAX_STRING_BYTES) || !validString(scope.appId, MAX_STRING_BYTES) || !validString(scope.environmentId, MAX_STRING_BYTES)) return LeonaProtobufFailure(LeonaProtobufFailureCode.INVALID_INPUT, "invalid scope")
        if (scope.tenantId != request.tenantId || scope.appId != request.appId || scope.environmentId != request.environmentId) return LeonaProtobufFailure(LeonaProtobufFailureCode.SCHEMA_MISMATCH, "scope declaration mismatch")
        if (request.entries.isEmpty()) return LeonaProtobufFailure(LeonaProtobufFailureCode.COUNT_EXCEEDED, "evidence batch is empty")
        if (request.entries.size > MAX_ENTRIES) return LeonaProtobufFailure(LeonaProtobufFailureCode.COUNT_EXCEEDED, "evidence entry count exceeds bound")
        for (entry in request.entries) {
            if (!validString(entry.key, MAX_KEY_BYTES)) return LeonaProtobufFailure(LeonaProtobufFailureCode.INVALID_INPUT, "invalid evidence key")
            if (entry.observedAtEpochMs < 0) return LeonaProtobufFailure(LeonaProtobufFailureCode.INVALID_INPUT, "invalid evidence timestamp")
            when (val value = entry.value) {
                is LeonaEvidenceValue.StringValue -> if (!validString(value.value, MAX_STRING_BYTES)) return LeonaProtobufFailure(LeonaProtobufFailureCode.INVALID_INPUT, "invalid evidence string")
                is LeonaEvidenceValue.Bytes -> if (value.value.size > MAX_BYTES_VALUE) return LeonaProtobufFailure(LeonaProtobufFailureCode.OVERSIZE, "evidence bytes exceed bound")
                is LeonaEvidenceValue.UInt -> Unit
                is LeonaEvidenceValue.Bool, is LeonaEvidenceValue.Int -> Unit
                is LeonaEvidenceValue.EnumValue -> Unit
            }
        }
        return null
    }

    private fun validString(value: String, maxBytes: Int): Boolean {
        val bytes = value.toByteArray(StandardCharsets.UTF_8)
        return value.isNotEmpty() && bytes.size <= maxBytes && value.none { it.isISOControl() || it.code in 0xD800..0xDFFF }
    }

    private fun sourceValue(value: Int): LeonaEvidenceSourceValue = when (value) {
        1 -> LeonaEvidenceSourceValue.ANDROID
        2 -> LeonaEvidenceSourceValue.LEO_PROVIDER
        3 -> LeonaEvidenceSourceValue.PLATFORM
        else -> throw WireFailure(LeonaProtobufFailureCode.UNKNOWN_ENUM, "unknown evidence source")
    }

    private fun qualityValue(value: Int): LeonaEvidenceQualityValue = when (value) {
        1 -> LeonaEvidenceQualityValue.RAW
        2 -> LeonaEvidenceQualityValue.VERIFIED
        3 -> LeonaEvidenceQualityValue.REDACTED
        else -> throw WireFailure(LeonaProtobufFailureCode.UNKNOWN_ENUM, "unknown evidence quality")
    }

    private fun enumValue(value: Int): LeonaEvidenceEnumValue = when (value) {
        1 -> LeonaEvidenceEnumValue.TRUE
        2 -> LeonaEvidenceEnumValue.FALSE
        3 -> LeonaEvidenceEnumValue.UNKNOWN
        else -> throw WireFailure(LeonaProtobufFailureCode.UNKNOWN_ENUM, "unknown evidence enum")
    }

    private val LeonaEvidenceSourceValue.number: Int
        get() = when (this) {
            LeonaEvidenceSourceValue.ANDROID -> EvidenceSource.EVIDENCE_SOURCE_ANDROID.number
            LeonaEvidenceSourceValue.LEO_PROVIDER -> EvidenceSource.EVIDENCE_SOURCE_LEO_PROVIDER.number
            LeonaEvidenceSourceValue.PLATFORM -> EvidenceSource.EVIDENCE_SOURCE_PLATFORM.number
        }
    private val LeonaEvidenceQualityValue.number: Int
        get() = when (this) {
            LeonaEvidenceQualityValue.RAW -> EvidenceQuality.EVIDENCE_QUALITY_RAW.number
            LeonaEvidenceQualityValue.VERIFIED -> EvidenceQuality.EVIDENCE_QUALITY_VERIFIED.number
            LeonaEvidenceQualityValue.REDACTED -> EvidenceQuality.EVIDENCE_QUALITY_REDACTED.number
        }
    private val LeonaEvidenceEnumValue.number: Int
        get() = when (this) {
            LeonaEvidenceEnumValue.TRUE -> EvidenceEnum.EVIDENCE_ENUM_TRUE.number
            LeonaEvidenceEnumValue.FALSE -> EvidenceEnum.EVIDENCE_ENUM_FALSE.number
            LeonaEvidenceEnumValue.UNKNOWN -> EvidenceEnum.EVIDENCE_ENUM_UNKNOWN.number
        }

    private class WireFailure(val code: LeonaProtobufFailureCode, message: String) : IllegalArgumentException(message)

    private class WireValidator(private val bytes: ByteArray) {
        private var position = 0
        fun validateRequest() {
            message(Kind.REQUEST, 0)
            if (position != bytes.size) fail(LeonaProtobufFailureCode.MALFORMED_WIRE, "trailing bytes")
        }

        private enum class Kind { REQUEST, SCOPE, BATCH, ENTRY }

        private fun message(kind: Kind, depth: Int) {
            if (depth > 8) fail(LeonaProtobufFailureCode.MALFORMED_WIRE, "nested message too deep")
            val seen = HashSet<Int>()
            var oneof = false
            var entries = 0
            while (position < bytes.size) {
                val tag = readVarint()
                if (tag <= 0 || tag > Int.MAX_VALUE) fail(LeonaProtobufFailureCode.MALFORMED_WIRE, "invalid field tag")
                val field = (tag ushr 3).toInt()
                val wire = (tag and 7).toInt()
                if (field == 0) fail(LeonaProtobufFailureCode.MALFORMED_WIRE, "field zero")
                val expected = expectedWire(kind, field) ?: fail(LeonaProtobufFailureCode.SCHEMA_MISMATCH, "unknown or reserved field")
                if (wire != expected) fail(LeonaProtobufFailureCode.MALFORMED_WIRE, "wrong wire type")
                if (kind != Kind.BATCH && !seen.add(field)) fail(LeonaProtobufFailureCode.MALFORMED_WIRE, "duplicate singular field")
                if (kind == Kind.ENTRY && field in 5..10) {
                    if (oneof) fail(LeonaProtobufFailureCode.INVALID_ONEOF, "multiple oneof values")
                    oneof = true
                }
                when (kind) {
                    Kind.REQUEST -> requestField(field, depth)
                    Kind.SCOPE -> lengthValue()
                    Kind.BATCH -> { lengthMessage(Kind.ENTRY, depth); entries++ }
                    Kind.ENTRY -> entryField(field)
                }
            }
            when (kind) {
                Kind.REQUEST -> if (seen.size != 12) fail(LeonaProtobufFailureCode.SCHEMA_MISMATCH, "required request field missing")
                Kind.SCOPE -> if (seen.size != 3) fail(LeonaProtobufFailureCode.SCHEMA_MISMATCH, "required scope field missing")
                Kind.BATCH -> if (entries == 0 || entries > MAX_ENTRIES) fail(LeonaProtobufFailureCode.COUNT_EXCEEDED, "invalid entry count")
                Kind.ENTRY -> if (seen.size < 5 || !oneof) fail(LeonaProtobufFailureCode.SCHEMA_MISMATCH, "required entry field missing")
            }
        }

        private fun requestField(field: Int, depth: Int) {
            when (field) {
                1 -> { val value = readVarint(); if (value != 1L) fail(LeonaProtobufFailureCode.INVALID_INPUT, "unsupported protocol major") }
                10 -> { if (readVarint() < 0) fail(LeonaProtobufFailureCode.INVALID_INPUT, "negative issued timestamp") }
                11 -> lengthMessage(Kind.SCOPE, depth)
                12 -> lengthMessage(Kind.BATCH, depth)
                else -> lengthValue()
            }
        }

        private fun entryField(field: Int) {
            when (field) {
                2 -> if (readVarint() < 0) fail(LeonaProtobufFailureCode.INVALID_INPUT, "negative observed timestamp")
                3, 4 -> {
                    val value = readVarint()
                    if (value !in 1L..3L) fail(LeonaProtobufFailureCode.UNKNOWN_ENUM, "unknown enum value")
                }
                5 -> if (readVarint() !in 0L..1L) fail(LeonaProtobufFailureCode.INVALID_INPUT, "invalid bool")
                6, 10 -> { val value = readVarint(); if (field == 10 && value !in 1L..3L) fail(LeonaProtobufFailureCode.UNKNOWN_ENUM, "unknown enum value") }
                7 -> fixed64()
                1, 8, 9 -> lengthValue()
                else -> fail(LeonaProtobufFailureCode.SCHEMA_MISMATCH, "unknown entry field")
            }
        }

        private fun expectedWire(kind: Kind, field: Int): Int? = when (kind) {
            Kind.REQUEST -> when (field) { 1, 10 -> 0; in 2..9, 11, 12 -> 2; else -> null }
            Kind.SCOPE -> if (field in 1..3) 2 else null
            Kind.BATCH -> if (field == 1) 2 else null
            Kind.ENTRY -> when (field) { 1, 8, 9 -> 2; 2, 3, 4, 5, 6, 10 -> 0; 7 -> 1; else -> null }
        }

        private fun lengthMessage(kind: Kind, depth: Int) {
            val length = readLength()
            val end = position + length
            if (end < position || end > bytes.size) fail(LeonaProtobufFailureCode.MALFORMED_WIRE, "truncated nested message")
            val nested = bytes.copyOfRange(position, end)
            try {
                WireValidator(nested).also { it.message(kind, depth + 1) }
            } catch (error: WireFailure) {
                throw error
            }
            position = end
        }

        private fun lengthValue() { val length = readLength(); position += length }
        private fun fixed64() { if (bytes.size - position < 8) fail(LeonaProtobufFailureCode.MALFORMED_WIRE, "truncated fixed64"); position += 8 }
        private fun readLength(): Int {
            val value = readVarint()
            if (value < 0 || value > Int.MAX_VALUE) fail(LeonaProtobufFailureCode.MALFORMED_WIRE, "invalid length")
            val length = value.toInt()
            if (length > bytes.size - position) fail(LeonaProtobufFailureCode.MALFORMED_WIRE, "truncated length-delimited value")
            return length
        }
        private fun readVarint(): Long {
            var result = 0L
            var shift = 0
            var count = 0
            while (count < 10) {
                if (position >= bytes.size) fail(LeonaProtobufFailureCode.MALFORMED_WIRE, "truncated varint")
                val current = bytes[position++].toInt() and 0xff
                count++
                if (count == 10 && current > 1) fail(LeonaProtobufFailureCode.MALFORMED_WIRE, "varint overflow")
                result = result or ((current and 0x7f).toLong() shl shift)
                if ((current and 0x80) == 0) {
                    val minimal = when {
                        result == 0L -> 1
                        result < (1L shl 7) -> 1
                        result < (1L shl 14) -> 2
                        result < (1L shl 21) -> 3
                        result < (1L shl 28) -> 4
                        result < (1L shl 35) -> 5
                        result < (1L shl 42) -> 6
                        result < (1L shl 49) -> 7
                        result < (1L shl 56) -> 8
                        result < (1L shl 63) -> 9
                        else -> 10
                    }
                    if (count != minimal) fail(LeonaProtobufFailureCode.MALFORMED_WIRE, "non-canonical varint")
                    return result
                }
                shift += 7
            }
            fail(LeonaProtobufFailureCode.MALFORMED_WIRE, "varint too long")
        }

        private fun fail(code: LeonaProtobufFailureCode, detail: String): Nothing = throw WireFailure(code, detail)
    }

    private fun hex(value: String): ByteArray = ByteArray(value.length / 2) { index -> value.substring(index * 2, index * 2 + 2).toInt(16).toByte() }
}
