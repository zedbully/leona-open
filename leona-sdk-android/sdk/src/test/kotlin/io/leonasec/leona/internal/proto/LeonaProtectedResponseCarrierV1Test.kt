/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.proto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

class LeonaProtectedResponseCarrierV1Test {
    private val payload: ByteArray
        get() = javaClass.getResourceAsStream("/leona/evidence/response/v1/valid-response.bin")!!.readBytes()
    private val carrier: ByteArray
        get() = javaClass.getResourceAsStream("/leona/evidence/response/v1/valid-response-carrier.bin")!!.readBytes()

    @Test
    fun `authoritative response payload and carrier decode and re-encode byte exactly`() {
        val decoded = LeonaProtectedResponseCarrierV1.decode(carrier) as LeonaProtectedResponseCarrierV1.DecodeResult.Success
        assertArrayEquals(payload, decoded.payload)
        val response = LeonaEvidenceResponseProtobufCodec.decode(payload) as LeonaResponseProtobufDecodeResult.Success
        val encoded = LeonaEvidenceResponseProtobufCodec.encode(response.response) as LeonaResponseProtobufEncodeResult.Success
        assertArrayEquals(payload, encoded.bytes)
        val wrapped = LeonaProtectedResponseCarrierV1.encodePayload(encoded.bytes) as LeonaProtectedResponseCarrierV1.EncodeResult.Success
        assertArrayEquals(carrier, wrapped.bytes)
    }

    @Test
    fun `response carrier is distinct from request carrier`() {
        val request = javaClass.getResourceAsStream("/leona/evidence/v1/valid-carrier.bin")!!.readBytes()
        assertEquals(LeonaProtectedResponseCarrierV1.FailureCode.BAD_MAGIC,
            (LeonaProtectedResponseCarrierV1.decode(request) as LeonaProtectedResponseCarrierV1.DecodeResult.Failure).code)
    }

    @Test
    fun `strict response binding rejects request id and digest mismatch`() {
        val response = LeonaEvidenceResponseProtobufCodec.decode(payload) as LeonaResponseProtobufDecodeResult.Success
        val digest = response.response.requestDigest()
        assertEquals(LeonaResponseProtobufFailureCode.REQUEST_ID_MISMATCH,
            ((LeonaEvidenceResponseProtobufCodec.decode(payload, "wrong", digest) as LeonaResponseProtobufDecodeResult.Failure).error.code))
        assertEquals(LeonaResponseProtobufFailureCode.REQUEST_DIGEST_MISMATCH,
            ((LeonaEvidenceResponseProtobufCodec.decode(payload, response.response.requestId, ByteArray(32)) as LeonaResponseProtobufDecodeResult.Failure).error.code))
    }

    @Test
    fun `response parser rejects unknown duplicate nonminimal and trailing wire`() {
        val unknown = payload + byteArrayOf(0x58, 0x01)
        assertEquals(LeonaResponseProtobufFailureCode.UNKNOWN_FIELD,
            ((LeonaEvidenceResponseProtobufCodec.decode(unknown) as LeonaResponseProtobufDecodeResult.Failure).error.code))
        val duplicate = payload + byteArrayOf(0x50, 0x01)
        assertEquals(LeonaResponseProtobufFailureCode.DUPLICATE_FIELD,
            ((LeonaEvidenceResponseProtobufCodec.decode(duplicate) as LeonaResponseProtobufDecodeResult.Failure).error.code))
        val nonMinimal = payload.copyOf().let { bytes ->
            val out = bytes.toMutableList()
            out[1] = 0x81.toByte(); out.add(2, 0x00)
            out.toByteArray()
        }
        assertTrue(LeonaEvidenceResponseProtobufCodec.decode(nonMinimal) is LeonaResponseProtobufDecodeResult.Failure)
        assertTrue(LeonaProtectedResponseCarrierV1.decode(carrier + byteArrayOf(0)) is LeonaProtectedResponseCarrierV1.DecodeResult.Failure)
    }

    @Test
    fun `response semantic validation rejects malformed identifiers and lifetime`() {
        val valid = LeonaEvidenceResponseProtobufCodec.decode(payload) as LeonaResponseProtobufDecodeResult.Success
        val response = valid.response
        val malformed = response.copy(serverInstallId = "I${"A".repeat(32)}")
        assertEquals(LeonaResponseProtobufFailureCode.INVALID_INPUT,
            (LeonaEvidenceResponseProtobufCodec.encode(malformed) as LeonaResponseProtobufEncodeResult.Failure).error.code)
        val expired = response.copy(boxExpiresAtEpochMs = response.issuedAtEpochMs)
        assertEquals(LeonaResponseProtobufFailureCode.INVALID_INPUT,
            (LeonaEvidenceResponseProtobufCodec.encode(expired) as LeonaResponseProtobufEncodeResult.Failure).error.code)
    }
}
