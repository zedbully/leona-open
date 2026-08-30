package io.leonasec.leona.internal.proto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

class LeonaProtectedPayloadCarrierV1Test {
    @Test
    fun `protobuf golden is wrapped as the frozen LPCARR01 carrier`() {
        val result = LeonaProtectedPayloadCarrierV1.encodeRequest(goldenModel()) as LeonaProtectedPayloadCarrierV1.EncodeResult.Success
        val carrier = result.bytes

        assertEquals(339, carrier.size)
        assertEquals("c568be45ad673497265fb4634eaa9767ed76383cb67c52a4e8aef64aaead4bd3", sha256(carrier))
        assertArrayEquals(frozenCarrier, carrier)
        assertArrayEquals("LPCARR01".encodeToByteArray(), carrier.copyOfRange(0, 8))
        assertEquals(1, carrier[8].toInt())
        assertEquals(5, carrier[9].toInt())
        assertEquals(0, carrier[10].toInt())
        assertEquals(0, carrier[11].toInt())
        // Success cannot leak a mutable internal carrier.
        carrier[0] = 0
        assertEquals('L'.code.toByte(), result.bytes[0])
        assertEquals(
            LeonaProtectedPayloadCarrierV1.FailureCode.PROTOBUF_REJECTED,
            (LeonaProtectedPayloadCarrierV1.encodeRequest(goldenModel().copy(tenantId = "")) as LeonaProtectedPayloadCarrierV1.EncodeResult.Failure).code,
        )
    }

    @Test
    fun `payload bounds and unavailable handoff fail closed`() {
        assertEncodeFailure(ByteArray(0), LeonaProtectedPayloadCarrierV1.FailureCode.EMPTY_PAYLOAD)
        assertEncodeFailure(ByteArray(LeonaProtectedPayloadCarrierV1.MAX_PAYLOAD_BYTES + 1), LeonaProtectedPayloadCarrierV1.FailureCode.OVERSIZE)
        val max = LeonaProtectedPayloadCarrierV1.encodePayload(ByteArray(LeonaProtectedPayloadCarrierV1.MAX_PAYLOAD_BYTES) { 1 }, LeonaEvidenceProtobufCodec.descriptor)
        assertTrue(max is LeonaProtectedPayloadCarrierV1.EncodeResult.Success)
        assertEquals(LeonaProtectedPayloadCarrierV1.MAX_CARRIER_BYTES, (max as LeonaProtectedPayloadCarrierV1.EncodeResult.Success).bytes.size)
        assertFailure(
            LeonaProtectedLogicalPayloadHandoff.ExternalBlocked(LeonaProtobufFailureCode.EXTERNAL_BLOCKED),
            LeonaProtectedPayloadCarrierV1.FailureCode.EXTERNAL_BLOCKED,
        )
    }

    @Test
    fun `strict decoder rejects frozen carrier mutations fail closed`() {
        assertTrue(LeonaProtectedPayloadCarrierV1.decodeRequest(frozenCarrier) is LeonaProtectedPayloadCarrierV1.DecodeResult.Success)
        fun mutation(expected: LeonaProtectedPayloadCarrierV1.FailureCode, change: (ByteArray) -> Unit) {
            val bytes = frozenCarrier.copyOf(); change(bytes)
            val result = LeonaProtectedPayloadCarrierV1.decodeRequest(bytes)
            assertTrue("expected $expected but got $result", result is LeonaProtectedPayloadCarrierV1.DecodeResult.Failure)
            assertEquals(expected, (result as LeonaProtectedPayloadCarrierV1.DecodeResult.Failure).code)
        }
        mutation(LeonaProtectedPayloadCarrierV1.FailureCode.BAD_MAGIC) { it[0] = 0 }
        mutation(LeonaProtectedPayloadCarrierV1.FailureCode.UNSUPPORTED_VERSION) { it[8] = 2 }
        mutation(LeonaProtectedPayloadCarrierV1.FailureCode.FIELD_COUNT_MISMATCH) { it[9] = 4 }
        mutation(LeonaProtectedPayloadCarrierV1.FailureCode.NONZERO_RESERVED) { it[10] = 1 }
        mutation(LeonaProtectedPayloadCarrierV1.FailureCode.UNKNOWN_TAG) { it[59] = 6 }
        mutation(LeonaProtectedPayloadCarrierV1.FailureCode.DUPLICATE_TAG) { it[34] = 1 }
        mutation(LeonaProtectedPayloadCarrierV1.FailureCode.OUT_OF_ORDER_TAG) { it[59] = 1 }
        mutation(LeonaProtectedPayloadCarrierV1.FailureCode.NONZERO_FLAGS) { it[13] = 1 }
        mutation(LeonaProtectedPayloadCarrierV1.FailureCode.NONZERO_RESERVED) { it[14] = 1 }
        mutation(LeonaProtectedPayloadCarrierV1.FailureCode.DESCRIPTOR_MISMATCH) { it[20] = 'X'.code.toByte() }
        mutation(LeonaProtectedPayloadCarrierV1.FailureCode.INVALID_UTF8) { it[20] = 0x80.toByte() }
        mutation(LeonaProtectedPayloadCarrierV1.FailureCode.DESCRIPTOR_MISMATCH) { it[114] = 0 }
        val emptyPayload = frozenCarrier.copyOf(154).also { it[150] = 0; it[151] = 0; it[152] = 0; it[153] = 0 }
        assertDecodeFailure(emptyPayload, LeonaProtectedPayloadCarrierV1.FailureCode.EMPTY_PAYLOAD)
        val truncated = frozenCarrier.copyOf(11)
        assertDecodeFailure(truncated, LeonaProtectedPayloadCarrierV1.FailureCode.TRUNCATED)
        mutation(LeonaProtectedPayloadCarrierV1.FailureCode.TRUNCATED) { it[16] = 0x7f }
        mutation(LeonaProtectedPayloadCarrierV1.FailureCode.TRUNCATED) { it[150] = 0xff.toByte(); it[151] = 0xff.toByte(); it[152] = 0xff.toByte(); it[153] = 0xff.toByte() }
        assertDecodeFailure(frozenCarrier + byteArrayOf(0), LeonaProtectedPayloadCarrierV1.FailureCode.TRAILING_BYTES)
        assertDecodeFailure(ByteArray(LeonaProtectedPayloadCarrierV1.MAX_CARRIER_BYTES + 1), LeonaProtectedPayloadCarrierV1.FailureCode.OVERSIZE)
        mutation(LeonaProtectedPayloadCarrierV1.FailureCode.PROTOBUF_REJECTED) { it[154] = 0 }
    }

    private fun assertFailure(handoff: LeonaProtectedLogicalPayloadHandoff, expected: LeonaProtectedPayloadCarrierV1.FailureCode) {
        val result = LeonaProtectedPayloadCarrierV1.encode(handoff)
        assertTrue(result is LeonaProtectedPayloadCarrierV1.EncodeResult.Failure)
        assertEquals(expected, (result as LeonaProtectedPayloadCarrierV1.EncodeResult.Failure).code)
    }

    private fun assertEncodeFailure(bytes: ByteArray, expected: LeonaProtectedPayloadCarrierV1.FailureCode) {
        val result = LeonaProtectedPayloadCarrierV1.encodePayload(bytes, LeonaEvidenceProtobufCodec.descriptor)
        assertTrue(result is LeonaProtectedPayloadCarrierV1.EncodeResult.Failure)
        assertEquals(expected, (result as LeonaProtectedPayloadCarrierV1.EncodeResult.Failure).code)
    }

    private fun assertDecodeFailure(bytes: ByteArray, expected: LeonaProtectedPayloadCarrierV1.FailureCode) {
        val result = LeonaProtectedPayloadCarrierV1.decodeRequest(bytes)
        assertTrue(result is LeonaProtectedPayloadCarrierV1.DecodeResult.Failure)
        assertEquals(expected, (result as LeonaProtectedPayloadCarrierV1.DecodeResult.Failure).code)
    }

    private val frozenCarrier: ByteArray
        get() = javaClass.getResourceAsStream("/leona/evidence/v1/valid-carrier.bin")!!.readBytes()

    private fun goldenModel() = LeonaEvidenceIngestRequestModel(
        protocolMajor = 1, tenantId = "tenant-golden", appId = "app-golden", environmentId = "prod",
        installId = "install-ref", sessionId = "session-ref", requestId = "request-golden",
        nonce = ByteArray(16) { it.toByte() }, idempotencyKey = "idem-golden", issuedAtEpochMs = 1_700_000_000_000L,
        clientScope = LeonaClientScopeModel("tenant-golden", "app-golden", "prod"),
        entries = listOf(LeonaEvidenceEntryModel("integrity.status", 1_700_000_000_000L, LeonaEvidenceSourceValue.ANDROID, LeonaEvidenceQualityValue.VERIFIED, LeonaEvidenceValue.Bool(true))),
    )

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
