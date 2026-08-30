package io.leonasec.leona.internal.proto

import io.leonasec.proto.v1.EvidenceIngestRequest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

class LeonaEvidenceProtobufCodecTest {
    private val golden: ByteArray
        get() = javaClass.getResourceAsStream("/leona/evidence/v1/valid-ingest.bin")!!.readBytes()

    @Test
    fun `golden vector is exact and deterministic`() {
        val result = LeonaEvidenceProtobufCodec.encode(goldenModel())
        assertTrue(result is LeonaProtobufEncodeResult.Success)
        val handoff = (result as LeonaProtobufEncodeResult.Success).handoff
        assertArrayEquals(golden, handoff.bytes)
        assertEquals(LeonaEvidenceProtobufCodec.PAYLOAD_CODEC, handoff.descriptor.payloadCodec)
        assertEquals(LeonaEvidenceProtobufCodec.PAYLOAD_SCHEMA, handoff.descriptor.payloadSchema)
        assertEquals(LeonaEvidenceProtobufCodec.MESSAGE_TYPE, handoff.descriptor.messageType)
        assertArrayEquals(
            hex("1056487dea69e58894f48aea6d04a528e1e2aaf543fc708deb7cec007aaf8703"),
            handoff.descriptor.schemaDigestSha256,
        )
        // Defensive copies prevent post-validation mutation of the handoff.
        val bytes = handoff.bytes
        bytes[0] = 0
        assertArrayEquals(golden, handoff.bytes)
        val digest = handoff.descriptor.schemaDigestSha256
        digest[0] = 0
        assertArrayEquals(hex("1056487dea69e58894f48aea6d04a528e1e2aaf543fc708deb7cec007aaf8703"), handoff.descriptor.schemaDigestSha256)
    }

    @Test
    fun `golden decodes and round trips byte for byte`() {
        val decoded = LeonaEvidenceProtobufCodec.decode(golden)
        assertTrue(decoded is LeonaProtobufDecodeResult.Success)
        val model = (decoded as LeonaProtobufDecodeResult.Success).request
        assertEquals(goldenModel().tenantId, model.tenantId)
        assertEquals(goldenModel().entries, model.entries)
        val encoded = LeonaEvidenceProtobufCodec.encode(model)
        assertTrue(encoded is LeonaProtobufEncodeResult.Success)
        assertArrayEquals(golden, (encoded as LeonaProtobufEncodeResult.Success).handoff.bytes)
    }

    @Test
    fun `descriptor resource has admitted digest`() {
        val digest = MessageDigest.getInstance("SHA-256").digest(
            javaClass.getResourceAsStream("/leona/evidence/v1/ingest.pb")!!.readBytes(),
        )
        assertArrayEquals(LeonaEvidenceProtobufCodec.descriptor.schemaDigestSha256, digest)
    }

    @Test
    fun `descriptor constructor rejects a non-admitted digest`() {
        val constructor = LeonaProtectedPayloadDescriptor::class.java.declaredConstructors
            .first { it.parameterTypes.size == 4 }
            .apply { isAccessible = true }
        val result = runCatching {
            constructor.newInstance(
                LeonaEvidenceProtobufCodec.PAYLOAD_CODEC,
                LeonaEvidenceProtobufCodec.PAYLOAD_SCHEMA,
                LeonaEvidenceProtobufCodec.MESSAGE_TYPE,
                ByteArray(32),
            )
        }
        assertTrue(result.isFailure)
    }

    @Test
    fun `unknown duplicate malformed and noncanonical wire fail closed`() {
        val unknown = golden + byteArrayOf(0x78, 0x01)
        assertFailure(unknown, LeonaProtobufFailureCode.SCHEMA_MISMATCH)
        val duplicate = golden + byteArrayOf(0x12, 0x01, 0x78)
        assertFailure(duplicate, LeonaProtobufFailureCode.MALFORMED_WIRE)
        assertFailure(golden.copyOf(golden.size - 1), LeonaProtobufFailureCode.MALFORMED_WIRE)
        val noncanonical = golden + byteArrayOf(0x78, 0x81.toByte(), 0x00)
        assertFailure(noncanonical, LeonaProtobufFailureCode.SCHEMA_MISMATCH)
        val wrongWire = golden.copyOf().also { it[0] = 0x0a }
        assertFailure(wrongWire, LeonaProtobufFailureCode.MALFORMED_WIRE)
        val nestedTruncation = golden.copyOf().also {
            val batchIndex = it.indexOfFirst { byte -> (byte.toInt() and 0xff) == 0x62 }
            it[batchIndex + 1] = 0x22
        }
        assertFailure(nestedTruncation, LeonaProtobufFailureCode.MALFORMED_WIRE)
    }

    @Test
    fun `invalid oneof and unknown enum fail closed`() {
        val both = golden.copyOf()
        // batch length (0x21) and entry length (0x1f) grow by a second oneof field.
        val batchIndex = both.indexOfFirst { (it.toInt() and 0xff) == 0x62 }
        val entryIndex = batchIndex + 2
        both[batchIndex + 1] = 0x23
        both[entryIndex + 1] = 0x21
        val expanded = both + byteArrayOf(0x30, 0x02)
        assertFailure(expanded, LeonaProtobufFailureCode.INVALID_ONEOF)
        val unknownEnum = golden.copyOf()
        val qualityIndex = unknownEnum.indexOfFirst { (it.toInt() and 0xff) == 0x20 }
        unknownEnum[qualityIndex + 1] = 0x04
        assertFailure(unknownEnum, LeonaProtobufFailureCode.UNKNOWN_ENUM)
    }

    @Test
    fun `bounds and semantic mismatch are rejected without downgrade`() {
        val oversized = LeonaEvidenceProtobufCodec.encode(goldenModel().copy(requestId = "x".repeat(100)), appCapBytes = 8)
        assertTrue(oversized is LeonaProtobufEncodeResult.Failure)
        assertEquals(LeonaProtobufFailureCode.OVERSIZE, (oversized as LeonaProtobufEncodeResult.Failure).error.code)
        assertTrue(LeonaEvidenceProtobufCodec.encode(goldenModel(), LeonaEvidenceProtobufCodec.DEFAULT_APP_CAP_BYTES) is LeonaProtobufEncodeResult.Success)
        assertEquals(
            LeonaProtobufFailureCode.OVERSIZE,
            (LeonaEvidenceProtobufCodec.encode(goldenModel(), LeonaEvidenceProtobufCodec.DEFAULT_APP_CAP_BYTES + 1) as LeonaProtobufEncodeResult.Failure).error.code,
        )
        assertEquals(LeonaProtobufFailureCode.INVALID_INPUT, (LeonaEvidenceProtobufCodec.decode(ByteArray(0)).let { (it as LeonaProtobufDecodeResult.Failure).error.code }))
        assertEquals(LeonaProtobufFailureCode.OVERSIZE, (LeonaEvidenceProtobufCodec.decode(golden, 0).let { (it as LeonaProtobufDecodeResult.Failure).error.code }))
        assertEquals(LeonaProtobufFailureCode.OVERSIZE, (LeonaEvidenceProtobufCodec.decode(golden, -1).let { (it as LeonaProtobufDecodeResult.Failure).error.code }))
        assertEquals(LeonaProtobufFailureCode.OVERSIZE, (LeonaEvidenceProtobufCodec.decode(golden, LeonaEvidenceProtobufCodec.DEFAULT_APP_CAP_BYTES + 1).let { (it as LeonaProtobufDecodeResult.Failure).error.code }))
        val exact = exactCapModel()
        val exactEncoded = (LeonaEvidenceProtobufCodec.encode(exact) as LeonaProtobufEncodeResult.Success).handoff.bytes
        assertEquals(LeonaEvidenceProtobufCodec.DEFAULT_APP_CAP_BYTES, exactEncoded.size)
        assertTrue(LeonaEvidenceProtobufCodec.decode(exactEncoded) is LeonaProtobufDecodeResult.Success)
        assertEquals(LeonaProtobufFailureCode.OVERSIZE, (LeonaEvidenceProtobufCodec.decode(exactEncoded + byteArrayOf(0), LeonaEvidenceProtobufCodec.DEFAULT_APP_CAP_BYTES).let { (it as LeonaProtobufDecodeResult.Failure).error.code }))
        val tooMany = goldenModel().copy(entries = List(LeonaEvidenceProtobufCodec.MAX_ENTRIES + 1) { goldenModel().entries.single() })
        val countFailure = LeonaEvidenceProtobufCodec.encode(tooMany)
        assertTrue(countFailure is LeonaProtobufEncodeResult.Failure)
        assertEquals(LeonaProtobufFailureCode.COUNT_EXCEEDED, (countFailure as LeonaProtobufEncodeResult.Failure).error.code)
        val mismatch = LeonaEvidenceProtobufCodec.encode(goldenModel().copy(clientScope = LeonaClientScopeModel("other", "app-golden", "prod")))
        assertTrue(mismatch is LeonaProtobufEncodeResult.Failure)
        assertEquals(LeonaProtobufFailureCode.SCHEMA_MISMATCH, (mismatch as LeonaProtobufEncodeResult.Failure).error.code)
    }

    @Test
    fun `external carrier remains typed blocked`() {
        val blocked: LeonaProtectedLogicalPayloadHandoff = LeonaProtectedLogicalPayloadHandoff.ExternalBlocked(LeonaProtobufFailureCode.EXTERNAL_BLOCKED)
        assertTrue(blocked is LeonaProtectedLogicalPayloadHandoff.ExternalBlocked)
    }

    @Test
    fun `contract strings and idempotency reject controls and whitespace`() {
        val control = LeonaEvidenceProtobufCodec.encode(goldenModel().copy(tenantId = "tenant\nvalue"))
        assertTrue(control is LeonaProtobufEncodeResult.Failure)
        val whitespace = LeonaEvidenceProtobufCodec.encode(goldenModel().copy(idempotencyKey = "idem key"))
        assertTrue(whitespace is LeonaProtobufEncodeResult.Failure)
        val nonAscii = LeonaEvidenceProtobufCodec.encode(goldenModel().copy(idempotencyKey = "idem-钥匙"))
        assertTrue(nonAscii is LeonaProtobufEncodeResult.Failure)
    }

    private fun assertFailure(bytes: ByteArray, code: LeonaProtobufFailureCode) {
        val result = LeonaEvidenceProtobufCodec.decode(bytes)
        assertTrue("expected failure", result is LeonaProtobufDecodeResult.Failure)
        val failure = result as LeonaProtobufDecodeResult.Failure
        assertEquals(failure.error.detail, code, failure.error.code)
    }

    private fun goldenModel() = LeonaEvidenceIngestRequestModel(
        protocolMajor = 1,
        tenantId = "tenant-golden",
        appId = "app-golden",
        environmentId = "prod",
        installId = "install-ref",
        sessionId = "session-ref",
        requestId = "request-golden",
        nonce = ByteArray(16) { it.toByte() },
        idempotencyKey = "idem-golden",
        issuedAtEpochMs = 1_700_000_000_000L,
        clientScope = LeonaClientScopeModel("tenant-golden", "app-golden", "prod"),
        entries = listOf(
            LeonaEvidenceEntryModel(
                key = "integrity.status",
                observedAtEpochMs = 1_700_000_000_000L,
                source = LeonaEvidenceSourceValue.ANDROID,
                quality = LeonaEvidenceQualityValue.VERIFIED,
                value = LeonaEvidenceValue.Bool(true),
            ),
        ),
    )

    private fun exactCapModel(): LeonaEvidenceIngestRequestModel {
        val baseEntries = List(7) { index ->
            LeonaEvidenceEntryModel("bulk-$index", 1_700_000_000_000L, LeonaEvidenceSourceValue.ANDROID, LeonaEvidenceQualityValue.RAW, LeonaEvidenceValue.Bytes(ByteArray(16 * 1024)))
        }
        var low = 0
        var high = LeonaEvidenceProtobufCodec.MAX_BYTES_VALUE
        while (low <= high) {
            val size = (low + high) ushr 1
            val candidate = goldenModel().copy(entries = baseEntries + LeonaEvidenceEntryModel("bulk-final", 1_700_000_000_000L, LeonaEvidenceSourceValue.ANDROID, LeonaEvidenceQualityValue.RAW, LeonaEvidenceValue.Bytes(ByteArray(size))))
            val result = LeonaEvidenceProtobufCodec.encode(candidate)
            if (result is LeonaProtobufEncodeResult.Success) {
                val actual = result.handoff.bytes.size
                when {
                    actual == LeonaEvidenceProtobufCodec.DEFAULT_APP_CAP_BYTES -> return candidate
                    actual < LeonaEvidenceProtobufCodec.DEFAULT_APP_CAP_BYTES -> low = size + 1
                    else -> high = size - 1
                }
            } else {
                high = size - 1
            }
        }
        error("unable to construct exact app-cap vector")
    }

    private fun hex(value: String): ByteArray = ByteArray(value.length / 2) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
