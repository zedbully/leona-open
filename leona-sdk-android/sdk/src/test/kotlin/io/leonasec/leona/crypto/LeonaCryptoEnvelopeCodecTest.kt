/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class LeonaCryptoEnvelopeCodecTest {
    private val context = LeonaCryptoPreparedAssertion(
        format = "leo-test",
        audience = "api.example.test",
        challenge = byteArrayOf(1, 2, 3),
        issuedAtMs = 100,
        expiresAtMs = 200,
    )

    @Test
    fun `request envelope round trips with assertion context and opaque bytes`() {
        val packet = LeonaCryptoSealedRequest(
            encryptedWire = byteArrayOf(9, 8, 7),
            assertionEnvelope = LeonaCryptoAssertionEnvelope(
                context = context,
                contextDigest = ByteArray(32) { it.toByte() },
                assertion = byteArrayOf(6, 5, 4),
            ),
        )

        val decoded = LeonaCryptoEnvelopeCodec.decodeRequest(
            LeonaCryptoEnvelopeCodec.encodeRequest(packet),
        )

        assertArrayEquals(packet.encryptedWire, decoded.encryptedWire)
        assertEquals(packet.assertionEnvelope.context.format, decoded.assertionEnvelope.context.format)
        assertEquals(packet.assertionEnvelope.context.audience, decoded.assertionEnvelope.context.audience)
        assertArrayEquals(packet.assertionEnvelope.context.challenge, decoded.assertionEnvelope.context.challenge)
        assertEquals(packet.assertionEnvelope.context.issuedAtMs, decoded.assertionEnvelope.context.issuedAtMs)
        assertEquals(packet.assertionEnvelope.context.expiresAtMs, decoded.assertionEnvelope.context.expiresAtMs)
        assertArrayEquals(packet.assertionEnvelope.contextDigest, decoded.assertionEnvelope.contextDigest)
        assertArrayEquals(packet.assertionEnvelope.assertion, decoded.assertionEnvelope.assertion)
    }

    @Test
    fun `response envelope carries only encrypted wire`() {
        val sealed = LeonaCryptoSealedResponse(byteArrayOf(4, 3, 2, 1))
        val decoded = LeonaCryptoEnvelopeCodec.decodeResponse(
            LeonaCryptoEnvelopeCodec.encodeResponse(sealed),
        )
        assertArrayEquals(sealed.encryptedWire, decoded.encryptedWire)
    }

    @Test
    fun `decoder rejects scope-like trailing data and version drift`() {
        val packet = LeonaCryptoSealedRequest(
            encryptedWire = byteArrayOf(1),
            assertionEnvelope = LeonaCryptoAssertionEnvelope(
                context = context,
                contextDigest = ByteArray(32),
                assertion = byteArrayOf(2),
            ),
        )
        val encoded = LeonaCryptoEnvelopeCodec.encodeRequest(packet)
        assertThrows(IllegalArgumentException::class.java) {
            LeonaCryptoEnvelopeCodec.decodeRequest(encoded + byteArrayOf(0))
        }
        assertThrows(IllegalArgumentException::class.java) {
            LeonaCryptoEnvelopeCodec.decodeRequest(encoded.copyOf().also { it[12] = 2 })
        }
    }
}
