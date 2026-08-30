/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.identity

import org.json.JSONObject
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IdentityEnvelopePolicyTest {

    @Test
    fun `API23 is the minimum supported encryption floor`() {
        assertFalse(IdentityEnvelopePolicy.isApiSupported(22))
        assertTrue(IdentityEnvelopePolicy.isApiSupported(23))
        assertTrue(IdentityEnvelopePolicy.isApiSupported(36))
    }

    @Test
    fun `malformed or plaintext envelopes are rejected`() {
        assertFalse(IdentityEnvelopePolicy.isAuthenticatedEnvelope(null))
        assertFalse(IdentityEnvelopePolicy.isAuthenticatedEnvelope("not-json"))
        assertFalse(
            IdentityEnvelopePolicy.isAuthenticatedEnvelope(
                JSONObject().put("mode", "plaintext").put("value", "secret").toString(),
            ),
        )
        assertFalse(
            IdentityEnvelopePolicy.isAuthenticatedEnvelope(
                JSONObject()
                    .put("mode", "keystore")
                    .put("iv", encode(ByteArray(11)))
                    .put("ct", encode(ByteArray(16)))
                    .toString(),
            ),
        )
        assertFalse(
            IdentityEnvelopePolicy.isAuthenticatedEnvelope(
                JSONObject()
                    .put("mode", "keystore")
                    .put("iv", encode(ByteArray(12)))
                    .put("ct", encode(ByteArray(15)))
                    .toString(),
            ),
        )
    }

    @Test
    fun `well formed envelope shape is admitted before keystore authentication`() {
        val envelope = JSONObject()
            .put("mode", "keystore")
            .put("iv", encode(ByteArray(12)))
            .put("ct", encode(ByteArray(16)))
            .toString()

        assertTrue(IdentityEnvelopePolicy.isAuthenticatedEnvelope(envelope))
    }

    private fun encode(bytes: ByteArray): String = java.util.Base64.getEncoder()
        .withoutPadding()
        .encodeToString(bytes)
}
