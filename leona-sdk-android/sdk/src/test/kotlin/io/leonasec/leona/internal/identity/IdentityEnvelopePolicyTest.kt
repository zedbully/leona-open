/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.identity

import org.json.JSONObject
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
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

    @Test
    fun `versioned envelope is bound to its record domain`() {
        val envelope = JSONObject()
            .put("version", IdentityEnvelopePolicy.CURRENT_VERSION)
            .put("mode", "keystore")
            .put("record", IdentityRecord.INSTALL_ID.wireName)
            .put("iv", encode(ByteArray(12)))
            .put("ct", encode(ByteArray(16)))
            .toString()

        assertTrue(IdentityEnvelopePolicy.isAuthenticatedEnvelope(envelope, IdentityRecord.INSTALL_ID))
        assertFalse(IdentityEnvelopePolicy.isAuthenticatedEnvelope(envelope, IdentityRecord.CANONICAL_DEVICE_ID))
        assertEquals(
            "leona.identity.v2:install_id",
            IdentityEnvelopePolicy.aadFor(IdentityRecord.INSTALL_ID),
        )
    }

    @Test
    fun `legacy v1 envelope is admitted only as migration input`() {
        val legacy = JSONObject()
            .put("mode", "keystore")
            .put("iv", encode(ByteArray(12)))
            .put("ct", encode(ByteArray(16)))
            .toString()

        val descriptor = IdentityEnvelopePolicy.inspect(legacy, IdentityRecord.INSTALL_ID)
        assertTrue(descriptor?.legacy == true)
        assertEquals(IdentityEnvelopePolicy.LEGACY_VERSION, descriptor?.version)
        assertFalse(InstallIdAdmission.isUsable("L" + "a".repeat(32)))
        assertTrue(InstallIdAdmission.isUsable("I" + "a".repeat(32)))
        assertTrue(CanonicalIdAdmission.isUsable("L" + "a".repeat(32)))
        assertFalse(CanonicalIdAdmission.isUsable("I" + "a".repeat(32)))

        val mislabeledLegacy = JSONObject(legacy)
            .put("record", IdentityRecord.INSTALL_ID.wireName)
            .toString()
        assertFalse(IdentityEnvelopePolicy.isAuthenticatedEnvelope(mislabeledLegacy, IdentityRecord.INSTALL_ID))
    }

    private fun encode(bytes: ByteArray): String = java.util.Base64.getEncoder()
        .withoutPadding()
        .encodeToString(bytes)
}
