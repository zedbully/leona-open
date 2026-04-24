/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.config

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.fail
import org.junit.Test

class PlayIntegrityAttestationProviderTest {

    @Test
    fun `provider wraps token as play integrity attestation`() = runTest {
        var captured: PlayIntegrityTokenRequest? = null
        val provider = PlayIntegrityAttestationProvider(
            tokenProvider = PlayIntegrityTokenProvider { request ->
                captured = request
                "  token-123  "
            },
            cloudProjectNumber = 123456789L,
        )

        val statement = provider.attest(
            challenge = "challenge-abc",
            installId = "install-1",
        )

        assertEquals(
            PlayIntegrityTokenRequest(
                requestHash = "challenge-abc",
                challenge = "challenge-abc",
                installId = "install-1",
                cloudProjectNumber = 123456789L,
            ),
            captured,
        )
        assertEquals(
            AttestationStatement(
                format = AttestationFormats.PLAY_INTEGRITY,
                token = "token-123",
            ),
            statement,
        )
    }

    @Test
    fun `provider returns null when token provider yields blank`() = runTest {
        val provider = PlayIntegrityAttestationProvider(
            tokenProvider = PlayIntegrityTokenProvider { "   " },
        )

        val statement = provider.attest(
            challenge = "challenge-abc",
            installId = "install-1",
        )

        assertNull(statement)
    }

    @Test
    fun `provider wraps raw bridge failures into standardized attestation exception`() = runTest {
        val provider = PlayIntegrityAttestationProvider(
            tokenProvider = PlayIntegrityTokenProvider { error("bridge down") },
        )

        try {
            provider.attest(
                challenge = "challenge-abc",
                installId = "install-1",
            )
            fail("Expected AttestationException")
        } catch (error: AttestationException) {
            assertEquals(AttestationFormats.PLAY_INTEGRITY, error.provider)
            assertEquals(AttestationFailureCodes.ATTESTATION_PROVIDER_FAILED, error.code)
            assertFalse(error.retryable)
        }
    }

    @Test
    fun `provider preserves standardized attestation exception from bridge`() = runTest {
        val expected = AttestationException(
            provider = AttestationFormats.PLAY_INTEGRITY,
            code = AttestationFailureCodes.PLAY_INTEGRITY_CANNOT_BIND_TO_SERVICE,
            retryable = true,
            message = "bind failed",
        )
        val provider = PlayIntegrityAttestationProvider(
            tokenProvider = PlayIntegrityTokenProvider { throw expected },
        )

        try {
            provider.attest(
                challenge = "challenge-abc",
                installId = "install-1",
            )
            fail("Expected AttestationException")
        } catch (error: AttestationException) {
            assertSame(expected, error)
        }
    }
}
