/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.config

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
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
}
