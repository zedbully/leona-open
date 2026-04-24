/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.sample

import io.leonasec.leona.config.PlayIntegrityTokenRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SamplePlayIntegrityTest {

    @Test
    fun `debug token mirrors request hash for server challenge binding`() {
        val request = PlayIntegrityTokenRequest(
            requestHash = "challenge-abc",
            challenge = "challenge-abc",
            installId = "install-1",
            cloudProjectNumber = 123456789L,
        )

        val token = SamplePlayIntegrity.buildDebugToken(request)

        assertTrue(token.contains("\"requestHash\":\"challenge-abc\""))
        assertTrue(token.contains("\"appRecognitionVerdict\":\"PLAY_RECOGNIZED\""))
        assertTrue(token.contains("\"deviceRecognitionVerdict\":[\"MEETS_DEVICE_INTEGRITY\"]"))
        assertTrue(token.contains("\"cloudProjectNumber\":123456789"))
        assertTrue(token.contains("\"installId\":\"install-1\""))
    }
}
