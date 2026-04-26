/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.sample

import org.junit.Assert.assertTrue
import org.junit.Test

class SampleMainlandAttestationTest {

    @Test
    fun debugTokenContainsExpectedOemEnvelopeFields() {
        val token = SampleMainlandAttestation.buildDebugToken(
            SampleMainlandAttestation.Request(
                challenge = "abc123",
                installId = "install-1",
                packageName = "io.demo.sample",
                manufacturer = "Xiaomi",
                brand = "Redmi",
                model = "K70",
                sdkInt = 34,
                issuedAtMillis = 123456789L,
            )
        )

        assertTrue(token.contains("\"provider\":\"sample_mainland_debug\""))
        assertTrue(token.contains("\"trustTier\":\"oem_attested\""))
        assertTrue(token.contains("\"challenge\":\"abc123\""))
        assertTrue(token.contains("\"installId\":\"install-1\""))
        assertTrue(token.contains("\"packageName\":\"io.demo.sample\""))
        assertTrue(token.contains("\"manufacturer\":\"Xiaomi\""))
        assertTrue(token.contains("\"mode\":\"oem_debug_fake\""))
    }
}
