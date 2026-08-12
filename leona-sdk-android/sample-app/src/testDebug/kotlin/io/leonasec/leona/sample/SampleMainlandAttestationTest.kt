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
        val token = SampleMainlandDebugAttestation.buildDebugToken(
            SampleMainlandAttestation.Request(
                challenge = "abc123",
                installIdSha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
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
        assertTrue(token.contains("\"installIdSha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\""))
        assertTrue(token.contains("\"packageName\":\"io.demo.sample\""))
        assertTrue(token.contains("\"manufacturer\":\"Xiaomi\""))
        assertTrue(token.contains("\"mode\":\"oem_debug_fake\""))
    }
}
