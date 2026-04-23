/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.auth;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VerdictResponseSignerTest {

    @Test
    void verifyPassesForMatchingInputs() {
        byte[] secret = "lk_live_sec_abcdefghijklmnopqrstuvwxyz".getBytes();
        String generatedAt = "2026-04-21T12:00:00Z";
        byte[] body = "{\"risk\":{\"level\":\"LOW\"}}".getBytes();

        String sig = VerdictResponseSigner.sign(secret, generatedAt, body);

        assertTrue(VerdictResponseSigner.verify(secret, generatedAt, body, sig));
    }

    @Test
    void verifyFailsWhenBodyChanges() {
        byte[] secret = "lk_live_sec_abcdefghijklmnopqrstuvwxyz".getBytes();
        String generatedAt = "2026-04-21T12:00:00Z";
        byte[] body = "{\"risk\":{\"level\":\"LOW\"}}".getBytes();
        String sig = VerdictResponseSigner.sign(secret, generatedAt, body);

        assertFalse(VerdictResponseSigner.verify(
            secret, generatedAt, "{\"risk\":{\"level\":\"HIGH\"}}".getBytes(), sig));
    }
}
