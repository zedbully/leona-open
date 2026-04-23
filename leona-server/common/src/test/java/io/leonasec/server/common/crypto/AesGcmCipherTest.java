/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.crypto;

import io.leonasec.server.common.spi.TestCryptoSupport;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AesGcmCipherTest {

    static {
        TestCryptoSupport.install();
    }

    private final AesGcmCipher cipher = new AesGcmCipher();

    @Test
    void roundTripSucceedsWithMatchingAssociatedData() throws Exception {
        byte[] key = new byte[32];
        for (int i = 0; i < key.length; i++) key[i] = (byte) (i + 1);

        byte[] plaintext = "hello-leona".getBytes();
        byte[] aad = "session-123".getBytes();

        byte[] sealed = cipher.seal(key, plaintext, aad);
        byte[] opened = cipher.open(key, sealed, aad);

        assertArrayEquals(plaintext, opened);
    }

    @Test
    void openFailsWhenAssociatedDataDoesNotMatch() throws Exception {
        byte[] key = new byte[32];
        byte[] plaintext = "payload".getBytes();

        byte[] sealed = cipher.seal(key, plaintext, "session-a".getBytes());

        assertThrows(Exception.class, () ->
            cipher.open(key, sealed, "session-b".getBytes()));
    }
}
