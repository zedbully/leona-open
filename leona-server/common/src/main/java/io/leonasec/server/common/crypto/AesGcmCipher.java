/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.crypto;

import io.leonasec.server.common.spi.ApiCryptoProviders;

public final class AesGcmCipher {

    public static final int NONCE_LEN = 12;
    public static final int TAG_BITS = 128;
    public static final int TAG_BYTES = TAG_BITS / 8;
    public static final int KEY_LEN = 32;

    public byte[] seal(byte[] key, byte[] plaintext, byte[] associatedData) throws Exception {
        return ApiCryptoProviders.provider().aesGcmSeal(key, plaintext, associatedData);
    }

    public byte[] open(byte[] key, byte[] wireFormat, byte[] associatedData) throws Exception {
        return ApiCryptoProviders.provider().aesGcmOpen(key, wireFormat, associatedData);
    }
}
