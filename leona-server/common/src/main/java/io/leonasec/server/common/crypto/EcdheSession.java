/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.crypto;

import io.leonasec.server.common.spi.ApiCryptoProvider;
import io.leonasec.server.common.spi.ApiCryptoProviders;

public final class EcdheSession {

    private final ApiCryptoProvider.EcdheSessionHandle handle;

    private EcdheSession(ApiCryptoProvider.EcdheSessionHandle handle) {
        this.handle = handle;
    }

    public static EcdheSession generate() {
        return new EcdheSession(ApiCryptoProviders.provider().generateEcdheSession());
    }

    public String publicKeyBase64Url() {
        return handle.publicKeyBase64Url();
    }

    public byte[] deriveSessionKey(String clientPublicKeyBase64Url, String sessionIdSalt, String contextInfo) {
        return handle.deriveSessionKey(clientPublicKeyBase64Url, sessionIdSalt, contextInfo);
    }

    public static String fingerprint(byte[] key) {
        return ApiCryptoProviders.provider().fingerprint(key);
    }
}
