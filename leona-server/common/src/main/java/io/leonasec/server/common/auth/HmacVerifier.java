/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.auth;

import io.leonasec.server.common.spi.ApiCryptoProviders;

public final class HmacVerifier {

    private HmacVerifier() {}

    public static String sign(byte[] secret, long timestamp, String nonce, byte[] body) {
        return ApiCryptoProviders.provider().signLegacy(secret, timestamp, nonce, body);
    }

    public static String signSdk(byte[] secret,
                                 String method,
                                 String path,
                                 String contentType,
                                 String sessionId,
                                 String requestId,
                                 long timestamp,
                                 String nonce,
                                 byte[] body) {
        return ApiCryptoProviders.provider()
            .signSdk(secret, method, path, contentType, sessionId, requestId, timestamp, nonce, body);
    }

    public static boolean verify(byte[] secret, long timestamp, String nonce,
                                 byte[] body, String providedSignature) {
        return ApiCryptoProviders.provider().verifyLegacy(secret, timestamp, nonce, body, providedSignature);
    }

    public static boolean verifySdk(byte[] secret,
                                    String method,
                                    String path,
                                    String contentType,
                                    String sessionId,
                                    String requestId,
                                    long timestamp,
                                    String nonce,
                                    byte[] body,
                                    String providedSignature) {
        return ApiCryptoProviders.provider().verifySdk(
            secret, method, path, contentType, sessionId, requestId, timestamp, nonce, body, providedSignature);
    }
}
