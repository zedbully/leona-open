/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.auth;

import io.leonasec.server.common.spi.ApiCryptoProviders;

public final class SdkRequestCanonicalizer {

    private SdkRequestCanonicalizer() {}

    public static String aad(String method,
                             String path,
                             String contentType,
                             String sessionId,
                             String requestId,
                             long timestamp,
                             String nonce) {
        return ApiCryptoProviders.provider().aad(method, path, contentType, sessionId, requestId, timestamp, nonce);
    }

    public static String signable(String method,
                                  String path,
                                  String contentType,
                                  String sessionId,
                                  String requestId,
                                  long timestamp,
                                  String nonce,
                                  byte[] body) {
        return ApiCryptoProviders.provider()
            .signable(method, path, contentType, sessionId, requestId, timestamp, nonce, body);
    }

    public static byte[] aadBytes(String method,
                                  String path,
                                  String contentType,
                                  String sessionId,
                                  String requestId,
                                  long timestamp,
                                  String nonce) {
        return ApiCryptoProviders.provider().aadBytes(method, path, contentType, sessionId, requestId, timestamp, nonce);
    }

    public static String sha256Hex(byte[] body) {
        return ApiCryptoProviders.provider().sha256Hex(body);
    }
}
