/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.spi;

import io.leonasec.server.common.api.HandshakeRequest;

public interface ApiCryptoProvider {

    interface EcdheSessionHandle {
        String publicKeyBase64Url();
        byte[] deriveSessionKey(String clientPublicKeyBase64Url, String sessionIdSalt, String contextInfo);
    }

    String aad(String method,
               String path,
               String contentType,
               String sessionId,
               String requestId,
               long timestamp,
               String nonce);

    String signable(String method,
                    String path,
                    String contentType,
                    String sessionId,
                    String requestId,
                    long timestamp,
                    String nonce,
                    byte[] body);

    byte[] aadBytes(String method,
                    String path,
                    String contentType,
                    String sessionId,
                    String requestId,
                    long timestamp,
                    String nonce);

    String sha256Hex(byte[] body);

    String signLegacy(byte[] secret, long timestamp, String nonce, byte[] body);

    String signSdk(byte[] secret,
                   String method,
                   String path,
                   String contentType,
                   String sessionId,
                   String requestId,
                   long timestamp,
                   String nonce,
                   byte[] body);

    boolean verifyLegacy(byte[] secret,
                         long timestamp,
                         String nonce,
                         byte[] body,
                         String providedSignature);

    boolean verifySdk(byte[] secret,
                      String method,
                      String path,
                      String contentType,
                      String sessionId,
                      String requestId,
                      long timestamp,
                      String nonce,
                      byte[] body,
                      String providedSignature);

    String deviceBindingCanonical(HandshakeRequest request);

    boolean verifyDeviceBinding(HandshakeRequest request);

    byte[] aesGcmSeal(byte[] key, byte[] plaintext, byte[] associatedData) throws Exception;

    byte[] aesGcmOpen(byte[] key, byte[] wireFormat, byte[] associatedData) throws Exception;

    EcdheSessionHandle generateEcdheSession();

    String fingerprint(byte[] key);
}
