/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.spi;

import io.leonasec.server.common.api.HandshakeRequest;

import java.util.Objects;

public final class ApiCryptoProviders {

    private static final String BOOTSTRAP_CLASS = "io.leonasec.server.privatebackend.PrivateApiCryptoBootstrap";

    private static volatile ApiCryptoProvider provider;

    private ApiCryptoProviders() {}

    public static ApiCryptoProvider provider() {
        ApiCryptoProvider current = provider;
        if (current != null) {
            return current;
        }
        synchronized (ApiCryptoProviders.class) {
            current = provider;
            if (current != null) {
                return current;
            }
            bootstrap();
            current = provider;
            return current != null ? current : MissingApiCryptoProvider.INSTANCE;
        }
    }

    public static void install(ApiCryptoProvider installed) {
        provider = Objects.requireNonNull(installed, "installed");
    }

    public static boolean isInstalled() {
        return provider != null;
    }

    public static void resetForTests() {
        provider = null;
    }

    private static void bootstrap() {
        try {
            Class.forName(BOOTSTRAP_CLASS);
        } catch (ClassNotFoundException ignored) {
            // Public repository intentionally ships without the closed-source implementation.
        }
    }

    private enum MissingApiCryptoProvider implements ApiCryptoProvider {
        INSTANCE;

        private UnsupportedOperationException missing() {
            return new UnsupportedOperationException(
                "Closed-source crypto module is not installed. Add :private-api-backend to the runtime classpath.");
        }

        @Override
        public String aad(String method, String path, String contentType, String sessionId, String requestId,
                          long timestamp, String nonce) {
            throw missing();
        }

        @Override
        public String signable(String method, String path, String contentType, String sessionId, String requestId,
                               long timestamp, String nonce, byte[] body) {
            throw missing();
        }

        @Override
        public byte[] aadBytes(String method, String path, String contentType, String sessionId, String requestId,
                               long timestamp, String nonce) {
            throw missing();
        }

        @Override
        public String sha256Hex(byte[] body) {
            throw missing();
        }

        @Override
        public String signLegacy(byte[] secret, long timestamp, String nonce, byte[] body) {
            throw missing();
        }

        @Override
        public String signSdk(byte[] secret, String method, String path, String contentType, String sessionId,
                              String requestId, long timestamp, String nonce, byte[] body) {
            throw missing();
        }

        @Override
        public boolean verifyLegacy(byte[] secret, long timestamp, String nonce, byte[] body, String providedSignature) {
            throw missing();
        }

        @Override
        public boolean verifySdk(byte[] secret, String method, String path, String contentType, String sessionId,
                                 String requestId, long timestamp, String nonce, byte[] body,
                                 String providedSignature) {
            throw missing();
        }

        @Override
        public String deviceBindingCanonical(HandshakeRequest request) {
            throw missing();
        }

        @Override
        public boolean verifyDeviceBinding(HandshakeRequest request) {
            throw missing();
        }

        @Override
        public byte[] aesGcmSeal(byte[] key, byte[] plaintext, byte[] associatedData) {
            throw missing();
        }

        @Override
        public byte[] aesGcmOpen(byte[] key, byte[] wireFormat, byte[] associatedData) {
            throw missing();
        }

        @Override
        public EcdheSessionHandle generateEcdheSession() {
            throw missing();
        }

        @Override
        public String fingerprint(byte[] key) {
            throw missing();
        }
    }
}
