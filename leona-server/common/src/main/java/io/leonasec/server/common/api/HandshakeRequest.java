/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.api;

/**
 * Request body for {@code POST /v1/handshake}.
 *
 * <p>{@code clientPublicKey} is base64url-encoded X25519 public key.
 * {@code deviceBinding} is an optional Android Keystore-backed proof that
 * binds the handshake to a long-lived device signing key.
 */
public record HandshakeRequest(
    String clientPublicKey,
    String installId,
    String sdkVersion,
    DeviceBinding deviceBinding
) {

    public record DeviceBinding(
        String keyAlgorithm,
        String publicKey,
        String signatureAlgorithm,
        String signature,
        boolean hardwareBacked,
        String attestationFormat,
        String attestationToken
    ) {}
}
