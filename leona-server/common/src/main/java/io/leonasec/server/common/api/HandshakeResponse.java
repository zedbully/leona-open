/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.api;

import java.time.Instant;
import java.util.Map;

/** Response body for {@code POST /v1/handshake}. */
public record HandshakeResponse(
    String serverPublicKey,
    String sessionId,
    Instant expiresAt,
    Map<String, Object> tamperBaseline,
    String deviceBindingStatus,
    AttestationSummary attestation,
    String canonicalDeviceId
) {
    public HandshakeResponse(
        String serverPublicKey,
        String sessionId,
        Instant expiresAt,
        Map<String, Object> tamperBaseline,
        String deviceBindingStatus,
        AttestationSummary attestation
    ) {
        this(serverPublicKey, sessionId, expiresAt, tamperBaseline, deviceBindingStatus, attestation, null);
    }

    public record AttestationSummary(
        String provider,
        String status,
        String code,
        Boolean retryable
    ) {}
}
