/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.ingestion.domain;

import io.leonasec.server.common.api.HandshakeRequest;

/**
 * Pluggable attestation verifier.
 *
 * Alpha default is permissive so projects can ship the protocol now and add
 * Play Integrity verification later without redesigning the handshake.
 */
public interface DeviceAttestationVerifier {
    Result verify(HandshakeRequest request);

    record Result(
        boolean accepted,
        String status,
        String provider,
        String code,
        Boolean retryable
    ) {
        public static Result accepted(String status) {
            return new Result(true, status, null, null, null);
        }

        public static Result accepted(String status, String provider, String code, Boolean retryable) {
            return new Result(true, status, provider, code, retryable);
        }

        public static Result rejected(String status) {
            return new Result(false, status, null, null, null);
        }

        public static Result rejected(String status, String provider, String code, Boolean retryable) {
            return new Result(false, status, provider, code, retryable);
        }
    }
}
