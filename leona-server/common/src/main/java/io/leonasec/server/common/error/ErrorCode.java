/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.error;

import org.springframework.http.HttpStatus;

/** Every customer-visible error response carries one of these codes. */
public enum ErrorCode {
    LEONA_AUTH_MISSING(HttpStatus.UNAUTHORIZED, "Authentication headers are missing"),
    LEONA_AUTH_INVALID(HttpStatus.UNAUTHORIZED, "Credentials are invalid"),
    LEONA_SIGNATURE_INVALID(HttpStatus.UNAUTHORIZED, "Request signature did not verify"),
    LEONA_TIMESTAMP_SKEW(HttpStatus.UNAUTHORIZED, "Request timestamp outside acceptable window"),
    LEONA_NONCE_REPLAY(HttpStatus.UNAUTHORIZED, "Replay detected: nonce already seen"),
    LEONA_RATE_LIMITED(HttpStatus.TOO_MANY_REQUESTS, "Rate limit exceeded"),
    LEONA_PAYLOAD_MALFORMED(HttpStatus.BAD_REQUEST, "Request payload could not be decoded"),
    LEONA_PAYLOAD_TOO_LARGE(HttpStatus.PAYLOAD_TOO_LARGE, "Payload exceeds 128 KiB"),
    LEONA_BOX_NOT_FOUND(HttpStatus.NOT_FOUND, "BoxId does not exist"),
    LEONA_BOX_ALREADY_USED(HttpStatus.GONE, "BoxId has already been consumed"),
    LEONA_BOX_EXPIRED(HttpStatus.GONE, "BoxId has expired"),
    LEONA_TENANT_SUSPENDED(HttpStatus.FORBIDDEN, "Tenant is suspended"),
    LEONA_INTERNAL_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "Internal server error");

    private final HttpStatus status;
    private final String defaultMessage;

    ErrorCode(HttpStatus status, String defaultMessage) {
        this.status = status;
        this.defaultMessage = defaultMessage;
    }

    public HttpStatus status() { return status; }
    public String defaultMessage() { return defaultMessage; }
}
