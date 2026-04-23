/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.error;

/**
 * Thrown anywhere inside the application to report a customer-visible
 * failure. Controllers translate this to an {@link ErrorResponse}.
 */
public class LeonaException extends RuntimeException {

    private final ErrorCode code;

    public LeonaException(ErrorCode code) {
        super(code.defaultMessage());
        this.code = code;
    }

    public LeonaException(ErrorCode code, String message) {
        super(message);
        this.code = code;
    }

    public LeonaException(ErrorCode code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public ErrorCode code() { return code; }
}
