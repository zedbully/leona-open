/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.error;

import java.util.Map;

/**
 * Thrown anywhere inside the application to report a customer-visible
 * failure. Controllers translate this to an {@link ErrorResponse}.
 */
public class LeonaException extends RuntimeException {

    private final ErrorCode code;
    private final Map<String, Object> details;

    public LeonaException(ErrorCode code) {
        this(code, code.defaultMessage(), null, Map.of());
    }

    public LeonaException(ErrorCode code, String message) {
        this(code, message, null, Map.of());
    }

    public LeonaException(ErrorCode code, String message, Throwable cause) {
        this(code, message, cause, Map.of());
    }

    public LeonaException(ErrorCode code, String message, Map<String, Object> details) {
        this(code, message, null, details);
    }

    public LeonaException(ErrorCode code, String message, Throwable cause, Map<String, Object> details) {
        super(message, cause);
        this.code = code;
        this.details = details == null ? Map.of() : Map.copyOf(details);
    }

    public ErrorCode code() { return code; }

    public Map<String, Object> details() { return details; }
}
