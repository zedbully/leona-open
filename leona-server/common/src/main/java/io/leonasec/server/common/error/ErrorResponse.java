/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.error;

import java.util.Map;

/** Uniform error response body. Shape matches {@code Error} in the OpenAPI spec. */
public record ErrorResponse(
    ErrorCode code,
    String message,
    String requestId,
    Map<String, Object> details
) {
    public ErrorResponse(ErrorCode code, String requestId) {
        this(code, code.defaultMessage(), requestId, Map.of());
    }

    public ErrorResponse(ErrorCode code, String message, String requestId) {
        this(code, message, requestId, Map.of());
    }
}
