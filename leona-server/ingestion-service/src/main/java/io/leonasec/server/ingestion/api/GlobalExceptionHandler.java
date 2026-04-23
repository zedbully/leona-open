/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.ingestion.api;

import io.leonasec.server.common.error.ErrorCode;
import io.leonasec.server.common.error.ErrorResponse;
import io.leonasec.server.common.error.LeonaException;
import io.leonasec.server.common.util.RequestIds;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(LeonaException.class)
    public ResponseEntity<ErrorResponse> handleLeona(LeonaException ex) {
        return ResponseEntity
            .status(ex.code().status())
            .body(new ErrorResponse(ex.code(), ex.getMessage(), RequestIds.newId()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleUnexpected(Exception ex) {
        // Log the full stack internally; return a uniform error to the caller.
        return ResponseEntity
            .status(ErrorCode.LEONA_INTERNAL_ERROR.status())
            .body(new ErrorResponse(ErrorCode.LEONA_INTERNAL_ERROR, RequestIds.newId()));
    }
}
