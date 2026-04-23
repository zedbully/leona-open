/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.query.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.leonasec.server.common.api.VerdictRequest;
import io.leonasec.server.common.api.VerdictResponse;
import io.leonasec.server.common.auth.VerdictResponseSigner;
import io.leonasec.server.common.error.ErrorCode;
import io.leonasec.server.common.error.LeonaException;
import io.micrometer.core.instrument.MeterRegistry;
import io.leonasec.server.query.domain.VerdictService;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;

/**
 * {@code POST /v1/verdict}.
 *
 * <p>Authentication (Bearer tenant secret) and signature verification
 * happen in the gateway. By the time we see the request we trust:
 *
 * <ul>
 *   <li>Tenant is authenticated and not suspended.</li>
 *   <li>Body + timestamp + nonce + signature all valid.</li>
 * </ul>
 */
@RestController
@RequestMapping("/v1/verdict")
public class VerdictController {

    private final VerdictService service;
    private final ObjectMapper mapper;
    private final MeterRegistry metrics;

    public VerdictController(VerdictService service, ObjectMapper mapper, MeterRegistry metrics) {
        this.service = service;
        this.mapper = mapper;
        this.metrics = metrics;
    }

    @PostMapping
    public ResponseEntity<String> verdict(
        @RequestHeader("X-Leona-Tenant") UUID tenantId,
        @RequestHeader("Authorization") String authorization,
        @Valid @RequestBody VerdictRequest request
    ) {
        VerdictResponse response = service.consume(tenantId, request.boxId());
        String generatedAt = Instant.now().toString();
        byte[] body = writeJson(response);
        String signature = VerdictResponseSigner.sign(
            extractSecret(authorization),
            generatedAt,
            body
        );
        metrics.counter("leona.verdict.success").increment();
        metrics.counter("leona.verdict.risk_level", "risk", response.risk().level().name()).increment();

        return ResponseEntity.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .header("X-Leona-Verdict-Generated-At", generatedAt)
            .header("X-Leona-Verdict-Signature", signature)
            .header("X-Leona-Verdict-Signature-Alg", "HMAC-SHA256")
            .body(new String(body, StandardCharsets.UTF_8));
    }

    private byte[] writeJson(VerdictResponse response) {
        try {
            return mapper.writeValueAsBytes(response);
        } catch (JsonProcessingException e) {
            throw new LeonaException(ErrorCode.LEONA_INTERNAL_ERROR, "Failed to serialize verdict", e);
        }
    }

    private byte[] extractSecret(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            throw new LeonaException(ErrorCode.LEONA_AUTH_INVALID, "Bearer token missing");
        }
        String secret = authorization.substring("Bearer ".length()).trim();
        if (secret.isEmpty()) {
            throw new LeonaException(ErrorCode.LEONA_AUTH_INVALID, "Bearer token missing");
        }
        return secret.getBytes(StandardCharsets.UTF_8);
    }
}
