/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.ingestion.api;

import io.leonasec.server.common.api.SenseResponse;
import io.leonasec.server.common.error.ErrorCode;
import io.leonasec.server.common.error.LeonaException;
import io.leonasec.server.ingestion.domain.SenseService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/** {@code POST /v1/sense} — accept encrypted SDK payload, mint BoxId. */
@RestController
@RequestMapping("/v1/sense")
public class SenseController {

    private static final int MAX_PAYLOAD_BYTES = 128 * 1024;

    private final SenseService sense;

    public SenseController(SenseService sense) {
        this.sense = sense;
    }

    @PostMapping(consumes = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public Mono<ResponseEntity<SenseResponse>> sense(
        @RequestHeader("X-Leona-Session-Id") String sessionId,
        @RequestHeader("X-Leona-Request-Id") String requestId,
        @RequestHeader("X-Leona-Timestamp") long timestamp,
        @RequestHeader("X-Leona-Nonce") String nonce,
        @RequestHeader("X-Leona-Tenant") String tenantId,
        @RequestHeader(value = "X-Leona-Native-Risk-Tags", required = false) String nativeRiskTags,
        @RequestHeader(value = "X-Leona-Native-Finding-Ids", required = false) String nativeFindingIds,
        @RequestHeader(value = "X-Leona-Native-Highest-Severity", required = false) Integer nativeHighestSeverity,
        @RequestBody byte[] body
    ) {
        if (body == null || body.length == 0) {
            return Mono.error(new LeonaException(
                ErrorCode.LEONA_PAYLOAD_MALFORMED, "Empty body"));
        }
        if (body.length > MAX_PAYLOAD_BYTES) {
            return Mono.error(new LeonaException(
                ErrorCode.LEONA_PAYLOAD_TOO_LARGE,
                "Payload " + body.length + " bytes exceeds cap " + MAX_PAYLOAD_BYTES));
        }
        return sense.ingest(
                sessionId,
                tenantId,
                body,
                requestId,
                timestamp,
                nonce,
                io.leonasec.server.ingestion.domain.SenseRequestRiskSignals.fromHeaders(
                    nativeRiskTags,
                    nativeFindingIds,
                    nativeHighestSeverity
                )
            )
            .map(ResponseEntity::ok);
    }
}
