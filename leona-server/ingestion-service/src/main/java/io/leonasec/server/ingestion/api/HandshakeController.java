/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.ingestion.api;

import io.leonasec.server.common.api.HandshakeRequest;
import io.leonasec.server.common.api.HandshakeResponse;
import io.leonasec.server.ingestion.domain.SessionService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * {@code POST /v1/handshake} — derive a session key with the SDK.
 */
@RestController
@RequestMapping("/v1/handshake")
public class HandshakeController {

    private final SessionService sessions;

    public HandshakeController(SessionService sessions) {
        this.sessions = sessions;
    }

    @PostMapping
    public Mono<ResponseEntity<HandshakeResponse>> handshake(
        @Valid @RequestBody HandshakeRequest request) {
        return sessions.establish(request)
            .map(ResponseEntity::ok);
    }
}
