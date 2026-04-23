/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.ingestion.domain;

import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * Per-session key store. Backed by Redis (see {@code RedisSessionStore}).
 */
public interface SessionStore {

    Mono<Void> store(String sessionId, byte[] sessionKey, Duration ttl);

    Mono<byte[]> load(String sessionId);

    Mono<Void> invalidate(String sessionId);
}
