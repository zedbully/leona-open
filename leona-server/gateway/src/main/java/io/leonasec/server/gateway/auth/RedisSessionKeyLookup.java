/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.gateway.auth;

import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Base64;

/**
 * Reads the per-session ECDHE-derived key established by {@code /v1/handshake}.
 *
 * <p>The ingestion-service stores session keys at {@code leona:session:<id>}.
 * Gateway uses the same Redis keyspace so it can verify the HMAC on
 * {@code /v1/sense} before the request reaches the ingestion-service.
 */
@Component
public class RedisSessionKeyLookup {

    private static final String KEY_PREFIX = "leona:session:";

    private final ReactiveStringRedisTemplate redis;

    public RedisSessionKeyLookup(ReactiveStringRedisTemplate redis) {
        this.redis = redis;
    }

    public Mono<byte[]> load(String sessionId) {
        return redis.opsForValue()
            .get(KEY_PREFIX + sessionId)
            .map(Base64.getDecoder()::decode);
    }
}
