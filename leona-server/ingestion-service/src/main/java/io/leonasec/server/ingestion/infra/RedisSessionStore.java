/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.ingestion.infra;

import io.leonasec.server.ingestion.domain.SessionStore;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Base64;

/**
 * Redis-backed {@link SessionStore}. Keys live under {@code leona:session:*}
 * with an explicit TTL so we don't accumulate stale sessions forever.
 */
@Repository
public class RedisSessionStore implements SessionStore {

    private static final String KEY_PREFIX = "leona:session:";

    private final ReactiveStringRedisTemplate redis;

    public RedisSessionStore(ReactiveStringRedisTemplate redis) {
        this.redis = redis;
    }

    @Override
    public Mono<Void> store(String sessionId, byte[] sessionKey, Duration ttl) {
        String encoded = Base64.getEncoder().encodeToString(sessionKey);
        return redis.opsForValue().set(KEY_PREFIX + sessionId, encoded, ttl).then();
    }

    @Override
    public Mono<byte[]> load(String sessionId) {
        return redis.opsForValue().get(KEY_PREFIX + sessionId)
            .map(Base64.getDecoder()::decode);
    }

    @Override
    public Mono<Void> invalidate(String sessionId) {
        return redis.delete(KEY_PREFIX + sessionId).then();
    }
}
