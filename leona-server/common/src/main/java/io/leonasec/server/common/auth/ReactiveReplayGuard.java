/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.auth;

import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Objects;

/**
 * Reactive variant of {@link ReplayGuard} for WebFlux callers (gateway,
 * ingestion-service). Identical semantics.
 */
public class ReactiveReplayGuard {

    private static final String KEY_PREFIX = "leona:nonce:";

    private final ReactiveStringRedisTemplate redis;

    public ReactiveReplayGuard(ReactiveStringRedisTemplate redis) {
        this.redis = Objects.requireNonNull(redis);
    }

    /** Returns {@code Mono.just(true)} on first-ever, {@code false} on replay. */
    public Mono<Boolean> claimOrReject(String nonce, Duration ttl) {
        return redis.opsForValue().setIfAbsent(KEY_PREFIX + nonce, "1", ttl);
    }

    public Mono<Boolean> claimOrReject(String nonce) {
        return claimOrReject(nonce, ReplayGuard.DEFAULT_TTL);
    }
}
