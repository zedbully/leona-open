/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.auth;

import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Duration;
import java.util.Objects;

/**
 * Blocking Redis-backed {@link ReplayGuard}. Uses {@code SET NX EX} so the
 * atomic "claim if absent" primitive is a single round trip.
 */
public class RedisReplayGuard implements ReplayGuard {

    private static final String KEY_PREFIX = "leona:nonce:";

    private final StringRedisTemplate redis;

    public RedisReplayGuard(StringRedisTemplate redis) {
        this.redis = Objects.requireNonNull(redis);
    }

    @Override
    public boolean claimOrReject(String nonce, Duration ttl) {
        String key = KEY_PREFIX + nonce;
        Boolean set = redis.opsForValue().setIfAbsent(key, "1", ttl);
        return Boolean.TRUE.equals(set);
    }
}
