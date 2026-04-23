/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.worker.infra;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

/**
 * Writes the computed verdict into the {@code leona:box:<id>} hash so that
 * the query-service's hot path returns immediately from Redis. Falls back
 * gracefully — if Redis is down the verdict still lives in Postgres and
 * query-service reads from there.
 */
@Component
public class RedisVerdictCache {

    private static final String KEY_PREFIX = "leona:box:";

    private final StringRedisTemplate redis;

    public RedisVerdictCache(StringRedisTemplate redis) {
        this.redis = redis;
    }

    public void store(String boxId, String riskLevel, int riskScore,
                       String reasonsJson, String eventsJson,
                       Instant observedAt, Instant expiresAt) {
        String key = KEY_PREFIX + boxId;
        redis.opsForHash().putAll(key, Map.of(
            "risk_level", riskLevel,
            "risk_score", String.valueOf(riskScore),
            "risk_reasons_json", reasonsJson,
            "events_json", eventsJson,
            "observed_at", observedAt.toString(),
            "scored_at", Instant.now().toString()
        ));
        Duration ttl = Duration.between(Instant.now(), expiresAt);
        if (!ttl.isNegative() && !ttl.isZero()) {
            redis.expire(key, ttl);
        }
    }
}
