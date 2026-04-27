/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.ingestion.infra;

import io.leonasec.server.common.api.BoxId;
import io.leonasec.server.common.api.RiskAssessment;
import io.leonasec.server.ingestion.domain.BoxIdRepository;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Stores the hot-path Redis hash at {@code leona:box:<id>} carrying the
 * tenant id, timestamps, and an immediately queryable risk snapshot.
 */
@Repository
public class RedisBoxIdRepository implements BoxIdRepository {

    private static final String KEY_PREFIX = "leona:box:";

    private final ReactiveRedisTemplate<String, String> redis;

    public RedisBoxIdRepository(ReactiveRedisTemplate<String, String> redis) {
        this.redis = redis;
    }

    @Override
    public Mono<Void> store(BoxId id, UUID tenantId, String deviceFingerprint, String canonicalDeviceId,
                            Instant observedAt, Instant expiresAt, RiskAssessment risk, String eventsJson) {
        String key = KEY_PREFIX + id.value();
        Duration ttl = Duration.between(Instant.now(), expiresAt);
        Map<Object, Object> fields = new LinkedHashMap<>();
        fields.put("tenant", tenantId.toString());
        if (deviceFingerprint != null && !deviceFingerprint.isBlank()) {
            fields.put("device_fingerprint", deviceFingerprint);
        }
        if (canonicalDeviceId != null && !canonicalDeviceId.isBlank()) {
            fields.put("canonical_device_id", canonicalDeviceId);
        }
        fields.put("observed_at", observedAt.toString());
        fields.put("expires_at", expiresAt.toString());
        fields.put("expires_at_epoch_ms", String.valueOf(expiresAt.toEpochMilli()));
        fields.put("risk_level", risk.level().name());
        fields.put("risk_score", String.valueOf(risk.score()));
        fields.put("risk_reasons_json", toJsonArray(risk.reasons()));
        fields.put("events_json", eventsJson);
        return redis.opsForHash().putAll(key, fields)
            .then(redis.expire(key, ttl))
            .then();
    }

    private String toJsonArray(Iterable<String> values) {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (String value : values) {
            if (!first) sb.append(',');
            sb.append('"').append(value.replace("\\", "\\\\").replace("\"", "\\\"")).append('"');
            first = false;
        }
        sb.append(']');
        return sb.toString();
    }
}
