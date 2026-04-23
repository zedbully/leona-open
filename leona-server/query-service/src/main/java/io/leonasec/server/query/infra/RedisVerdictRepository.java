/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.query.infra;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.leonasec.server.common.api.BoxId;
import io.leonasec.server.common.api.DetectionEvent;
import io.leonasec.server.common.api.RiskAssessment;
import io.leonasec.server.common.api.VerdictResponse;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Redis-first verdict reader. If the worker has warmed the Redis hash
 * (fields {@code risk_level}, {@code risk_score}, {@code risk_reasons_json},
 * {@code events_json}, {@code observed_at}), we serve the verdict without
 * touching Postgres.
 *
 * <p>Used by {@code CompositeVerdictRepository} which falls through to
 * {@code DbVerdictRepository} on miss. This component is deliberately not
 * a {@code VerdictRepository} — it's a plain cache accessor that returns
 * {@code Optional}.
 */
@Component
public class RedisVerdictRepository {

    private static final String KEY_PREFIX = "leona:box:";

    private final StringRedisTemplate redis;
    private final ObjectMapper mapper;

    public RedisVerdictRepository(StringRedisTemplate redis, ObjectMapper mapper) {
        this.redis = redis;
        this.mapper = mapper;
    }

    public Optional<VerdictResponse> load(BoxId id, Instant usedAt) {
        String key = KEY_PREFIX + id.value();
        Map<Object, Object> entries = redis.opsForHash().entries(key);
        if (entries.isEmpty() || !entries.containsKey("risk_level")) {
            return Optional.empty();
        }

        String riskLevel = str(entries, "risk_level", "CLEAN");
        int riskScore = intOf(entries, "risk_score");
        List<String> reasons = parseList(str(entries, "risk_reasons_json", "[]"),
            new TypeReference<>() {});
        List<DetectionEvent> events = parseList(str(entries, "events_json", "[]"),
            new TypeReference<>() {});
        Instant observedAt = Instant.parse(str(entries, "observed_at", Instant.now().toString()));

        return Optional.of(new VerdictResponse(
            id,
            /* deviceFingerprint = */ null,
            new RiskAssessment(
                RiskAssessment.Level.valueOf(riskLevel),
                riskScore,
                reasons == null ? List.of() : reasons),
            events == null ? List.of() : events,
            observedAt,
            usedAt
        ));
    }

    private static String str(Map<Object, Object> map, String key, String def) {
        Object v = map.get(key);
        return v == null ? def : v.toString();
    }

    private static int intOf(Map<Object, Object> map, String key) {
        Object v = map.get(key);
        try { return v == null ? 0 : Integer.parseInt(v.toString()); }
        catch (NumberFormatException e) { return 0; }
    }

    private <T> T parseList(String json, TypeReference<T> ref) {
        try { return mapper.readValue(json, ref); }
        catch (Exception e) { return null; }
    }
}
