/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.query.infra;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.leonasec.server.common.api.BoxId;
import io.leonasec.server.common.api.VerdictResponse;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RedisVerdictRepositoryTest {

    @Test
    void loadReturnsCanonicalIdentityFieldsFromRedisHash() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        @SuppressWarnings("unchecked")
        HashOperations<String, Object, Object> hash = mock(HashOperations.class);
        when(redis.opsForHash()).thenReturn(hash);

        BoxId boxId = BoxId.generate();
        Map<Object, Object> entries = new LinkedHashMap<>();
        entries.put("risk_level", "LOW");
        entries.put("risk_score", "12");
        entries.put("risk_reasons_json", "[\"reason\"]");
        entries.put("events_json", "[]");
        entries.put("observed_at", "2026-04-21T11:59:00Z");
        entries.put("device_fingerprint", "fp-123");
        entries.put("canonical_device_id", "L756bc06b9f5afc8e80548d41ce43062");
        when(hash.entries(eq("leona:box:" + boxId.value()))).thenReturn(entries);

        RedisVerdictRepository repository = new RedisVerdictRepository(redis, new ObjectMapper());

        var response = repository.load(boxId, Instant.parse("2026-04-21T12:00:00Z"));

        assertTrue(response.isPresent());
        VerdictResponse verdict = response.orElseThrow();
        assertEquals("fp-123", verdict.deviceFingerprint());
        assertEquals("L756bc06b9f5afc8e80548d41ce43062", verdict.canonicalDeviceId());
    }
}
