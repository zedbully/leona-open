/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.ingestion.domain;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

/**
 * Supplies an optional tamper baseline to the SDK during handshake.
 *
 * <p>The initial server-side rollout keeps this intentionally simple: an
 * operator can provide a JSON object via configuration, and the handshake
 * response will echo it under {@code tamperBaseline}. The Android SDK merges
 * that baseline with any local Builder-supplied policy, preferring the server
 * values when both are present.
 */
@Component
public class TamperBaselineProvider {

    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};

    private final Map<String, Object> baseline;

    public TamperBaselineProvider(
        @Value("${leona.handshake.tamper-baseline-json:}") String rawJson,
        ObjectMapper objectMapper
    ) {
        this.baseline = parse(rawJson, objectMapper);
    }

    public Map<String, Object> current() {
        return baseline;
    }

    private static Map<String, Object> parse(String rawJson, ObjectMapper objectMapper) {
        if (rawJson == null || rawJson.isBlank()) {
            return Map.of();
        }
        try {
            Map<String, Object> parsed = objectMapper.readValue(rawJson, MAP_TYPE);
            return Collections.unmodifiableMap(parsed);
        } catch (IOException e) {
            throw new IllegalArgumentException("Invalid leona.handshake.tamper-baseline-json", e);
        }
    }
}
