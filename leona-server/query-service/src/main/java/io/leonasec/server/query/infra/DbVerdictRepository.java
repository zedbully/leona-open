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
import io.leonasec.server.query.domain.BoxEntity;
import io.leonasec.server.query.domain.BoxRepository;
import io.leonasec.server.query.domain.VerdictRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Primary verdict repository — reads from Postgres. Used by
 * {@code query-service} when the Redis hot-path doesn't already have
 * the worker's computed verdict cached.
 *
 * <p>Redis reads happen elsewhere ({@link RedisVerdictRepository}); this
 * class is the durable fallback.
 */
@Repository
public class DbVerdictRepository implements VerdictRepository {

    private final BoxRepository boxes;
    private final ObjectMapper mapper;

    public DbVerdictRepository(BoxRepository boxes, ObjectMapper mapper) {
        this.boxes = boxes;
        this.mapper = mapper;
    }

    @Override
    public Optional<VerdictResponse> load(BoxId id, Instant usedAt) {
        return boxes.findById(id.value())
            .map(entity -> toResponse(entity, usedAt));
    }

    private VerdictResponse toResponse(BoxEntity e, Instant usedAt) {
        List<String> reasons = parseReasons(e.getRiskReasonsJson());
        List<DetectionEvent> events = parseEvents(e.getEventsJson());
        return new VerdictResponse(
            BoxId.of(e.getBoxId()),
            e.getDeviceFingerprint(),
            new RiskAssessment(
                RiskAssessment.Level.valueOf(e.getRiskLevel()),
                e.getRiskScore(),
                reasons),
            events,
            e.getObservedAt(),
            usedAt
        );
    }

    private List<String> parseReasons(String json) {
        if (json == null || json.isEmpty()) return List.of();
        try {
            return mapper.readValue(json, new TypeReference<List<String>>() {});
        } catch (Exception e) {
            return List.of();
        }
    }

    private List<DetectionEvent> parseEvents(String json) {
        if (json == null || json.isEmpty()) return List.of();
        try {
            return mapper.readValue(json, new TypeReference<List<DetectionEvent>>() {});
        } catch (Exception e) {
            return List.of();
        }
    }
}
