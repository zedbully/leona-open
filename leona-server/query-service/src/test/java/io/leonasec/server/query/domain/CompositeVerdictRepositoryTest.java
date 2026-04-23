/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.query.domain;

import io.leonasec.server.common.api.BoxId;
import io.leonasec.server.common.api.RiskAssessment;
import io.leonasec.server.common.api.VerdictResponse;
import io.leonasec.server.query.infra.DbVerdictRepository;
import io.leonasec.server.query.infra.RedisVerdictRepository;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CompositeVerdictRepositoryTest {

    @Test
    void returnsRedisValueWhenPresent() {
        RedisVerdictRepository redis = mock(RedisVerdictRepository.class);
        DbVerdictRepository db = mock(DbVerdictRepository.class);
        CompositeVerdictRepository repository = new CompositeVerdictRepository(redis, db);

        BoxId boxId = BoxId.generate();
        Instant usedAt = Instant.parse("2026-04-21T12:00:00Z");
        VerdictResponse response = response(boxId, usedAt, RiskAssessment.Level.MEDIUM, 24);

        when(redis.load(boxId, usedAt)).thenReturn(Optional.of(response));

        Optional<VerdictResponse> actual = repository.load(boxId, usedAt);

        assertEquals(Optional.of(response), actual);
    }

    @Test
    void fallsBackToDatabaseWhenRedisThrows() {
        RedisVerdictRepository redis = mock(RedisVerdictRepository.class);
        DbVerdictRepository db = mock(DbVerdictRepository.class);
        CompositeVerdictRepository repository = new CompositeVerdictRepository(redis, db);

        BoxId boxId = BoxId.generate();
        Instant usedAt = Instant.parse("2026-04-21T12:00:00Z");
        VerdictResponse response = response(boxId, usedAt, RiskAssessment.Level.HIGH, 64);

        when(redis.load(boxId, usedAt)).thenThrow(new RuntimeException("redis down"));
        when(db.load(boxId, usedAt)).thenReturn(Optional.of(response));

        Optional<VerdictResponse> actual = repository.load(boxId, usedAt);

        assertEquals(Optional.of(response), actual);
    }

    @Test
    void fallsBackToDatabaseWhenRedisMisses() {
        RedisVerdictRepository redis = mock(RedisVerdictRepository.class);
        DbVerdictRepository db = mock(DbVerdictRepository.class);
        CompositeVerdictRepository repository = new CompositeVerdictRepository(redis, db);

        BoxId boxId = BoxId.generate();
        Instant usedAt = Instant.parse("2026-04-21T12:00:00Z");
        VerdictResponse response = response(boxId, usedAt, RiskAssessment.Level.LOW, 8);

        when(redis.load(boxId, usedAt)).thenReturn(Optional.empty());
        when(db.load(boxId, usedAt)).thenReturn(Optional.of(response));

        Optional<VerdictResponse> actual = repository.load(boxId, usedAt);

        assertEquals(Optional.of(response), actual);
    }

    private VerdictResponse response(BoxId boxId, Instant usedAt, RiskAssessment.Level level, int score) {
        return new VerdictResponse(
            boxId,
            null,
            new RiskAssessment(level, score, List.of("reason")),
            List.of(),
            Instant.parse("2026-04-21T11:59:00Z"),
            usedAt
        );
    }
}
