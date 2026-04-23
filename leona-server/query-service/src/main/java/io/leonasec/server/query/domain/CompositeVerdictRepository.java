/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.query.domain;

import io.leonasec.server.common.api.BoxId;
import io.leonasec.server.common.api.VerdictResponse;
import io.leonasec.server.query.infra.DbVerdictRepository;
import io.leonasec.server.query.infra.RedisVerdictRepository;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Optional;

/**
 * Composite repository: Redis first, Postgres fallback.
 *
 * <p>Redis carries the verdict the worker warmed while it was fresh;
 * Postgres has durable history. If Redis is down we degrade gracefully
 * to Postgres without failing the request.
 */
@Component
@Primary
public class CompositeVerdictRepository implements VerdictRepository {

    private final RedisVerdictRepository redis;
    private final DbVerdictRepository db;

    public CompositeVerdictRepository(RedisVerdictRepository redis, DbVerdictRepository db) {
        this.redis = redis;
        this.db = db;
    }

    @Override
    public Optional<VerdictResponse> load(BoxId id, Instant usedAt) {
        try {
            Optional<VerdictResponse> cached = redis.load(id, usedAt);
            if (cached.isPresent()) return cached;
        } catch (Exception e) {
            // Redis degraded — fall through to DB.
        }
        return db.load(id, usedAt);
    }
}
