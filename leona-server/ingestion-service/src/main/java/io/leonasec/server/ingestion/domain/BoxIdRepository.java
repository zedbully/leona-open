/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.ingestion.domain;

import io.leonasec.server.common.api.BoxId;
import io.leonasec.server.common.api.RiskAssessment;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

/**
 * Hot-path box record stored at ingestion time. It contains the minimum data
 * needed for query-service to answer an immediate verdict lookup from Redis,
 * before the worker finishes durable persistence.
 */
public interface BoxIdRepository {

    Mono<Void> store(BoxId id, UUID tenantId, String deviceFingerprint, String canonicalDeviceId,
                     Instant observedAt, Instant expiresAt, RiskAssessment risk, String eventsJson);
}
