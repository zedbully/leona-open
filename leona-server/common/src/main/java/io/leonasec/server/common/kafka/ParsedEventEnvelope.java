/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.kafka;

import io.leonasec.server.common.api.BoxId;
import io.leonasec.server.common.api.DetectionEvent;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * The message published by {@code ingestion-service} and consumed by
 * {@code worker-event-persister}. Carries the parsed detection events so
 * the worker does not need access to the session key.
 */
public record ParsedEventEnvelope(
    BoxId boxId,
    UUID tenantId,
    Instant observedAt,
    Instant expiresAt,
    List<DetectionEvent> events
) {}
