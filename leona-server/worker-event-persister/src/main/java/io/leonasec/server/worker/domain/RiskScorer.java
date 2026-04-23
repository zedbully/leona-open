/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.worker.domain;

import io.leonasec.server.common.api.DetectionEvent;
import io.leonasec.server.common.api.RiskAssessment;
import io.leonasec.server.common.risk.RiskScoringEngine;
import io.leonasec.server.common.risk.RiskScoringEngines;
import io.leonasec.server.common.risk.RiskScoringContext;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.UUID;

/**
 * Rule-based risk scorer for v0.1.0-alpha.1.
 *
 * <p>Each event contributes a weighted score based on severity and category.
 * The worker stores the final verdict in Postgres; the query-service reads
 * it unchanged. The ML-based scorer on the roadmap will replace this
 * implementation without touching the calling code.
 */
@Component
public class RiskScorer {

    private final RiskScoringEngine engine = RiskScoringEngines.active();

    public RiskAssessment score(List<DetectionEvent> events) {
        return engine.score(events);
    }

    public RiskAssessment score(UUID tenantId, List<DetectionEvent> events) {
        return engine.score(events, RiskScoringContext.worker(tenantId));
    }
}
