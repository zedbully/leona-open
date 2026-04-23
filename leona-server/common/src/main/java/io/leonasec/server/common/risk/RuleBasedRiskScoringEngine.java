/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.risk;

import io.leonasec.server.common.api.DetectionEvent;
import io.leonasec.server.common.api.RiskAssessment;

import java.util.List;

/**
 * Default OSS scorer implementation.
 */
public final class RuleBasedRiskScoringEngine implements RiskScoringEngine {
    @Override
    public RiskAssessment score(List<DetectionEvent> events) {
        return RuleBasedRiskScorer.score(events);
    }

    @Override
    public RiskAssessment score(List<DetectionEvent> events, RiskScoringContext context) {
        return RuleBasedRiskScorer.score(events, context);
    }
}
