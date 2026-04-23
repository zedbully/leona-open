/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.risk;

import io.leonasec.server.common.api.Category;
import io.leonasec.server.common.api.DetectionEvent;
import io.leonasec.server.common.api.RiskAssessment;
import io.leonasec.server.common.api.Severity;

import java.util.List;

/**
 * Rule weights / boosts / thresholds used by the rule-based scorer.
 *
 * <p>The public repo keeps a fallback policy while private deployments can
 * provide a stronger implementation from the private backend module.
 */
public interface RiskScorePolicy {

    int severityWeight(Severity severity);

    default int severityWeight(Severity severity, RiskScoringContext context) {
        return severityWeight(severity);
    }

    int categoryBoost(Category category);

    default int categoryBoost(Category category, RiskScoringContext context) {
        return categoryBoost(category);
    }

    RiskAssessment.Level levelOf(int score, List<DetectionEvent> events);

    default RiskAssessment.Level levelOf(int score, List<DetectionEvent> events, RiskScoringContext context) {
        return levelOf(score, events);
    }

    default int capScore(int total) {
        return Math.min(100, total);
    }

    default int capScore(int total, RiskScoringContext context) {
        return capScore(total);
    }
}
