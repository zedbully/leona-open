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
 * Default OSS fallback risk policy.
 */
public final class DefaultRiskScorePolicy implements RiskScorePolicy {
    @Override
    public int severityWeight(Severity severity) {
        return switch (severity) {
            case INFO -> 0;
            case LOW -> 2;
            case MEDIUM -> 8;
            case HIGH -> 20;
            case CRITICAL -> 40;
        };
    }

    @Override
    public int categoryBoost(Category category) {
        return switch (category) {
            case INJECTION, UNIDBG, HONEYPOT_TRIPPED -> 10;
            case ENVIRONMENT, TAMPERING -> 4;
            case NETWORK -> 2;
            case OTHER -> 0;
        };
    }

    @Override
    public RiskAssessment.Level levelOf(int score, List<DetectionEvent> events) {
        boolean anyCritical = events.stream().anyMatch(e -> e.severity().atLeast(Severity.CRITICAL));
        if (anyCritical || score >= 80) return RiskAssessment.Level.CRITICAL;
        if (score >= 50) return RiskAssessment.Level.HIGH;
        if (score >= 20) return RiskAssessment.Level.MEDIUM;
        if (score > 0) return RiskAssessment.Level.LOW;
        return RiskAssessment.Level.CLEAN;
    }
}
