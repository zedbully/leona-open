/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.risk;

import io.leonasec.server.common.api.DetectionEvent;
import io.leonasec.server.common.api.RiskAssessment;
import io.leonasec.server.common.api.Severity;

import java.util.ArrayList;
import java.util.List;

/**
 * Shared rule-based risk scorer used by ingestion-time hot-path caching and
 * by the worker's durable persistence flow.
 */
public final class RuleBasedRiskScorer {

    private RuleBasedRiskScorer() {}

    public static RiskAssessment score(List<DetectionEvent> events) {
        return score(events, null);
    }

    public static RiskAssessment score(List<DetectionEvent> events, RiskScoringContext context) {
        RiskScorePolicy policy = RiskScorePolicies.active();
        if (events == null || events.isEmpty()) {
            return new RiskAssessment(RiskAssessment.Level.CLEAN, 0, List.of());
        }

        int total = 0;
        List<String> reasons = new ArrayList<>();
        for (DetectionEvent e : events) {
            int weight = weightOf(e, policy, context);
            total += weight;
            if (weight > 0) reasons.add(e.id());
        }

        int capped = policy.capScore(total, context);
        RiskAssessment.Level level = policy.levelOf(capped, events, context);
        return new RiskAssessment(level, capped, reasons.stream().distinct().toList());
    }

    private static int weightOf(DetectionEvent event, RiskScorePolicy policy, RiskScoringContext context) {
        return policy.severityWeight(event.severity(), context) + policy.categoryBoost(event.category(), context);
    }
}
