/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.risk;

import io.leonasec.server.common.api.DetectionEvent;
import io.leonasec.server.common.api.RiskAssessment;

import java.util.List;

/**
 * Backend risk scoring extension point.
 *
 * Public builds can use the default rule-based scorer, while private backend
 * modules may supply a stronger implementation without changing callers.
 */
public interface RiskScoringEngine {
    RiskAssessment score(List<DetectionEvent> events);

    default RiskAssessment score(List<DetectionEvent> events, RiskScoringContext context) {
        return score(events);
    }
}
