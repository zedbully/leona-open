/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.risk;

import io.leonasec.server.common.api.Category;
import io.leonasec.server.common.api.DetectionEvent;
import io.leonasec.server.common.api.RiskAssessment;
import io.leonasec.server.common.api.Severity;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RuleBasedRiskScorerTest {

    @Test
    void emptyEventListIsClean() {
        RiskAssessment risk = RuleBasedRiskScorer.score(List.of());
        assertEquals(RiskAssessment.Level.CLEAN, risk.level());
        assertEquals(0, risk.score());
    }

    @Test
    void criticalInjectionEscalatesToCritical() {
        DetectionEvent event = new DetectionEvent(
            "injection.frida.trampoline.arm64.v1",
            Category.INJECTION,
            Severity.CRITICAL,
            Instant.parse("2026-04-21T00:00:00Z"),
            Map.of("path", "[anon]")
        );

        RiskAssessment risk = RuleBasedRiskScorer.score(List.of(event));

        assertEquals(RiskAssessment.Level.CRITICAL, risk.level());
        assertEquals(50, risk.score());
        assertEquals(List.of(event.id()), risk.reasons());
    }
}
