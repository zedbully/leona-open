/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.api;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VerdictDecisionPolicyTest {

    @Test
    void injectionSignalsEscalateToRejectBlock() {
        DetectionEvent event = new DetectionEvent(
            "injection.frida.known_library",
            Category.INJECTION,
            Severity.HIGH,
            Instant.parse("2026-04-24T00:00:00Z"),
            Map.of("source", "request_headers")
        );
        RiskAssessment risk = new RiskAssessment(RiskAssessment.Level.HIGH, 64, List.of(event.id()));

        assertEquals("reject", VerdictDecisionPolicy.decision(risk, List.of(event)));
        assertEquals("block", VerdictDecisionPolicy.action(risk, List.of(event)));
        assertTrue(VerdictDecisionPolicy.riskTags(risk, List.of(event)).contains("hook.frida"));
        assertTrue(VerdictDecisionPolicy.riskTags(risk, List.of(event)).contains("hook.injection"));
    }

    @Test
    void mediumNonInjectionFallsBackToChallengeReview() {
        DetectionEvent event = new DetectionEvent(
            "environment.emulator.detected",
            Category.ENVIRONMENT,
            Severity.MEDIUM,
            Instant.parse("2026-04-24T00:00:00Z"),
            Map.of("source", "native")
        );
        RiskAssessment risk = new RiskAssessment(RiskAssessment.Level.MEDIUM, 24, List.of(event.id()));

        assertEquals("challenge", VerdictDecisionPolicy.decision(risk, List.of(event)));
        assertEquals("review", VerdictDecisionPolicy.action(risk, List.of(event)));
        assertTrue(VerdictDecisionPolicy.riskTags(risk, List.of(event)).contains("environment.risky"));
        assertTrue(VerdictDecisionPolicy.riskTags(risk, List.of(event)).contains("environment.emulator.detected"));
    }
}
