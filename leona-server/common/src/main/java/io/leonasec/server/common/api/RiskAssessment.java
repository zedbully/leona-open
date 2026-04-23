/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.api;

import java.util.List;
import java.util.Objects;

/**
 * Server-side verdict for a BoxId. Produced by the risk scorer at ingestion
 * time, served verbatim via the verdict endpoint.
 */
public record RiskAssessment(Level level, int score, List<String> reasons) {

    public RiskAssessment {
        Objects.requireNonNull(level, "risk level");
        if (score < 0 || score > 100) {
            throw new IllegalArgumentException("risk score must be in [0,100], got " + score);
        }
        reasons = reasons == null ? List.of() : List.copyOf(reasons);
    }

    public enum Level {
        CLEAN,
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL;

        public boolean atLeast(Level other) {
            return ordinal() >= other.ordinal();
        }
    }
}
