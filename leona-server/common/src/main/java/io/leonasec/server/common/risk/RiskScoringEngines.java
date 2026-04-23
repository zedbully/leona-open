/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.risk;

/**
 * Resolves the active risk scoring engine.
 */
public final class RiskScoringEngines {

    private static final String PRIVATE_ENGINE_CLASS =
        "io.leonasec.server.privatebackend.PrivateRiskScoringEngine";

    private static final RiskScoringEngine ENGINE = resolve();

    private RiskScoringEngines() {}

    public static RiskScoringEngine active() {
        return ENGINE;
    }

    private static RiskScoringEngine resolve() {
        try {
            Class<?> clazz = Class.forName(PRIVATE_ENGINE_CLASS);
            Object instance = clazz.getDeclaredConstructor().newInstance();
            if (instance instanceof RiskScoringEngine engine) {
                return engine;
            }
            throw new IllegalStateException(PRIVATE_ENGINE_CLASS + " must implement RiskScoringEngine");
        } catch (Throwable ignored) {
            return new RuleBasedRiskScoringEngine();
        }
    }
}
