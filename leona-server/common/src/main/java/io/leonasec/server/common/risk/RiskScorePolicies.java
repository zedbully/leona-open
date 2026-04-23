/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.risk;

/**
 * Resolves the active risk score policy.
 */
public final class RiskScorePolicies {

    private static final String PRIVATE_POLICY_CLASS =
        "io.leonasec.server.privatebackend.PrivateRiskScorePolicy";

    private static final RiskScorePolicy POLICY = resolve();

    private RiskScorePolicies() {}

    public static RiskScorePolicy active() {
        return POLICY;
    }

    private static RiskScorePolicy resolve() {
        try {
            Class<?> clazz = Class.forName(PRIVATE_POLICY_CLASS);
            Object instance = clazz.getDeclaredConstructor().newInstance();
            if (instance instanceof RiskScorePolicy policy) {
                return policy;
            }
            throw new IllegalStateException(PRIVATE_POLICY_CLASS + " must implement RiskScorePolicy");
        } catch (Throwable ignored) {
            return new DefaultRiskScorePolicy();
        }
    }
}
