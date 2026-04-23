/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.risk;

import java.util.UUID;

/**
 * Optional runtime context supplied to the risk scoring engine.
 *
 * <p>Public fallback implementations can ignore it, while private backends can
 * use it for tenant-aware or stage-aware policy selection.
 */
public record RiskScoringContext(
    UUID tenantId,
    Stage stage
) {
    public static RiskScoringContext ingestion(UUID tenantId) {
        return new RiskScoringContext(tenantId, Stage.INGESTION);
    }

    public static RiskScoringContext worker(UUID tenantId) {
        return new RiskScoringContext(tenantId, Stage.WORKER);
    }

    public enum Stage {
        INGESTION,
        WORKER,
    }
}
