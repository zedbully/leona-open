/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.auth;

import java.util.UUID;

/**
 * Authenticated principal for the current request, propagated by the gateway
 * via the {@code X-Leona-Tenant} header after it has verified the AppKey or
 * SecretKey. Downstream services trust this header <strong>only because the
 * network policy ensures they are unreachable except via the gateway</strong>.
 */
public record TenantContext(UUID tenantId, String appKey, Role role) {

    public enum Role {
        /** SDK — uploads detection payloads. */
        INGESTION,
        /** Customer backend — queries verdicts. */
        VERDICT_CONSUMER,
        /** Human operator via dashboard. */
        ADMIN,
    }

    public static TenantContext ingestion(UUID tenantId, String appKey) {
        return new TenantContext(tenantId, appKey, Role.INGESTION);
    }

    public static TenantContext verdictConsumer(UUID tenantId, String appKey) {
        return new TenantContext(tenantId, appKey, Role.VERDICT_CONSUMER);
    }
}
