/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.query.domain;

import io.leonasec.server.common.api.BoxId;

import java.time.Instant;
import java.util.UUID;

/**
 * Enforces the single-use property on BoxIds. Every verdict request first
 * tries to claim the BoxId — only one caller ever wins.
 *
 * <p>Backed by Redis (primary) and falls back to a PostgreSQL row-level
 * lock if Redis is unreachable. Both paths produce the same {@link Outcome}.
 */
public interface BoxIdClaim {

    Outcome claim(BoxId id, UUID tenantId);

    record Outcome(Status status, Instant usedAt) {
        public static Outcome claimed(Instant now) { return new Outcome(Status.CLAIMED, now); }
        public static Outcome alreadyUsed() { return new Outcome(Status.ALREADY_USED, null); }
        public static Outcome expired() { return new Outcome(Status.EXPIRED, null); }
        public static Outcome notFound() { return new Outcome(Status.NOT_FOUND, null); }
        public static Outcome wrongTenant() { return new Outcome(Status.WRONG_TENANT, null); }
    }

    enum Status {
        CLAIMED,
        ALREADY_USED,
        EXPIRED,
        NOT_FOUND,
        WRONG_TENANT,
    }
}
