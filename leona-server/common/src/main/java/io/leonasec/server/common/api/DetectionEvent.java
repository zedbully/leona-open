/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.api;

import java.time.Instant;
import java.util.Map;

/**
 * One detection event as produced by the SDK's native core. Uniform across
 * SDK platforms (Android, future iOS) so downstream analytics stays stable.
 *
 * <p>Identified by {@link #id}, which is a dotted namespace such as
 * {@code injection.frida.trampoline.arm64.v1}.
 */
public record DetectionEvent(
    String id,
    Category category,
    Severity severity,
    Instant at,
    Map<String, String> evidence
) {
    public DetectionEvent {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("event id must be non-blank");
        }
        if (category == null) throw new IllegalArgumentException("category must be non-null");
        if (severity == null) throw new IllegalArgumentException("severity must be non-null");
        if (at == null) throw new IllegalArgumentException("at must be non-null");
        evidence = evidence == null ? Map.of() : Map.copyOf(evidence);
    }
}
