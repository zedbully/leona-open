/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.api;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/** Response body for {@code POST /v1/verdict}. */
public record VerdictResponse(
    BoxId boxId,
    String deviceFingerprint,
    String canonicalDeviceId,
    RiskAssessment risk,
    List<DetectionEvent> events,
    Instant observedAt,
    Instant usedAt
) {
    public VerdictResponse(
        BoxId boxId,
        String deviceFingerprint,
        RiskAssessment risk,
        List<DetectionEvent> events,
        Instant observedAt,
        Instant usedAt
    ) {
        this(boxId, deviceFingerprint, null, risk, events, observedAt, usedAt);
    }

    public VerdictResponse {
        Objects.requireNonNull(boxId, "boxId");
        Objects.requireNonNull(risk, "risk");
        Objects.requireNonNull(observedAt, "observedAt");
        Objects.requireNonNull(usedAt, "usedAt");
        events = events == null ? List.of() : List.copyOf(events);
        // deviceFingerprint may legitimately be null before v0.4.
    }

    @JsonProperty("decision")
    public String decision() {
        return VerdictDecisionPolicy.decision(risk, events);
    }

    @JsonProperty("action")
    public String action() {
        return VerdictDecisionPolicy.action(risk, events);
    }

    @JsonProperty("riskLevel")
    public String riskLevel() {
        return risk.level().name();
    }

    @JsonProperty("riskScore")
    public int riskScore() {
        return risk.score();
    }

    @JsonProperty("riskTags")
    public Set<String> riskTags() {
        return VerdictDecisionPolicy.riskTags(risk, events);
    }
}
