/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.ingestion.domain;

import io.leonasec.server.common.api.Category;
import io.leonasec.server.common.api.DetectionEvent;
import io.leonasec.server.common.api.Severity;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Supplemental risk hints carried in SDK headers.
 *
 * <p>These values are client-provided and therefore not a trust anchor, but we
 * still persist/score them as corroborating telemetry so obvious hook signals
 * are not silently discarded when they reach the server.
 */
public record SenseRequestRiskSignals(
    Set<String> nativeRiskTags,
    List<String> nativeFindingIds,
    Integer nativeHighestSeverity
) {

    static final SenseRequestRiskSignals EMPTY =
        new SenseRequestRiskSignals(Set.of(), List.of(), null);

    public SenseRequestRiskSignals {
        nativeRiskTags = nativeRiskTags == null ? Set.of() : Set.copyOf(nativeRiskTags);
        nativeFindingIds = nativeFindingIds == null ? List.of() : List.copyOf(nativeFindingIds);
    }

    public static SenseRequestRiskSignals fromHeaders(
        String nativeRiskTagsHeader,
        String nativeFindingIdsHeader,
        Integer nativeHighestSeverity
    ) {
        Set<String> tags = splitCsv(nativeRiskTagsHeader);
        List<String> findingIds = List.copyOf(splitCsv(nativeFindingIdsHeader));
        Integer normalizedSeverity = normalizeSeverity(nativeHighestSeverity);
        if (tags.isEmpty() && findingIds.isEmpty() && normalizedSeverity == null) {
            return EMPTY;
        }
        return new SenseRequestRiskSignals(tags, findingIds, normalizedSeverity);
    }

    public boolean isEmpty() {
        return nativeRiskTags.isEmpty() && nativeFindingIds.isEmpty() && nativeHighestSeverity == null;
    }

    public List<DetectionEvent> toDetectionEvents(Instant observedAt) {
        if (isEmpty()) {
            return List.of();
        }

        Severity severity = resolveSeverity();
        List<DetectionEvent> events = new ArrayList<>();
        for (String findingId : nativeFindingIds) {
            events.add(new DetectionEvent(
                findingId,
                categoryFor(findingId),
                severity,
                observedAt,
                Map.of(
                    "source", "request_headers",
                    "nativeHighestSeverity", nativeHighestSeverity == null ? "" : nativeHighestSeverity.toString()
                )
            ));
        }

        if (events.isEmpty()) {
            for (String tag : nativeRiskTags) {
                String syntheticId = "signal." + tag.replaceAll("[^a-zA-Z0-9.]+", "_");
                events.add(new DetectionEvent(
                    syntheticId,
                    categoryFor(tag),
                    severity,
                    observedAt,
                    Map.of(
                        "source", "request_headers",
                        "nativeRiskTag", tag
                    )
                ));
            }
        }

        return List.copyOf(events);
    }

    private Severity resolveSeverity() {
        if (nativeHighestSeverity != null) {
            return switch (nativeHighestSeverity) {
                case 4 -> Severity.CRITICAL;
                case 3 -> Severity.HIGH;
                case 2 -> Severity.MEDIUM;
                case 1 -> Severity.LOW;
                default -> Severity.INFO;
            };
        }
        return hasInjectionSignal() ? Severity.HIGH : Severity.LOW;
    }

    private boolean hasInjectionSignal() {
        return nativeFindingIds.stream().anyMatch(SenseRequestRiskSignals::looksLikeInjectionSignal)
            || nativeRiskTags.stream().anyMatch(SenseRequestRiskSignals::looksLikeInjectionSignal);
    }

    private static Category categoryFor(String value) {
        String normalized = value.toLowerCase(Locale.ROOT);
        if (looksLikeInjectionSignal(normalized)) {
            return Category.INJECTION;
        }
        if (normalized.contains("unidbg")) {
            return Category.UNIDBG;
        }
        if (normalized.contains("environment") || normalized.contains("emulator") || normalized.contains("root")) {
            return Category.ENVIRONMENT;
        }
        if (normalized.contains("tamper") || normalized.contains("installer") || normalized.contains("signature")) {
            return Category.TAMPERING;
        }
        return Category.OTHER;
    }

    private static boolean looksLikeInjectionSignal(String value) {
        String normalized = value.toLowerCase(Locale.ROOT);
        return normalized.contains("hook")
            || normalized.contains("frida")
            || normalized.contains("xposed")
            || normalized.contains("substrate")
            || normalized.contains("injection")
            || normalized.contains("zygisk");
    }

    private static Set<String> splitCsv(String header) {
        if (header == null || header.isBlank()) {
            return Set.of();
        }
        Set<String> values = new LinkedHashSet<>();
        for (String value : header.split(",")) {
            String trimmed = value.trim();
            if (!trimmed.isEmpty()) {
                values.add(trimmed);
            }
        }
        return values;
    }

    private static Integer normalizeSeverity(Integer nativeHighestSeverity) {
        if (nativeHighestSeverity == null) {
            return null;
        }
        if (nativeHighestSeverity < 0) {
            return null;
        }
        return Math.min(nativeHighestSeverity, 4);
    }
}
