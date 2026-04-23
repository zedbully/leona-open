/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.api;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Derives coarse business-facing verdict fields from risk + events.
 *
 * <p>This keeps the hot-path storage schema unchanged while still returning a
 * normalized decision/action pair that SDK integrators can consume directly.
 */
public final class VerdictDecisionPolicy {

    private VerdictDecisionPolicy() {}

    public static String decision(RiskAssessment risk, List<DetectionEvent> events) {
        if (hasInjectionSignal(risk, events)) {
            return risk.level().ordinal() >= RiskAssessment.Level.MEDIUM.ordinal()
                ? "reject"
                : "challenge";
        }
        return switch (risk.level()) {
            case CLEAN, LOW -> "allow";
            case MEDIUM -> "challenge";
            case HIGH, CRITICAL -> "reject";
        };
    }

    public static String action(RiskAssessment risk, List<DetectionEvent> events) {
        if (hasInjectionSignal(risk, events)) {
            return risk.level().ordinal() >= RiskAssessment.Level.MEDIUM.ordinal()
                ? "block"
                : "review";
        }
        return switch (risk.level()) {
            case CLEAN, LOW -> "allow";
            case MEDIUM -> "review";
            case HIGH, CRITICAL -> "block";
        };
    }

    public static Set<String> riskTags(RiskAssessment risk, List<DetectionEvent> events) {
        LinkedHashSet<String> tags = new LinkedHashSet<>();
        if (risk != null && risk.level() != null) {
            tags.add("risk." + risk.level().name().toLowerCase(Locale.ROOT));
        }
        if (events != null) {
            for (DetectionEvent event : events) {
                addTagsForValue(tags, event.id());
                if (event.evidence() != null) {
                    event.evidence().values().forEach(value -> addTagsForValue(tags, value));
                }
            }
        }
        if (risk != null && risk.reasons() != null) {
            risk.reasons().forEach(value -> addTagsForValue(tags, value));
        }
        return Set.copyOf(tags);
    }

    private static boolean hasInjectionSignal(RiskAssessment risk, List<DetectionEvent> events) {
        if (events != null && events.stream().anyMatch(event -> looksLikeInjectionSignal(event.id()))) {
            return true;
        }
        return risk != null
            && risk.reasons() != null
            && risk.reasons().stream().anyMatch(VerdictDecisionPolicy::looksLikeInjectionSignal);
    }

    private static void addTagsForValue(Set<String> tags, String raw) {
        if (raw == null || raw.isBlank()) {
            return;
        }
        String value = raw.toLowerCase(Locale.ROOT);
        if (value.contains("frida")) {
            tags.add("hook.frida");
            tags.add("hook.injection");
        }
        if (value.contains("xposed")) {
            tags.add("hook.xposed");
            tags.add("hook.injection");
        }
        if (value.contains("substrate") || value.contains("zygisk")) {
            tags.add("hook.injection");
        }
        if (value.contains("hook") || value.contains("injection")) {
            tags.add("hook.injection");
        }
        if (value.contains("tamper")) {
            tags.add("tamper.detected");
        }
        if (value.contains("emulator") || value.contains("environment") || value.contains("root")) {
            tags.add("environment.risky");
        }
    }

    private static boolean looksLikeInjectionSignal(String raw) {
        if (raw == null || raw.isBlank()) {
            return false;
        }
        String value = raw.toLowerCase(Locale.ROOT);
        return value.contains("frida")
            || value.contains("xposed")
            || value.contains("substrate")
            || value.contains("zygisk")
            || value.contains("hook")
            || value.contains("injection");
    }
}
