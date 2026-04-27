/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.ingestion.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.leonasec.server.common.config.TamperBaselineSchema;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/**
 * Supplies an optional tamper baseline to the SDK during handshake.
 *
 * <p>An operator can provide the baseline either as inline JSON or via a file
 * path. The handshake response echoes the sanitized payload under
 * {@code tamperBaseline}. The Android SDK merges that baseline with any local
 * Builder-supplied policy, preferring the server values when both are present.
 */
@Component
public class TamperBaselineProvider {
    public record SourceInfo(
        String mode,
        String path
    ) {}

    private final Map<String, Object> baseline;
    private final SourceInfo sourceInfo;

    public TamperBaselineProvider(
        @Value("${leona.handshake.tamper-baseline-path:}") String rawPath,
        @Value("${leona.handshake.tamper-baseline-json:}") String rawJson,
        ObjectMapper objectMapper
    ) {
        ResolvedBaseline resolved = resolve(rawPath, rawJson, objectMapper);
        this.baseline = resolved.baseline();
        this.sourceInfo = resolved.sourceInfo();
    }

    public Map<String, Object> current() {
        return baseline;
    }

    public SourceInfo sourceInfo() {
        return sourceInfo;
    }

    private static ResolvedBaseline resolve(String rawPath, String rawJson, ObjectMapper objectMapper) {
        String path = trim(rawPath);
        String json = trim(rawJson);
        if (!path.isEmpty() && !json.isEmpty()) {
            throw new IllegalArgumentException(
                "Configure only one of leona.handshake.tamper-baseline-path or leona.handshake.tamper-baseline-json");
        }
        if (!path.isEmpty()) {
            return new ResolvedBaseline(
                parse(readFile(path), objectMapper),
                new SourceInfo("FILE", path)
            );
        }
        if (!json.isEmpty()) {
            return new ResolvedBaseline(
                parse(json, objectMapper),
                new SourceInfo("INLINE_JSON", null)
            );
        }
        return new ResolvedBaseline(Map.of(), new SourceInfo("NONE", null));
    }

    private static String readFile(String rawPath) {
        Path path = Path.of(rawPath);
        if (!Files.exists(path)) {
            throw new IllegalArgumentException("Handshake tamper baseline file does not exist: " + path);
        }
        try {
            return Files.readString(path, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalArgumentException("Failed to read handshake tamper baseline file: " + path, e);
        }
    }

    private static Map<String, Object> parse(String rawJson, ObjectMapper objectMapper) {
        return TamperBaselineSchema.parseAndSanitize(rawJson, objectMapper);
    }

    private static String trim(String value) {
        return value == null ? "" : value.trim();
    }

    private record ResolvedBaseline(Map<String, Object> baseline, SourceInfo sourceInfo) {}
}
