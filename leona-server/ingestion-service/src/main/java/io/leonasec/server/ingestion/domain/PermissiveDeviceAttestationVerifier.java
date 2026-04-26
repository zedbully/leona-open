/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.ingestion.domain;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.leonasec.server.common.api.HandshakeRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

@Component
public class PermissiveDeviceAttestationVerifier implements DeviceAttestationVerifier {

    private static final Set<String> DEVICE_VERDICTS_BY_STRENGTH = Set.of(
        "MEETS_BASIC_INTEGRITY",
        "MEETS_DEVICE_INTEGRITY",
        "MEETS_STRONG_INTEGRITY"
    );

    private final boolean requireAttestation;
    private final boolean trustJwsPayloadClaims;
    private final String minimumDeviceVerdict;
    private final Duration maxAge;
    private final ObjectMapper mapper;
    private final OemAttestationVerifiers.OemAttestationVerifier oemAttestationVerifier;

    public PermissiveDeviceAttestationVerifier(
        @Value("${leona.handshake.attestation.required:true}") boolean requireAttestation,
        @Value("${leona.handshake.attestation.trust-jws-payload-claims:false}") boolean trustJwsPayloadClaims,
        @Value("${leona.handshake.attestation.minimum-device-verdict:MEETS_DEVICE_INTEGRITY}") String minimumDeviceVerdict,
        @Value("${leona.handshake.attestation.max-age-seconds:300}") long maxAgeSeconds,
        ObjectMapper mapper
    ) {
        this.requireAttestation = requireAttestation;
        this.trustJwsPayloadClaims = trustJwsPayloadClaims;
        this.minimumDeviceVerdict = normalize(minimumDeviceVerdict);
        this.maxAge = Duration.ofSeconds(Math.max(30L, maxAgeSeconds));
        this.mapper = mapper.copy().findAndRegisterModules();
        this.oemAttestationVerifier = OemAttestationVerifiers.active();
    }

    @Override
    public Result verify(HandshakeRequest request) {
        HandshakeRequest.DeviceBinding binding = request.deviceBinding();
        if (binding == null) {
            return Result.rejected("binding_missing", null, "BINDING_MISSING", false);
        }
        if (binding.attestationToken() == null || binding.attestationToken().isBlank()
            || binding.attestationFormat() == null || binding.attestationFormat().isBlank()) {
            return requireAttestation
                ? Result.rejected("attestation_missing", null, "ATTESTATION_MISSING", false)
                : Result.accepted("binding-without-attestation", null, null, null);
        }

        String format = normalizeFormat(binding.attestationFormat());
        return switch (format) {
            case "play_integrity" -> verifyPlayIntegrity(request, binding);
            case "oem_attestation" -> oemAttestationVerifier.verify(request);
            default -> Result.rejected("attestation_format_unsupported", format, "ATTESTATION_FORMAT_UNSUPPORTED", false);
        };
    }

    private Result verifyPlayIntegrity(HandshakeRequest request, HandshakeRequest.DeviceBinding binding) {
        JsonNode claims = parseClaims(binding.attestationToken());
        if (claims == null || claims.isMissingNode()) {
            return Result.rejected("attestation_parse_failed", "play_integrity", "PLAY_INTEGRITY_PARSE_FAILED", false);
        }

        String expectedChallenge = handshakeChallenge(request);
        String actualChallenge = firstText(
            claims,
            "requestDetails.requestHash",
            "requestDetails.nonce",
            "nonce",
            "requestHash"
        );
        if (actualChallenge == null || !expectedChallenge.equals(actualChallenge)) {
            return Result.rejected("attestation_challenge_mismatch", "play_integrity", "PLAY_INTEGRITY_CHALLENGE_MISMATCH", false);
        }

        Long timestampMillis = firstLong(
            claims,
            "requestDetails.timestampMillis",
            "timestampMillis"
        );
        if (timestampMillis == null || timestampMillis <= 0L) {
            return Result.rejected("attestation_timestamp_missing", "play_integrity", "PLAY_INTEGRITY_TIMESTAMP_MISSING", false);
        }
        Instant issuedAt = Instant.ofEpochMilli(timestampMillis);
        Instant now = Instant.now();
        if (issuedAt.isAfter(now.plusSeconds(60))) {
            return Result.rejected("attestation_clock_skew", "play_integrity", "PLAY_INTEGRITY_CLOCK_SKEW", true);
        }
        if (issuedAt.isBefore(now.minus(maxAge))) {
            return Result.rejected("attestation_stale", "play_integrity", "PLAY_INTEGRITY_STALE", true);
        }

        String appVerdict = firstText(
            claims,
            "appIntegrity.appRecognitionVerdict",
            "appRecognitionVerdict"
        );
        if (!"PLAY_RECOGNIZED".equals(normalize(appVerdict))) {
            return Result.rejected("attestation_app_unrecognized", "play_integrity", "PLAY_INTEGRITY_APP_UNRECOGNIZED", false);
        }

        Set<String> deviceVerdicts = firstArrayValues(
            claims,
            "deviceIntegrity.deviceRecognitionVerdict",
            "deviceRecognitionVerdict"
        );
        if (!meetsMinimumDeviceVerdict(deviceVerdicts)) {
            return Result.rejected("attestation_device_untrusted", "play_integrity", "PLAY_INTEGRITY_DEVICE_UNTRUSTED", false);
        }

        return Result.accepted("play_integrity/" + normalizeDeviceVerdictStatus(deviceVerdicts), "play_integrity", "PLAY_INTEGRITY_VERIFIED", false);
    }

    private JsonNode parseClaims(String token) {
        try {
            String trimmed = token == null ? "" : token.trim();
            if (trimmed.isEmpty()) {
                return null;
            }
            if (trimmed.startsWith("{")) {
                return mapper.readTree(trimmed);
            }
            String[] parts = trimmed.split("\\.");
            if (parts.length == 3 && trustJwsPayloadClaims) {
                byte[] decoded = Base64.getUrlDecoder().decode(parts[1]);
                return mapper.readTree(decoded);
            }
            return null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private boolean meetsMinimumDeviceVerdict(Set<String> deviceVerdicts) {
        if (deviceVerdicts.isEmpty()) {
            return false;
        }
        int minRank = verdictRank(minimumDeviceVerdict);
        int bestRank = deviceVerdicts.stream()
            .mapToInt(PermissiveDeviceAttestationVerifier::verdictRank)
            .max()
            .orElse(-1);
        return bestRank >= minRank;
    }

    private String normalizeDeviceVerdictStatus(Set<String> deviceVerdicts) {
        return deviceVerdicts.stream()
            .max((left, right) -> Integer.compare(verdictRank(left), verdictRank(right)))
            .map(PermissiveDeviceAttestationVerifier::normalize)
            .orElse("unknown");
    }

    private static int verdictRank(String verdict) {
        String normalized = normalize(verdict);
        return switch (normalized) {
            case "MEETS_STRONG_INTEGRITY" -> 3;
            case "MEETS_DEVICE_INTEGRITY" -> 2;
            case "MEETS_BASIC_INTEGRITY" -> 1;
            default -> -1;
        };
    }

    private static String handshakeChallenge(HandshakeRequest request) {
        return sha256Hex(
            (request.installId() + "\n" + request.sdkVersion() + "\n" + request.clientPublicKey())
                .getBytes(StandardCharsets.UTF_8)
        );
    }

    private static String sha256Hex(byte[] bytes) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
            StringBuilder builder = new StringBuilder(digest.length * 2);
            for (byte value : digest) {
                builder.append(Character.forDigit((value >> 4) & 0xF, 16));
                builder.append(Character.forDigit(value & 0xF, 16));
            }
            return builder.toString();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static String firstText(JsonNode root, String... paths) {
        for (String path : paths) {
            JsonNode node = nodeAt(root, path);
            if (node != null && !node.isMissingNode() && !node.isNull()) {
                String value = node.asText(null);
                if (value != null && !value.isBlank()) {
                    return value;
                }
            }
        }
        return null;
    }

    private static Long firstLong(JsonNode root, String... paths) {
        for (String path : paths) {
            JsonNode node = nodeAt(root, path);
            if (node != null && !node.isMissingNode() && !node.isNull()) {
                if (node.isNumber()) {
                    return node.longValue();
                }
                if (node.isTextual()) {
                    try {
                        return Long.parseLong(node.asText().trim());
                    } catch (NumberFormatException ignored) {
                        // continue
                    }
                }
            }
        }
        return null;
    }

    private static Set<String> firstArrayValues(JsonNode root, String... paths) {
        for (String path : paths) {
            JsonNode node = nodeAt(root, path);
            if (node == null || node.isMissingNode() || node.isNull()) {
                continue;
            }
            LinkedHashSet<String> values = new LinkedHashSet<>();
            if (node.isArray()) {
                node.forEach(item -> {
                    String value = item.asText(null);
                    if (value != null && !value.isBlank()) {
                        values.add(normalize(value));
                    }
                });
            } else if (node.isTextual()) {
                values.add(normalize(node.asText()));
            }
            if (!values.isEmpty()) {
                return values;
            }
        }
        return Set.of();
    }

    private static JsonNode nodeAt(JsonNode root, String path) {
        JsonNode current = root;
        for (String segment : path.split("\\.")) {
            if (current == null) {
                return null;
            }
            current = current.path(segment);
        }
        return current;
    }

    private static String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private static String normalizeFormat(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }
}
