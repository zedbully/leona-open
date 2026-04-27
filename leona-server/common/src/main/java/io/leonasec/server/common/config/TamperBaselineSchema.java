/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Shared allowlist + type schema for handshake tamper baselines.
 */
public final class TamperBaselineSchema {

    public enum ValueKind {
        STRING,
        STRING_ARRAY,
        STRING_MAP
    }

    public record Summary(
        boolean configured,
        int totalFieldCount,
        int stringFieldCount,
        int stringArrayFieldCount,
        int stringMapFieldCount,
        List<String> configuredFields
    ) {}

    private static final Set<String> STRING_FIELDS = Set.of(
        "expectedPackageName",
        "expectedSigningCertificateLineageSha256",
        "expectedApkSigningBlockSha256",
        "expectedApkSha256",
        "expectedManifestEntrySha256",
        "expectedResourcesArscSha256",
        "expectedResourceInventorySha256",
        "expectedSplitInventorySha256",
        "expectedDynamicFeatureSplitSha256",
        "expectedDynamicFeatureSplitNameSha256",
        "expectedConfigSplitAxisSha256",
        "expectedConfigSplitNameSha256",
        "expectedConfigSplitAbiSha256",
        "expectedConfigSplitLocaleSha256",
        "expectedConfigSplitDensitySha256",
        "expectedRequestedPermissionsSha256",
        "expectedRequestedPermissionSemanticsSha256",
        "expectedDeclaredPermissionSemanticsSha256",
        "expectedUsesFeatureSha256",
        "expectedUsesFeatureNameSha256",
        "expectedUsesFeatureRequiredSha256",
        "expectedUsesFeatureGlEsVersionSha256",
        "expectedUsesSdkSha256",
        "expectedUsesSdkMinSha256",
        "expectedUsesSdkTargetSha256",
        "expectedUsesSdkMaxSha256",
        "expectedSupportsScreensSha256",
        "expectedSupportsScreensSmallScreensSha256",
        "expectedSupportsScreensNormalScreensSha256",
        "expectedSupportsScreensLargeScreensSha256",
        "expectedSupportsScreensXlargeScreensSha256",
        "expectedSupportsScreensResizeableSha256",
        "expectedSupportsScreensAnyDensitySha256",
        "expectedSupportsScreensRequiresSmallestWidthDpSha256",
        "expectedSupportsScreensCompatibleWidthLimitDpSha256",
        "expectedSupportsScreensLargestWidthLimitDpSha256",
        "expectedCompatibleScreensSha256",
        "expectedCompatibleScreensScreenSizeSha256",
        "expectedCompatibleScreensScreenDensitySha256",
        "expectedUsesLibrarySha256",
        "expectedUsesLibraryNameSha256",
        "expectedUsesLibraryRequiredSha256",
        "expectedUsesLibraryOnlySha256",
        "expectedUsesLibraryOnlyNameSha256",
        "expectedUsesLibraryOnlyRequiredSha256",
        "expectedUsesNativeLibrarySha256",
        "expectedUsesNativeLibraryNameSha256",
        "expectedUsesNativeLibraryRequiredSha256",
        "expectedQueriesSha256",
        "expectedQueriesPackageSha256",
        "expectedQueriesPackageNameSha256",
        "expectedQueriesPackageSemanticsSha256",
        "expectedQueriesProviderSha256",
        "expectedQueriesProviderAuthoritySha256",
        "expectedQueriesProviderSemanticsSha256",
        "expectedQueriesIntentSha256",
        "expectedQueriesIntentActionSha256",
        "expectedQueriesIntentCategorySha256",
        "expectedQueriesIntentDataSha256",
        "expectedQueriesIntentDataSchemeSha256",
        "expectedQueriesIntentDataAuthoritySha256",
        "expectedQueriesIntentDataPathSha256",
        "expectedQueriesIntentDataMimeTypeSha256",
        "expectedQueriesIntentSemanticsSha256",
        "expectedApplicationSemanticsSha256",
        "expectedApplicationSecuritySemanticsSha256",
        "expectedApplicationRuntimeSemanticsSha256"
    );

    private static final Set<String> STRING_ARRAY_FIELDS = Set.of(
        "allowedInstallerPackages",
        "allowedSigningCertSha256"
    );

    private static final Set<String> STRING_MAP_FIELDS = Set.of(
        "expectedNativeLibSha256",
        "expectedApkSigningBlockIdSha256",
        "expectedResourceEntrySha256",
        "expectedDexSha256",
        "expectedDexSectionSha256",
        "expectedDexMethodSha256",
        "expectedSplitApkSha256",
        "expectedElfSectionSha256",
        "expectedElfExportSymbolSha256",
        "expectedElfExportGraphSha256",
        "expectedDeclaredPermissionFieldValues",
        "expectedComponentSignatureSha256",
        "expectedComponentAccessSemanticsSha256",
        "expectedComponentOperationalSemanticsSha256",
        "expectedComponentFieldValues",
        "expectedProviderUriPermissionPatternsSha256",
        "expectedProviderPathPermissionsSha256",
        "expectedProviderAuthoritySetSha256",
        "expectedProviderSemanticsSha256",
        "expectedProviderAccessSemanticsSha256",
        "expectedProviderOperationalSemanticsSha256",
        "expectedIntentFilterSha256",
        "expectedIntentFilterActionSha256",
        "expectedIntentFilterCategorySha256",
        "expectedIntentFilterDataSha256",
        "expectedIntentFilterDataSchemeSha256",
        "expectedIntentFilterDataAuthoritySha256",
        "expectedIntentFilterDataPathSha256",
        "expectedIntentFilterDataMimeTypeSha256",
        "expectedIntentFilterSemanticsSha256",
        "expectedGrantUriPermissionSha256",
        "expectedGrantUriPermissionSemanticsSha256",
        "expectedUsesFeatureFieldValues",
        "expectedUsesSdkFieldValues",
        "expectedUsesLibraryFieldValues",
        "expectedUsesNativeLibraryFieldValues",
        "expectedApplicationFieldValues",
        "expectedMetaDataType",
        "expectedMetaDataValueSha256",
        "expectedManifestMetaDataEntrySha256",
        "expectedManifestMetaDataSemanticsSha256",
        "expectedMetaData"
    );

    private TamperBaselineSchema() {}

    public static Map<String, Object> parseAndSanitize(String rawJson, ObjectMapper objectMapper) {
        if (rawJson == null || rawJson.isBlank()) {
            return Map.of();
        }
        try {
            JsonNode root = objectMapper.readTree(rawJson);
            if (!(root instanceof ObjectNode objectNode)) {
                throw new IllegalArgumentException("leona.handshake.tamper-baseline-json must be a JSON object");
            }
            return sanitizeObject(objectNode);
        } catch (IOException e) {
            throw new IllegalArgumentException("Invalid leona.handshake.tamper-baseline-json", e);
        }
    }

    public static Summary summarize(Map<String, Object> baseline) {
        if (baseline == null || baseline.isEmpty()) {
            return new Summary(false, 0, 0, 0, 0, List.of());
        }
        int stringFieldCount = 0;
        int stringArrayFieldCount = 0;
        int stringMapFieldCount = 0;
        TreeSet<String> configuredFields = new TreeSet<>();
        for (Map.Entry<String, Object> entry : baseline.entrySet()) {
            configuredFields.add(entry.getKey());
            ValueKind kind = kindOf(entry.getKey());
            if (kind == ValueKind.STRING) {
                stringFieldCount++;
            } else if (kind == ValueKind.STRING_ARRAY) {
                stringArrayFieldCount++;
            } else if (kind == ValueKind.STRING_MAP) {
                stringMapFieldCount++;
            }
        }
        return new Summary(
            true,
            baseline.size(),
            stringFieldCount,
            stringArrayFieldCount,
            stringMapFieldCount,
            List.copyOf(configuredFields)
        );
    }

    public static Map<String, Object> example() {
        Map<String, Object> example = new LinkedHashMap<>();
        example.put("expectedPackageName", "io.leonasec.demo");
        example.put("allowedInstallerPackages", List.of("com.android.vending"));
        example.put("expectedSigningCertificateLineageSha256", "5d63b8e5f91dc96fa51d326f8ad7c03f7b4e70ef5b6a0375648a8c2b98d22a0c");
        example.put("expectedApkSigningBlockSha256", "2d08a0fd24e94d46e983fbd85d6c9b2aa60eb7b39a2b3e23c4fa2e6171d01911");
        example.put("expectedApkSigningBlockIdSha256", Map.of(
            "0x7109871a", "975f8d9290632568c4bd5ee144b2d30b50f484b44c840c20a53240dbbb6bcb24"
        ));
        example.put("expectedResourcesArscSha256", "9f3f8f25b58a8746c3f76b50ebfdd8dd2c5e7dbf5c12f5cfd388c7d0a0d7ef0a");
        example.put("expectedResourceInventorySha256", "a019ad820f742c8137f76f23c06ecb2ed8e2518742b3d1ea1118e0a1336e1a3c");
        example.put("expectedResourceEntrySha256", Map.of(
            "res/raw/leona.bin", "7a2e4c1e88e2c8bb5d0aa7e1132871c9e9a8a4bc2a2d047a5c20d102ce19d6b8"
        ));
        example.put("expectedComponentAccessSemanticsSha256", Map.of(
            "activity:io.leonasec.demo.MainActivity", "4f0bc7f0d7c0d2a30b2777e8b6d95f8be7f42ab42b1f0d3f6878c4c3e4a9d101"
        ));
        example.put("expectedComponentOperationalSemanticsSha256", Map.of(
            "service:io.leonasec.demo.SyncService", "b2cb47d84d7110b4bdb5d2cfddf6a5ec5cb99d91f8d34bb13f1c95f2bf39f211"
        ));
        example.put("expectedProviderAccessSemanticsSha256", Map.of(
            "provider:io.leonasec.demo.DataProvider", "6dfd5fe9fbc7d385fd13f3520d6c0d7a0cb89d5d4f4f4f58d84bd9e1a93fd301"
        ));
        example.put("expectedProviderOperationalSemanticsSha256", Map.of(
            "provider:io.leonasec.demo.DataProvider", "19fca6b84bfd7a3c1d711245b56be529a3b84bb5e03a0cbb341e0cd89f7904a2"
        ));
        example.put("expectedApplicationSecuritySemanticsSha256", "0d9cbef84d1a56bb0dc4c7a29ee5edc1224cf991f2fb0d0577e1a94507c5cc10");
        example.put("expectedApplicationRuntimeSemanticsSha256", "e6710aef8c6b4d28531fb3f87c2185e598c45b25479c94c1c5c8a8d146f70f20");
        example.put("expectedApplicationFieldValues", Map.of(
            "application#usesCleartextTraffic", "false"
        ));
        return Map.copyOf(example);
    }

    private static Map<String, Object> sanitizeObject(ObjectNode root) {
        Map<String, Object> sanitized = new LinkedHashMap<>();
        root.properties().forEach(entry -> {
            String key = trim(entry.getKey());
            if (key.isEmpty()) {
                return;
            }
            JsonNode value = entry.getValue();
            if (STRING_FIELDS.contains(key)) {
                String normalized = requireString(key, value);
                if (!normalized.isEmpty()) {
                    sanitized.put(key, normalized);
                }
                return;
            }
            if (STRING_ARRAY_FIELDS.contains(key)) {
                List<String> normalized = requireStringArray(key, value);
                if (!normalized.isEmpty()) {
                    sanitized.put(key, normalized);
                }
                return;
            }
            if (STRING_MAP_FIELDS.contains(key)) {
                Map<String, String> normalized = requireStringMap(key, value);
                if (!normalized.isEmpty()) {
                    sanitized.put(key, normalized);
                }
                return;
            }
            throw new IllegalArgumentException(
                "Invalid leona.handshake.tamper-baseline-json: unsupported field '" + key + "'");
        });
        return Map.copyOf(sanitized);
    }

    private static String requireString(String key, JsonNode node) {
        if (!node.isTextual()) {
            throw new IllegalArgumentException(typeError(key, "string", node));
        }
        return trim(node.asText());
    }

    private static List<String> requireStringArray(String key, JsonNode node) {
        if (!node.isArray()) {
            throw new IllegalArgumentException(typeError(key, "array<string>", node));
        }
        Set<String> values = new LinkedHashSet<>();
        for (JsonNode item : node) {
            if (!item.isTextual()) {
                throw new IllegalArgumentException(typeError(key, "array<string>", item));
            }
            String normalized = trim(item.asText());
            if (!normalized.isEmpty()) {
                values.add(normalized);
            }
        }
        return List.copyOf(values);
    }

    private static Map<String, String> requireStringMap(String key, JsonNode node) {
        if (!(node instanceof ObjectNode objectNode)) {
            throw new IllegalArgumentException(typeError(key, "object<string,string>", node));
        }
        Map<String, String> values = new LinkedHashMap<>();
        objectNode.properties().forEach(entry -> {
            String entryKey = trim(entry.getKey());
            if (entryKey.isEmpty()) {
                return;
            }
            JsonNode entryValue = entry.getValue();
            if (!entryValue.isTextual()) {
                throw new IllegalArgumentException(typeError(key, "object<string,string>", entryValue));
            }
            String normalized = trim(entryValue.asText());
            if (!normalized.isEmpty()) {
                values.put(entryKey, normalized);
            }
        });
        return Map.copyOf(values);
    }

    private static ValueKind kindOf(String key) {
        if (STRING_FIELDS.contains(key)) {
            return ValueKind.STRING;
        }
        if (STRING_ARRAY_FIELDS.contains(key)) {
            return ValueKind.STRING_ARRAY;
        }
        if (STRING_MAP_FIELDS.contains(key)) {
            return ValueKind.STRING_MAP;
        }
        throw new IllegalArgumentException("Unsupported tamper baseline field: " + key);
    }

    private static String trim(String value) {
        return value == null ? "" : value.trim();
    }

    private static String typeError(String key, String expected, JsonNode node) {
        return "Invalid leona.handshake.tamper-baseline-json: field '" + key + "' must be "
            + expected + " but was " + node.getNodeType().name().toLowerCase();
    }
}
