/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TamperBaselineSchemaTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void parseAndSanitizeAcceptsExtendedSemanticBaseline() {
        Map<String, Object> baseline = TamperBaselineSchema.parseAndSanitize(
            """
            {
              "expectedPackageName": " io.demo.app ",
              "allowedInstallerPackages": [" com.android.vending ", " ", "com.android.vending"],
              "expectedComponentAccessSemanticsSha256": {
                "activity:io.demo.MainActivity": " AA11 "
              },
              "expectedProviderOperationalSemanticsSha256": {
                "provider:io.demo.DataProvider": " BB22 "
              },
              "expectedResourcesArscSha256": " DD44 ",
              "expectedResourceInventorySha256": " DD55 ",
              "expectedSigningCertificateLineageSha256": " FF66 ",
              "expectedApkSigningBlockSha256": " AA77 ",
              "expectedApkSigningBlockIdSha256": {
                "0x7109871a": " BB88 "
              },
              "expectedResourceEntrySha256": {
                "res/raw/leona.bin": " EE55 "
              },
              "expectedUsesSdkFieldValues": {
                "uses-sdk#targetSdkVersion": " 34 "
              },
              "expectedApplicationSecuritySemanticsSha256": " CC33 ",
              "expectedApplicationFieldValues": {
                "application#usesCleartextTraffic": " false "
              }
            }
            """,
            objectMapper
        );

        assertEquals("io.demo.app", baseline.get("expectedPackageName"));
        assertEquals(List.of("com.android.vending"), baseline.get("allowedInstallerPackages"));
        assertEquals(
            Map.of("activity:io.demo.MainActivity", "AA11"),
            baseline.get("expectedComponentAccessSemanticsSha256")
        );
        assertEquals(
            Map.of("provider:io.demo.DataProvider", "BB22"),
            baseline.get("expectedProviderOperationalSemanticsSha256")
        );
        assertEquals("DD44", baseline.get("expectedResourcesArscSha256"));
        assertEquals("DD55", baseline.get("expectedResourceInventorySha256"));
        assertEquals("FF66", baseline.get("expectedSigningCertificateLineageSha256"));
        assertEquals("AA77", baseline.get("expectedApkSigningBlockSha256"));
        assertEquals(
            Map.of("0x7109871a", "BB88"),
            baseline.get("expectedApkSigningBlockIdSha256")
        );
        assertEquals(
            Map.of("res/raw/leona.bin", "EE55"),
            baseline.get("expectedResourceEntrySha256")
        );
        assertEquals(
            Map.of("uses-sdk#targetSdkVersion", "34"),
            baseline.get("expectedUsesSdkFieldValues")
        );
        assertEquals("CC33", baseline.get("expectedApplicationSecuritySemanticsSha256"));
        assertEquals(
            Map.of("application#usesCleartextTraffic", "false"),
            baseline.get("expectedApplicationFieldValues")
        );
    }

    @Test
    void parseAndSanitizeRejectsUnknownBaselineField() {
        IllegalArgumentException error = assertThrows(
            IllegalArgumentException.class,
            () -> TamperBaselineSchema.parseAndSanitize(
                "{\"expectedPackageName\":\"io.demo\",\"unexpectedField\":\"boom\"}",
                objectMapper
            )
        );

        assertEquals(
            "Invalid leona.handshake.tamper-baseline-json: unsupported field 'unexpectedField'",
            error.getMessage()
        );
    }

    @Test
    void parseAndSanitizeRejectsWrongFieldType() {
        IllegalArgumentException error = assertThrows(
            IllegalArgumentException.class,
            () -> TamperBaselineSchema.parseAndSanitize(
                "{\"expectedComponentAccessSemanticsSha256\":\"not-an-object\"}",
                objectMapper
            )
        );

        assertEquals(
            "Invalid leona.handshake.tamper-baseline-json: field 'expectedComponentAccessSemanticsSha256' must be object<string,string> but was string",
            error.getMessage()
        );
    }

    @Test
    void summarizeReturnsFieldShapeInventory() {
        TamperBaselineSchema.Summary summary = TamperBaselineSchema.summarize(
            Map.of(
                "expectedPackageName", "io.demo",
                "allowedInstallerPackages", List.of("com.android.vending"),
                "expectedComponentAccessSemanticsSha256", Map.of("activity:io.demo.MainActivity", "aa11")
            )
        );

        assertTrue(summary.configured());
        assertEquals(3, summary.totalFieldCount());
        assertEquals(1, summary.stringFieldCount());
        assertEquals(1, summary.stringArrayFieldCount());
        assertEquals(1, summary.stringMapFieldCount());
        assertEquals(
            List.of(
                "allowedInstallerPackages",
                "expectedComponentAccessSemanticsSha256",
                "expectedPackageName"
            ),
            summary.configuredFields()
        );
    }

    @Test
    void exampleContainsCurrentSemanticFields() {
        Map<String, Object> example = TamperBaselineSchema.example();

        assertTrue(example.containsKey("expectedComponentAccessSemanticsSha256"));
        assertTrue(example.containsKey("expectedComponentOperationalSemanticsSha256"));
        assertTrue(example.containsKey("expectedProviderAccessSemanticsSha256"));
        assertTrue(example.containsKey("expectedProviderOperationalSemanticsSha256"));
        assertTrue(example.containsKey("expectedApplicationSecuritySemanticsSha256"));
        assertTrue(example.containsKey("expectedApplicationRuntimeSemanticsSha256"));
        assertTrue(example.containsKey("expectedSigningCertificateLineageSha256"));
        assertTrue(example.containsKey("expectedApkSigningBlockSha256"));
        assertTrue(example.containsKey("expectedApkSigningBlockIdSha256"));
        assertTrue(example.containsKey("expectedResourcesArscSha256"));
        assertTrue(example.containsKey("expectedResourceInventorySha256"));
        assertTrue(example.containsKey("expectedResourceEntrySha256"));
    }
}
