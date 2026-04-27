/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.ingestion.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class TamperBaselineProviderTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void acceptsAndSanitizesExtendedSemanticBaseline() {
        TamperBaselineProvider provider = new TamperBaselineProvider(
            "",
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

        assertEquals("io.demo.app", provider.current().get("expectedPackageName"));
        assertEquals(
            List.of("com.android.vending"),
            provider.current().get("allowedInstallerPackages")
        );
        assertEquals(
            Map.of("activity:io.demo.MainActivity", "AA11"),
            provider.current().get("expectedComponentAccessSemanticsSha256")
        );
        assertEquals(
            Map.of("provider:io.demo.DataProvider", "BB22"),
            provider.current().get("expectedProviderOperationalSemanticsSha256")
        );
        assertEquals("DD44", provider.current().get("expectedResourcesArscSha256"));
        assertEquals("DD55", provider.current().get("expectedResourceInventorySha256"));
        assertEquals("FF66", provider.current().get("expectedSigningCertificateLineageSha256"));
        assertEquals("AA77", provider.current().get("expectedApkSigningBlockSha256"));
        assertEquals(
            Map.of("0x7109871a", "BB88"),
            provider.current().get("expectedApkSigningBlockIdSha256")
        );
        assertEquals(
            Map.of("res/raw/leona.bin", "EE55"),
            provider.current().get("expectedResourceEntrySha256")
        );
        assertEquals(
            Map.of("uses-sdk#targetSdkVersion", "34"),
            provider.current().get("expectedUsesSdkFieldValues")
        );
        assertEquals("CC33", provider.current().get("expectedApplicationSecuritySemanticsSha256"));
        assertEquals(
            Map.of("application#usesCleartextTraffic", "false"),
            provider.current().get("expectedApplicationFieldValues")
        );
    }

    @Test
    void rejectsUnknownBaselineField() {
        IllegalArgumentException error = assertThrows(
            IllegalArgumentException.class,
            () -> new TamperBaselineProvider(
                "",
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
    void rejectsWrongFieldType() {
        IllegalArgumentException error = assertThrows(
            IllegalArgumentException.class,
            () -> new TamperBaselineProvider(
                "",
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
    void loadsBaselineFromFilePath() throws IOException {
        Path baselineFile = Files.createTempFile("leona-handshake-baseline", ".json");
        Files.writeString(
            baselineFile,
            """
            {
              "expectedPackageName": "io.demo.file",
              "expectedApplicationRuntimeSemanticsSha256": "FF66"
            }
            """
        );

        try {
            TamperBaselineProvider provider = new TamperBaselineProvider(
                baselineFile.toString(),
                "",
                objectMapper
            );

            assertEquals("io.demo.file", provider.current().get("expectedPackageName"));
            assertEquals("FF66", provider.current().get("expectedApplicationRuntimeSemanticsSha256"));
            assertEquals("FILE", provider.sourceInfo().mode());
            assertEquals(baselineFile.toString(), provider.sourceInfo().path());
        } finally {
            Files.deleteIfExists(baselineFile);
        }
    }

    @Test
    void rejectsMissingBaselineFile() {
        IllegalArgumentException error = assertThrows(
            IllegalArgumentException.class,
            () -> new TamperBaselineProvider(
                "/tmp/leona-handshake-baseline-missing.json",
                "",
                objectMapper
            )
        );

        assertEquals(
            "Handshake tamper baseline file does not exist: /tmp/leona-handshake-baseline-missing.json",
            error.getMessage()
        );
    }

    @Test
    void rejectsAmbiguousFileAndInlineConfiguration() {
        IllegalArgumentException error = assertThrows(
            IllegalArgumentException.class,
            () -> new TamperBaselineProvider(
                "/tmp/baseline.json",
                "{\"expectedPackageName\":\"io.demo\"}",
                objectMapper
            )
        );

        assertEquals(
            "Configure only one of leona.handshake.tamper-baseline-path or leona.handshake.tamper-baseline-json",
            error.getMessage()
        );
    }
}
