/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.ingestion.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.info.Info;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TamperBaselineInfoContributorTest {

    @Test
    void contributesStructuredSummary() {
        TamperBaselineProvider provider = new TamperBaselineProvider(
            "",
            """
            {
              "expectedPackageName": "io.demo",
              "allowedInstallerPackages": ["com.android.vending"],
              "expectedComponentAccessSemanticsSha256": {
                "activity:io.demo.MainActivity": "aa11"
              }
            }
            """,
            new ObjectMapper()
        );
        TamperBaselineInfoContributor contributor = new TamperBaselineInfoContributor(provider);

        Info.Builder builder = new Info.Builder();
        contributor.contribute(builder);
        @SuppressWarnings("unchecked")
        Map<String, Object> detail = (Map<String, Object>) builder.build().getDetails().get("handshakeTamperBaseline");

        assertEquals("INLINE_JSON", detail.get("sourceMode"));
        assertNull(detail.get("sourcePath"));
        assertEquals(true, detail.get("configured"));
        assertEquals(3, detail.get("totalFieldCount"));
        assertEquals(1, detail.get("stringFieldCount"));
        assertEquals(1, detail.get("stringArrayFieldCount"));
        assertEquals(1, detail.get("stringMapFieldCount"));
        assertEquals(
            List.of(
                "allowedInstallerPackages",
                "expectedComponentAccessSemanticsSha256",
                "expectedPackageName"
            ),
            detail.get("configuredFields")
        );
    }

    @Test
    void contributesDisabledSummaryWhenUnset() {
        TamperBaselineProvider provider = new TamperBaselineProvider("", "", new ObjectMapper());
        TamperBaselineInfoContributor contributor = new TamperBaselineInfoContributor(provider);

        Info.Builder builder = new Info.Builder();
        contributor.contribute(builder);
        @SuppressWarnings("unchecked")
        Map<String, Object> detail = (Map<String, Object>) builder.build().getDetails().get("handshakeTamperBaseline");

        assertEquals("NONE", detail.get("sourceMode"));
        assertNull(detail.get("sourcePath"));
        assertEquals(false, detail.get("configured"));
        assertEquals(0, detail.get("totalFieldCount"));
        assertTrue(((List<?>) detail.get("configuredFields")).isEmpty());
    }
}
