/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.query.api;

import io.leonasec.server.common.api.BoxId;
import io.leonasec.server.common.api.Category;
import io.leonasec.server.common.api.DetectionEvent;
import io.leonasec.server.common.api.RiskAssessment;
import io.leonasec.server.common.api.Severity;
import io.leonasec.server.common.api.VerdictResponse;
import io.leonasec.server.common.error.ErrorCode;
import io.leonasec.server.common.error.LeonaException;
import io.leonasec.server.query.domain.VerdictService;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = VerdictController.class)
@Import({GlobalExceptionHandler.class, VerdictControllerWebMvcTest.TestConfig.class})
class VerdictControllerWebMvcTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private VerdictService service;

    @Test
    void acceptsStringBoxIdBodyAndReturnsSignedVerdict() throws Exception {
        UUID tenantId = UUID.randomUUID();
        BoxId boxId = BoxId.generate();
        Instant usedAt = Instant.parse("2026-04-21T12:00:00Z");
        VerdictResponse response = new VerdictResponse(
            boxId,
            null,
            new RiskAssessment(RiskAssessment.Level.MEDIUM, 42, List.of("rule.demo")),
            List.of(new DetectionEvent(
                "injection.frida.known_library",
                Category.INJECTION,
                Severity.HIGH,
                Instant.parse("2026-04-21T11:58:00Z"),
                Map.of("source", "request_headers")
            )),
            Instant.parse("2026-04-21T11:59:00Z"),
            usedAt
        );
        when(service.consume(tenantId, boxId)).thenReturn(response);

        mockMvc.perform(post("/v1/verdict")
                .header("X-Leona-Tenant", tenantId)
                .header("Authorization", "Bearer lk_live_sec_demo")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"boxId\":\"" + boxId.value() + "\"}"))
            .andExpect(status().isOk())
            .andExpect(header().exists("X-Leona-Verdict-Generated-At"))
            .andExpect(header().exists("X-Leona-Verdict-Signature"))
            .andExpect(header().string("X-Leona-Verdict-Signature-Alg", "HMAC-SHA256"))
            .andExpect(jsonPath("$.boxId").value(boxId.value()))
            .andExpect(jsonPath("$.decision").value("reject"))
            .andExpect(jsonPath("$.action").value("block"))
            .andExpect(jsonPath("$.risk.level").value("MEDIUM"))
            .andExpect(jsonPath("$.risk.score").value(42))
            .andExpect(jsonPath("$.riskLevel").value("MEDIUM"))
            .andExpect(jsonPath("$.riskScore").value(42))
            .andExpect(jsonPath("$.riskTags").isArray());
    }

    @Test
    void translatesLeonaExceptionToExpectedHttpStatus() throws Exception {
        UUID tenantId = UUID.randomUUID();
        BoxId boxId = BoxId.generate();
        when(service.consume(tenantId, boxId)).thenThrow(new LeonaException(ErrorCode.LEONA_BOX_ALREADY_USED));

        mockMvc.perform(post("/v1/verdict")
                .header("X-Leona-Tenant", tenantId)
                .header("Authorization", "Bearer lk_live_sec_demo")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"boxId\":\"" + boxId.value() + "\"}"))
            .andExpect(status().isGone())
            .andExpect(jsonPath("$.code").value("LEONA_BOX_ALREADY_USED"));
    }

    @TestConfiguration
    static class TestConfig {
        @Bean
        SimpleMeterRegistry meterRegistry() {
            return new SimpleMeterRegistry();
        }
    }
}
