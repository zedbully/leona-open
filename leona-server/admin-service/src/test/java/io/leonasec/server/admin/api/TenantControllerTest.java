/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.admin.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.leonasec.server.admin.domain.TenantService;
import io.leonasec.server.common.util.RequestIds;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Instant;
import java.util.UUID;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class TenantControllerTest {

    private final TenantService service = mock(TenantService.class);
    private final ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(new TenantController(service)).build();
    }

    @Test
    void createTenantReturnsCreated() throws Exception {
        UUID tenantId = UUID.randomUUID();
        TenantService.CreatedTenant created = new TenantService.CreatedTenant(
            tenantId,
            "demo",
            new TenantService.CreatedKeyPair("lk_live_app_123", "lk_live_sec_456")
        );
        when(service.createTenant("demo")).thenReturn(created);

        mockMvc.perform(post("/v1/admin/tenants")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsBytes(new TenantController.CreateTenantRequest("demo"))))
            .andExpect(status().isCreated())
            .andExpect(header().exists(RequestIds.HEADER))
            .andExpect(jsonPath("$.tenantId").value(tenantId.toString()))
            .andExpect(jsonPath("$.name").value("demo"))
            .andExpect(jsonPath("$.keyPair.appKey").value("lk_live_app_123"));
    }

    @Test
    void createKeysReturnsCreated() throws Exception {
        UUID tenantId = UUID.randomUUID();
        when(service.createKeyPair(tenantId)).thenReturn(
            new TenantService.CreatedKeyPair("lk_live_app_123", "lk_live_sec_456")
        );

        mockMvc.perform(post("/v1/admin/tenants/{tenantId}/keys", tenantId))
            .andExpect(status().isCreated())
            .andExpect(header().exists(RequestIds.HEADER))
            .andExpect(jsonPath("$.appKey").value("lk_live_app_123"))
            .andExpect(jsonPath("$.secretKey").value("lk_live_sec_456"));
    }

    @Test
    void revokeKeyReturnsOk() throws Exception {
        UUID tenantId = UUID.randomUUID();
        Instant revokedAt = Instant.parse("2026-04-21T12:00:00Z");
        when(service.revokeKeyPair(tenantId, "lk_live_app_old")).thenReturn(
            new TenantService.RevokedKeyPair("lk_live_app_old", revokedAt, false)
        );

        mockMvc.perform(delete("/v1/admin/tenants/{tenantId}/keys/{appKey}", tenantId, "lk_live_app_old"))
            .andExpect(status().isOk())
            .andExpect(header().exists(RequestIds.HEADER))
            .andExpect(jsonPath("$.appKey").value("lk_live_app_old"))
            .andExpect(jsonPath("$.alreadyRevoked").value(false));
    }

    @Test
    void rotateKeyReturnsOk() throws Exception {
        UUID tenantId = UUID.randomUUID();
        Instant revokedAt = Instant.parse("2026-04-21T12:00:00Z");
        when(service.rotateKeyPair(tenantId, "lk_live_app_old")).thenReturn(
            new TenantService.RotatedKeyPair(
                "lk_live_app_old",
                revokedAt,
                new TenantService.CreatedKeyPair("lk_live_app_new", "lk_live_sec_new")
            )
        );

        mockMvc.perform(post("/v1/admin/tenants/{tenantId}/keys/{appKey}/rotate", tenantId, "lk_live_app_old"))
            .andExpect(status().isOk())
            .andExpect(header().exists(RequestIds.HEADER))
            .andExpect(jsonPath("$.oldAppKey").value("lk_live_app_old"))
            .andExpect(jsonPath("$.replacement.appKey").value("lk_live_app_new"));
    }
}
