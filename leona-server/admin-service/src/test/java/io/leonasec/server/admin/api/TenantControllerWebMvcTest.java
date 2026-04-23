/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.admin.api;

import io.leonasec.server.admin.config.SecurityConfig;
import io.leonasec.server.admin.domain.TenantService;
import io.leonasec.server.common.error.ErrorCode;
import io.leonasec.server.common.error.LeonaException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = TenantController.class)
@AutoConfigureMockMvc(addFilters = true)
@ActiveProfiles("local")
@Import({SecurityConfig.class, GlobalExceptionHandler.class})
class TenantControllerWebMvcTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private TenantService service;

    @Test
    void localProfileAllowsCreateWithoutAuth() throws Exception {
        UUID tenantId = UUID.randomUUID();
        when(service.createTenant("demo")).thenReturn(new TenantService.CreatedTenant(
            tenantId,
            "demo",
            new TenantService.CreatedKeyPair("lk_live_app_demo", "lk_live_sec_demo")
        ));

        mockMvc.perform(post("/v1/admin/tenants")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"demo\"}"))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.tenantId").value(tenantId.toString()))
            .andExpect(jsonPath("$.keyPair.appKey").value("lk_live_app_demo"));
    }

    @Test
    void translatesDomainErrorsToApiErrors() throws Exception {
        UUID tenantId = UUID.randomUUID();
        when(service.createKeyPair(tenantId)).thenThrow(new LeonaException(ErrorCode.LEONA_INTERNAL_ERROR, "Tenant not found"));

        mockMvc.perform(post("/v1/admin/tenants/{tenantId}/keys", tenantId))
            .andExpect(status().isInternalServerError())
            .andExpect(jsonPath("$.code").value("LEONA_INTERNAL_ERROR"))
            .andExpect(jsonPath("$.message").value("Tenant not found"));
    }
}
