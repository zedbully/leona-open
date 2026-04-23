/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.gateway.filter;

import io.leonasec.server.common.auth.RequestPrincipal;
import io.leonasec.server.common.auth.TenantKeyLookup;
import io.leonasec.server.common.error.LeonaException;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AppKeyAuthFilterTest {

    @Test
    void knownSdkAppKeyAddsTenantHeader() {
        TenantKeyLookup lookup = mock(TenantKeyLookup.class);
        AppKeyAuthFilter filter = new AppKeyAuthFilter(lookup);
        UUID tenantId = UUID.randomUUID();
        when(lookup.resolveAppKeyReactive("lk_live_app_test"))
            .thenReturn(Mono.just(Optional.of(
                new TenantKeyLookup.Resolved(tenantId, "lk_live_app_test", new byte[] {1, 2, 3})
            )));

        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.post("/v1/handshake")
                .header("X-Leona-App-Key", "lk_live_app_test")
                .build()
        );
        AtomicReference<ServerWebExchange> captured = new AtomicReference<>();
        GatewayFilterChain chain = ex -> {
            captured.set(ex);
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();

        ServerWebExchange next = captured.get();
        assertEquals(tenantId.toString(), next.getRequest().getHeaders().getFirst(RequestPrincipal.HEADER_TENANT));
        assertEquals("INGESTION", next.getRequest().getHeaders().getFirst(RequestPrincipal.HEADER_ROLE));
    }

    @Test
    void unknownSdkAppKeyFailsAuthentication() {
        TenantKeyLookup lookup = mock(TenantKeyLookup.class);
        AppKeyAuthFilter filter = new AppKeyAuthFilter(lookup);
        when(lookup.resolveAppKeyReactive("lk_live_app_missing"))
            .thenReturn(Mono.just(Optional.empty()));

        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.post("/v1/handshake")
                .header("X-Leona-App-Key", "lk_live_app_missing")
                .build()
        );
        GatewayFilterChain chain = ex -> Mono.empty();

        assertThrows(LeonaException.class, () -> filter.filter(exchange, chain).block());
    }
}
