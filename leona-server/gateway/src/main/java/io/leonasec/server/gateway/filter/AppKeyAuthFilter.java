/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.gateway.filter;

import io.leonasec.server.common.auth.RequestPrincipal;
import io.leonasec.server.common.auth.TenantKeyLookup;
import io.leonasec.server.common.error.ErrorCode;
import io.leonasec.server.common.error.LeonaException;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.annotation.Order;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Extracts {@code X-Leona-App-Key} (for SDK requests) or
 * {@code Authorization: Bearer} (for customer backend) and sets the
 * resolved tenant context as exchange attributes.
 *
 * <p>Runs before {@link SignatureVerificationFilter}. For SDK traffic the
 * gateway later resolves the real per-session signing key from Redis using
 * {@code X-Leona-Session-Id}; for verdict traffic the bearer secret itself
 * is the signing key and is stored here as an exchange attribute.
 */
@Component
@Order(-10)
public class AppKeyAuthFilter implements GlobalFilter {

    public static final String ATTR_TENANT_ID = "leona.tenant.id";
    public static final String ATTR_APP_KEY = "leona.app.key";
    public static final String ATTR_SIGNING_KEY = "leona.signing.key";
    public static final String ATTR_ROLE = "leona.role";

    private static final List<String> SDK_PATHS = List.of("/v1/sense", "/v1/handshake");
    private static final List<String> VERDICT_PATHS = List.of("/v1/verdict");

    private final TenantKeyLookup lookup;

    public AppKeyAuthFilter(TenantKeyLookup lookup) {
        this.lookup = lookup;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest req = exchange.getRequest();
        String path = req.getPath().value();

        if (SDK_PATHS.stream().anyMatch(path::startsWith)) {
            return authenticateSdk(exchange, chain);
        }
        if (VERDICT_PATHS.stream().anyMatch(path::startsWith)) {
            return authenticateVerdict(exchange, chain);
        }
        return chain.filter(exchange);
    }

    private Mono<Void> authenticateSdk(ServerWebExchange exchange, GatewayFilterChain chain) {
        String appKey = exchange.getRequest().getHeaders().getFirst("X-Leona-App-Key");
        if (appKey == null || appKey.isBlank()) {
            return Mono.error(new LeonaException(ErrorCode.LEONA_AUTH_MISSING, "X-Leona-App-Key missing"));
        }

        return lookup.resolveAppKeyReactive(appKey)
            .flatMap(resolved -> resolved
                .map(r -> {
                    exchange.getAttributes().put(ATTR_TENANT_ID, r.tenantId().toString());
                    exchange.getAttributes().put(ATTR_APP_KEY, r.appKey());
                    exchange.getAttributes().put(ATTR_ROLE, "INGESTION");
                    return chain.filter(propagateHeaders(exchange, r.tenantId().toString(), "INGESTION"));
                })
                .orElseGet(() -> Mono.error(new LeonaException(
                    ErrorCode.LEONA_AUTH_INVALID, "Unknown AppKey"))));
    }

    private Mono<Void> authenticateVerdict(ServerWebExchange exchange, GatewayFilterChain chain) {
        String auth = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (auth == null || !auth.startsWith("Bearer ")) {
            return Mono.error(new LeonaException(ErrorCode.LEONA_AUTH_MISSING, "Bearer token missing"));
        }
        String secret = auth.substring("Bearer ".length()).trim();
        if (secret.isEmpty()) {
            return Mono.error(new LeonaException(ErrorCode.LEONA_AUTH_MISSING));
        }

        return lookup.resolveSecretKeyReactive(secret)
            .flatMap(resolved -> resolved
                .map(r -> {
                    exchange.getAttributes().put(ATTR_TENANT_ID, r.tenantId().toString());
                    exchange.getAttributes().put(ATTR_APP_KEY, r.appKey());
                    exchange.getAttributes().put(ATTR_SIGNING_KEY, r.signingKey());
                    exchange.getAttributes().put(ATTR_ROLE, "VERDICT_CONSUMER");
                    return chain.filter(propagateHeaders(exchange, r.tenantId().toString(), "VERDICT_CONSUMER"));
                })
                .orElseGet(() -> Mono.error(new LeonaException(
                    ErrorCode.LEONA_AUTH_INVALID, "Unknown SecretKey"))));
    }

    private ServerWebExchange propagateHeaders(ServerWebExchange exchange, String tenantId, String role) {
        ServerHttpRequest mutated = exchange.getRequest().mutate()
            .header(RequestPrincipal.HEADER_TENANT, tenantId)
            .header(RequestPrincipal.HEADER_ROLE, role)
            .build();
        return exchange.mutate().request(mutated).build();
    }
}
