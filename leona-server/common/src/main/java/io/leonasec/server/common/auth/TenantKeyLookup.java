/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.auth;

import reactor.core.publisher.Mono;

import java.util.Optional;
import java.util.UUID;

/**
 * Resolves a public AppKey or Bearer secret to the tenant it belongs to and
 * the signing key used to verify the request signature.
 *
 * <p>Two flavours because the gateway is reactive (WebFlux) and everything
 * downstream is servlet (MVC + virtual threads). The blocking variant is
 * fine on the downstream side because virtual threads absorb the block.
 */
public interface TenantKeyLookup {

    /** Resolve an AppKey (public, from SDK). */
    Mono<Optional<Resolved>> resolveAppKeyReactive(String appKey);

    /** Resolve a tenant SecretKey (from customer backend). */
    Mono<Optional<Resolved>> resolveSecretKeyReactive(String secretKey);

    /** Blocking helper for virtual-thread callers. */
    default Optional<Resolved> resolveAppKey(String appKey) {
        return resolveAppKeyReactive(appKey).blockOptional().orElse(Optional.empty());
    }

    /** Blocking helper for virtual-thread callers. */
    default Optional<Resolved> resolveSecretKey(String secretKey) {
        return resolveSecretKeyReactive(secretKey).blockOptional().orElse(Optional.empty());
    }

    /**
     * The result of a successful lookup. {@code signingKey} is the material
     * fed to the HMAC verifier; for SDK requests it's derived from the ECDHE
     * session established at {@code /v1/handshake}, for customer backends
     * it's the SecretKey itself.
     */
    record Resolved(UUID tenantId, String appKey, byte[] signingKey) {}
}
