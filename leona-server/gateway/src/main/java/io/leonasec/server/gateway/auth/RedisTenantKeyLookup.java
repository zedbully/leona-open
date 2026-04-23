/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.gateway.auth;

import io.leonasec.server.common.auth.TenantKeyLookup;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Redis-backed tenant key resolver.
 *
 * <p>Keys:
 * <ul>
 *   <li>{@code leona:appkey:<appKey>} → hash with {@code tenant}, {@code session_key_b64}</li>
 *   <li>{@code leona:secret:<secretHash>} → hash with {@code tenant}, {@code app_key}</li>
 * </ul>
 *
 * <p>Written by {@code ingestion-service} after a successful handshake (for
 * the app-key flow) and by {@code admin-service} at tenant provisioning
 * time (for the bearer flow).
 */
@Component
public class RedisTenantKeyLookup implements TenantKeyLookup {

    private static final String APP_KEY_PREFIX = "leona:appkey:";
    private static final String SECRET_KEY_PREFIX = "leona:secret:";

    private final ReactiveStringRedisTemplate redis;

    public RedisTenantKeyLookup(ReactiveStringRedisTemplate redis) {
        this.redis = redis;
    }

    @Override
    public Mono<Optional<Resolved>> resolveAppKeyReactive(String appKey) {
        return redis.<String, String>opsForHash()
            .entries(APP_KEY_PREFIX + appKey)
            .collectMap(Map.Entry::getKey, Map.Entry::getValue)
            .map(map -> {
                if (map.isEmpty()) return Optional.<Resolved>empty();
                String tenant = map.get("tenant");
                String keyB64 = map.get("session_key_b64");
                if (tenant == null || keyB64 == null) return Optional.<Resolved>empty();
                return Optional.of(new Resolved(
                    UUID.fromString(tenant),
                    appKey,
                    Base64.getDecoder().decode(keyB64)));
            })
            .defaultIfEmpty(Optional.empty());
    }

    @Override
    public Mono<Optional<Resolved>> resolveSecretKeyReactive(String secretKey) {
        String secretHash = sha256Base64(secretKey);
        return redis.<String, String>opsForHash()
            .entries(SECRET_KEY_PREFIX + secretHash)
            .collectMap(Map.Entry::getKey, Map.Entry::getValue)
            .map(map -> {
                if (map.isEmpty()) return Optional.<Resolved>empty();
                String tenant = map.get("tenant");
                String appKey = map.get("app_key");
                if (tenant == null || appKey == null) return Optional.<Resolved>empty();
                // For bearer flow we sign with the secret itself; it's already
                // strong entropy, no extra derivation needed.
                return Optional.of(new Resolved(
                    UUID.fromString(tenant),
                    appKey,
                    secretKey.getBytes()));
            })
            .defaultIfEmpty(Optional.empty());
    }

    private static String sha256Base64(String input) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
