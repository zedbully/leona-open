/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.admin.domain;

import io.leonasec.server.admin.infra.RedisKeyRegistry;
import io.leonasec.server.common.error.ErrorCode;
import io.leonasec.server.common.error.LeonaException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/**
 * Creates tenants and their initial AppKey / SecretKey pair.
 *
 * <p>AppKeys look like {@code lk_live_app_<24 alphanumerics>}. SecretKeys
 * look like {@code lk_live_sec_<40 alphanumerics>}. The SecretKey is only
 * ever returned once — subsequent retrieval is impossible. SHA-256 of the
 * plaintext lives in Postgres for future rotation-verification.
 */
@Service
public class TenantService {

    private static final SecureRandom RNG = new SecureRandom();
    private static final String ALPHABET =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    private final TenantRepository tenants;
    private final ApiKeyRepository keys;
    private final RedisKeyRegistry registry;

    public TenantService(TenantRepository tenants, ApiKeyRepository keys, RedisKeyRegistry registry) {
        this.tenants = tenants;
        this.keys = keys;
        this.registry = registry;
    }

    @Transactional
    public CreatedTenant createTenant(String name) {
        TenantEntity tenant = tenants.save(new TenantEntity(
            UUID.randomUUID(), name, Instant.now(), false));
        return new CreatedTenant(tenant.getTenantId(), tenant.getName(), createKeyPair(tenant.getTenantId()));
    }

    @Transactional
    public CreatedKeyPair createKeyPair(UUID tenantId) {
        if (tenants.findById(tenantId).isEmpty()) {
            throw new LeonaException(ErrorCode.LEONA_INTERNAL_ERROR, "Tenant not found");
        }
        String appKey = "lk_live_app_" + randomAlphanumeric(24);
        String secretKey = "lk_live_sec_" + randomAlphanumeric(40);
        String hash = sha256Base64(secretKey);

        keys.save(new ApiKeyEntity(appKey, tenantId, hash, Instant.now()));

        // Warm the Redis registry so the gateway and ingestion-service pick
        // up the credential without waiting for a cache refresh cycle.
        registry.registerAppKey(appKey, tenantId, deriveSessionPlaceholder(appKey));
        registry.registerSecretHash(hash, tenantId, appKey);

        return new CreatedKeyPair(appKey, secretKey);
    }

    @Transactional
    public RevokedKeyPair revokeKeyPair(UUID tenantId, String appKey) {
        ApiKeyEntity key = requireKey(tenantId, appKey);
        if (key.getRevokedAt() != null) {
            return new RevokedKeyPair(appKey, key.getRevokedAt(), true);
        }

        Instant revokedAt = Instant.now();
        revokeKeyEntity(key, revokedAt);

        return new RevokedKeyPair(appKey, revokedAt, false);
    }

    @Transactional
    public RotatedKeyPair rotateKeyPair(UUID tenantId, String oldAppKey) {
        ApiKeyEntity oldKey = requireKey(tenantId, oldAppKey);
        if (oldKey.getRevokedAt() != null) {
            throw new LeonaException(ErrorCode.LEONA_AUTH_INVALID, "AppKey already revoked");
        }

        CreatedKeyPair replacement = createKeyPair(tenantId);
        Instant revokedAt = Instant.now();
        revokeKeyEntity(oldKey, revokedAt);

        return new RotatedKeyPair(oldAppKey, revokedAt, replacement);
    }

    private byte[] deriveSessionPlaceholder(String appKey) {
        // Pre-handshake placeholder key so the gateway can resolve the
        // AppKey before the SDK completes its first /v1/handshake. Replaced
        // by the real ECDHE-derived key the first time the SDK handshakes.
        return sha256Bytes(appKey + ":bootstrap");
    }

    private static String randomAlphanumeric(int len) {
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            sb.append(ALPHABET.charAt(RNG.nextInt(ALPHABET.length())));
        }
        return sb.toString();
    }

    private static String sha256Base64(String input) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sha256Bytes(input));
    }

    private static byte[] sha256Bytes(String input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private ApiKeyEntity requireKey(UUID tenantId, String appKey) {
        ApiKeyEntity key = keys.findById(appKey)
            .orElseThrow(() -> new LeonaException(ErrorCode.LEONA_BOX_NOT_FOUND, "AppKey not found"));
        if (!key.getTenantId().equals(tenantId)) {
            throw new LeonaException(ErrorCode.LEONA_BOX_NOT_FOUND, "AppKey does not belong to this tenant");
        }
        return key;
    }

    private void revokeKeyEntity(ApiKeyEntity key, Instant revokedAt) {
        key.revoke(revokedAt);
        keys.save(key);
        registry.revokeAppKey(key.getAppKey());
        registry.revokeSecretHash(key.getSecretHash());
    }

    public record CreatedTenant(UUID tenantId, String name, CreatedKeyPair keyPair) {}
    public record CreatedKeyPair(String appKey, String secretKey) {}
    public record RevokedKeyPair(String appKey, Instant revokedAt, boolean alreadyRevoked) {}
    public record RotatedKeyPair(String oldAppKey, Instant oldKeyRevokedAt, CreatedKeyPair replacement) {}
}
