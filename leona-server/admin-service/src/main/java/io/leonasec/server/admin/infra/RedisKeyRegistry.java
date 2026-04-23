/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.admin.infra;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.Map;
import java.util.UUID;

/**
 * Writes the key-to-tenant mapping into the same Redis structures the
 * gateway reads from.
 *
 * <p>Note: this couples the admin service to the gateway's Redis schema.
 * If the schema evolves, update both sides simultaneously and bump a
 * version stamp in the key names.
 */
@Component
public class RedisKeyRegistry {

    private static final String APP_KEY_PREFIX = "leona:appkey:";
    private static final String SECRET_KEY_PREFIX = "leona:secret:";

    private final StringRedisTemplate redis;

    public RedisKeyRegistry(StringRedisTemplate redis) {
        this.redis = redis;
    }

    public void registerAppKey(String appKey, UUID tenantId, byte[] sessionKey) {
        redis.opsForHash().putAll(APP_KEY_PREFIX + appKey, Map.of(
            "tenant", tenantId.toString(),
            "session_key_b64", Base64.getEncoder().encodeToString(sessionKey)
        ));
    }

    public void registerSecretHash(String secretHash, UUID tenantId, String appKey) {
        redis.opsForHash().putAll(SECRET_KEY_PREFIX + secretHash, Map.of(
            "tenant", tenantId.toString(),
            "app_key", appKey
        ));
    }

    public void revokeAppKey(String appKey) {
        redis.delete(APP_KEY_PREFIX + appKey);
    }

    public void revokeSecretHash(String secretHash) {
        redis.delete(SECRET_KEY_PREFIX + secretHash);
    }
}
