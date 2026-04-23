/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.query.infra;

import io.leonasec.server.common.api.BoxId;
import io.leonasec.server.query.domain.BoxIdClaim;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Repository;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Redis-backed single-use claim. Uses a Lua script to atomically:
 *
 * <ol>
 *   <li>Read the hash stored under {@code leona:box:<id>}.</li>
 *   <li>If missing → {@code NOT_FOUND}.</li>
 *   <li>If tenant mismatch → {@code WRONG_TENANT}.</li>
 *   <li>If {@code expires_at} is in the past → {@code EXPIRED}.</li>
 *   <li>If {@code used_at} already set → {@code ALREADY_USED}.</li>
 *   <li>Otherwise stamp {@code used_at = now} and return {@code CLAIMED}.</li>
 * </ol>
 *
 * <p>Current implementation calls Redis {@code EVAL} directly for each
 * claim. If this becomes a measurable hot-path cost, promote it to
 * {@code SCRIPT LOAD + EVALSHA} in a later hardening pass.
 */
@Repository
public class RedisBoxIdClaim implements BoxIdClaim {

    private static final String KEY_PREFIX = "leona:box:";
    private static final String LUA = """
        local h = redis.call('HGETALL', KEYS[1])
        if #h == 0 then return 'NOT_FOUND' end
        local t = {}; for i = 1, #h, 2 do t[h[i]] = h[i+1] end
        if t['tenant'] ~= ARGV[1] then return 'WRONG_TENANT' end
        if t['expires_at_epoch_ms'] ~= nil and t['expires_at_epoch_ms'] ~= '' and tonumber(t['expires_at_epoch_ms']) <= tonumber(ARGV[3]) then return 'EXPIRED' end
        if t['used_at'] ~= nil and t['used_at'] ~= '' then return 'ALREADY_USED' end
        redis.call('HSET', KEYS[1], 'used_at', ARGV[2])
        return 'CLAIMED'
        """;

    private final StringRedisTemplate redis;

    public RedisBoxIdClaim(StringRedisTemplate redis) {
        this.redis = redis;
    }

    @Override
    public Outcome claim(BoxId id, UUID tenantId) {
        String key = KEY_PREFIX + id.value();
        Instant now = Instant.now();

        Object raw = redis.execute(
            (connection) -> connection.scriptingCommands().eval(
                LUA.getBytes(),
                org.springframework.data.redis.connection.ReturnType.STATUS,
                1,
                key.getBytes(),
                tenantId.toString().getBytes(),
                now.toString().getBytes(),
                String.valueOf(now.toEpochMilli()).getBytes()
            ),
            true
        );

        String status = normalizeStatus(raw);
        return switch (status) {
            case "CLAIMED" -> Outcome.claimed(now);
            case "ALREADY_USED" -> Outcome.alreadyUsed();
            case "EXPIRED" -> Outcome.expired();
            case "WRONG_TENANT" -> Outcome.wrongTenant();
            case "NOT_FOUND" -> Outcome.notFound();
            default -> Outcome.notFound();
        };
    }

    private String normalizeStatus(Object raw) {
        if (raw == null) return "NOT_FOUND";
        if (raw instanceof byte[] bytes) return new String(bytes, StandardCharsets.UTF_8);
        return raw.toString();
    }

    /** Unused but kept so IDE navigation to {@code List / Map} imports stays valid. */
    @SuppressWarnings("unused")
    private void _keepImports() { List.of(); Map.of(); }
}
