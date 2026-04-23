/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.query.infra;

import io.leonasec.server.common.api.BoxId;
import io.leonasec.server.query.domain.BoxIdClaim;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisScriptingCommands;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RedisBoxIdClaimTest {

    @Test
    void mapsClaimedStatusFromRedisBytes() {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        RedisConnection connection = mock(RedisConnection.class);
        RedisScriptingCommands scripting = mock(RedisScriptingCommands.class);
        when(connection.scriptingCommands()).thenReturn(scripting);
        when(scripting.eval(any(byte[].class), eq(org.springframework.data.redis.connection.ReturnType.STATUS), eq(1), any(byte[][].class)))
            .thenReturn("CLAIMED".getBytes(StandardCharsets.UTF_8));
        doAnswer(invocation -> {
            @SuppressWarnings("unchecked")
            RedisCallback<Object> callback = invocation.getArgument(0);
            return callback.doInRedis(connection);
        }).when(redis).execute(any(RedisCallback.class), eq(true));

        RedisBoxIdClaim claim = new RedisBoxIdClaim(redis);
        BoxId boxId = BoxId.generate();
        UUID tenantId = UUID.randomUUID();
        Instant before = Instant.now();

        BoxIdClaim.Outcome outcome = claim.claim(boxId, tenantId);

        assertEquals(BoxIdClaim.Status.CLAIMED, outcome.status());
        assertNotNull(outcome.usedAt());
        assertFalse(outcome.usedAt().isBefore(before));
        verify(scripting).eval(any(byte[].class), eq(org.springframework.data.redis.connection.ReturnType.STATUS), eq(1), any(byte[][].class));
    }

    @Test
    void mapsAlreadyUsedStatus() {
        RedisBoxIdClaim claim = new RedisBoxIdClaim(redisReturning("ALREADY_USED"));

        BoxIdClaim.Outcome outcome = claim.claim(BoxId.generate(), UUID.randomUUID());

        assertEquals(BoxIdClaim.Status.ALREADY_USED, outcome.status());
    }

    @Test
    void mapsExpiredStatus() {
        RedisBoxIdClaim claim = new RedisBoxIdClaim(redisReturning("EXPIRED"));

        BoxIdClaim.Outcome outcome = claim.claim(BoxId.generate(), UUID.randomUUID());

        assertEquals(BoxIdClaim.Status.EXPIRED, outcome.status());
    }

    @Test
    void mapsWrongTenantStatus() {
        RedisBoxIdClaim claim = new RedisBoxIdClaim(redisReturning("WRONG_TENANT"));

        BoxIdClaim.Outcome outcome = claim.claim(BoxId.generate(), UUID.randomUUID());

        assertEquals(BoxIdClaim.Status.WRONG_TENANT, outcome.status());
    }

    @Test
    void mapsNullOrUnknownStatusToNotFound() {
        RedisBoxIdClaim nullClaim = new RedisBoxIdClaim(redisReturning(null));
        RedisBoxIdClaim unknownClaim = new RedisBoxIdClaim(redisReturning("SOMETHING_ELSE"));

        assertEquals(BoxIdClaim.Status.NOT_FOUND, nullClaim.claim(BoxId.generate(), UUID.randomUUID()).status());
        assertEquals(BoxIdClaim.Status.NOT_FOUND, unknownClaim.claim(BoxId.generate(), UUID.randomUUID()).status());
    }

    private StringRedisTemplate redisReturning(Object result) {
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        doAnswer(invocation -> result).when(redis).execute(any(RedisCallback.class), eq(true));
        return redis;
    }
}
