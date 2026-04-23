/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.admin.domain;

import io.leonasec.server.admin.infra.RedisKeyRegistry;
import io.leonasec.server.common.error.ErrorCode;
import io.leonasec.server.common.error.LeonaException;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TenantServiceTest {

    @Test
    void createKeyPairPersistsAndWarmsRedis() {
        TenantRepository tenants = mock(TenantRepository.class);
        ApiKeyRepository keys = mock(ApiKeyRepository.class);
        RedisKeyRegistry registry = mock(RedisKeyRegistry.class);
        TenantService service = new TenantService(tenants, keys, registry);

        UUID tenantId = UUID.randomUUID();
        when(tenants.findById(tenantId)).thenReturn(Optional.of(
            new TenantEntity(tenantId, "demo", Instant.now(), false)
        ));
        when(keys.save(any(ApiKeyEntity.class))).thenAnswer(invocation -> invocation.getArgument(0));

        TenantService.CreatedKeyPair pair = service.createKeyPair(tenantId);

        assertTrue(pair.appKey().startsWith("lk_live_app_"));
        assertTrue(pair.secretKey().startsWith("lk_live_sec_"));

        ArgumentCaptor<ApiKeyEntity> savedKey = ArgumentCaptor.forClass(ApiKeyEntity.class);
        verify(keys).save(savedKey.capture());
        assertEquals(pair.appKey(), savedKey.getValue().getAppKey());
        assertEquals(tenantId, savedKey.getValue().getTenantId());
        assertNotEquals(pair.secretKey(), savedKey.getValue().getSecretHash());

        verify(registry).registerAppKey(eq(pair.appKey()), eq(tenantId), any(byte[].class));
        verify(registry).registerSecretHash(eq(savedKey.getValue().getSecretHash()), eq(tenantId), eq(pair.appKey()));
    }

    @Test
    void revokeKeyPairIsIdempotent() {
        TenantRepository tenants = mock(TenantRepository.class);
        ApiKeyRepository keys = mock(ApiKeyRepository.class);
        RedisKeyRegistry registry = mock(RedisKeyRegistry.class);
        TenantService service = new TenantService(tenants, keys, registry);

        UUID tenantId = UUID.randomUUID();
        ApiKeyEntity key = new ApiKeyEntity("lk_live_app_existing", tenantId, "secret-hash", Instant.now());
        Instant revokedAt = Instant.parse("2026-04-21T12:00:00Z");
        key.revoke(revokedAt);
        when(keys.findById(key.getAppKey())).thenReturn(Optional.of(key));

        TenantService.RevokedKeyPair revoked = service.revokeKeyPair(tenantId, key.getAppKey());

        assertTrue(revoked.alreadyRevoked());
        assertEquals(revokedAt, revoked.revokedAt());
        verify(keys, never()).save(any(ApiKeyEntity.class));
        verify(registry, never()).revokeAppKey(anyString());
        verify(registry, never()).revokeSecretHash(anyString());
    }

    @Test
    void rotateKeyPairCreatesReplacementAndRevokesOldKey() {
        TenantRepository tenants = mock(TenantRepository.class);
        ApiKeyRepository keys = mock(ApiKeyRepository.class);
        RedisKeyRegistry registry = mock(RedisKeyRegistry.class);
        TenantService service = new TenantService(tenants, keys, registry);

        UUID tenantId = UUID.randomUUID();
        ApiKeyEntity oldKey = new ApiKeyEntity("lk_live_app_old", tenantId, "old-secret-hash", Instant.now());

        when(tenants.findById(tenantId)).thenReturn(Optional.of(
            new TenantEntity(tenantId, "demo", Instant.now(), false)
        ));
        when(keys.findById(oldKey.getAppKey())).thenReturn(Optional.of(oldKey));
        when(keys.save(any(ApiKeyEntity.class))).thenAnswer(invocation -> invocation.getArgument(0));

        TenantService.RotatedKeyPair rotated = service.rotateKeyPair(tenantId, oldKey.getAppKey());

        assertEquals(oldKey.getAppKey(), rotated.oldAppKey());
        assertNotNull(rotated.oldKeyRevokedAt());
        assertEquals(rotated.oldKeyRevokedAt(), oldKey.getRevokedAt());
        assertTrue(rotated.replacement().appKey().startsWith("lk_live_app_"));
        assertTrue(rotated.replacement().secretKey().startsWith("lk_live_sec_"));
        assertNotEquals(oldKey.getAppKey(), rotated.replacement().appKey());

        verify(registry).revokeAppKey(oldKey.getAppKey());
        verify(registry).revokeSecretHash(oldKey.getSecretHash());
        verify(registry).registerAppKey(eq(rotated.replacement().appKey()), eq(tenantId), any(byte[].class));
    }

    @Test
    void rotateKeyPairRejectsAlreadyRevokedKey() {
        TenantRepository tenants = mock(TenantRepository.class);
        ApiKeyRepository keys = mock(ApiKeyRepository.class);
        RedisKeyRegistry registry = mock(RedisKeyRegistry.class);
        TenantService service = new TenantService(tenants, keys, registry);

        UUID tenantId = UUID.randomUUID();
        ApiKeyEntity key = new ApiKeyEntity("lk_live_app_old", tenantId, "old-secret-hash", Instant.now());
        key.revoke(Instant.parse("2026-04-21T12:00:00Z"));
        when(keys.findById(key.getAppKey())).thenReturn(Optional.of(key));

        LeonaException error = assertThrows(LeonaException.class,
            () -> service.rotateKeyPair(tenantId, key.getAppKey()));

        assertEquals(ErrorCode.LEONA_AUTH_INVALID, error.code());
        verify(keys, never()).save(any(ApiKeyEntity.class));
        verify(registry, never()).registerAppKey(anyString(), eq(tenantId), any(byte[].class));
        verify(registry, never()).revokeAppKey(anyString());
    }

    @Test
    void createKeyPairRejectsUnknownTenant() {
        TenantRepository tenants = mock(TenantRepository.class);
        ApiKeyRepository keys = mock(ApiKeyRepository.class);
        RedisKeyRegistry registry = mock(RedisKeyRegistry.class);
        TenantService service = new TenantService(tenants, keys, registry);

        UUID tenantId = UUID.randomUUID();
        when(tenants.findById(tenantId)).thenReturn(Optional.empty());

        LeonaException error = assertThrows(LeonaException.class, () -> service.createKeyPair(tenantId));

        assertEquals(ErrorCode.LEONA_INTERNAL_ERROR, error.code());
        assertFalse(error.getMessage().isBlank());
        verify(keys, never()).save(any(ApiKeyEntity.class));
    }
}
