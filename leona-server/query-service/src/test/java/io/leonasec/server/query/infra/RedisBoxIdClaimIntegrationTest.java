/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.query.infra;

import io.leonasec.server.common.api.BoxId;
import io.leonasec.server.query.domain.BoxIdClaim;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class RedisBoxIdClaimIntegrationTest {

    private static final String EXTERNAL_REDIS_HOST_ENV = "LEONA_TEST_REDIS_HOST";
    private static final String EXTERNAL_REDIS_PORT_ENV = "LEONA_TEST_REDIS_PORT";

    static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
        .withExposedPorts(6379);

    private static String redisHost;
    private static int redisPort;
    private static boolean useExternalRedis;

    private LettuceConnectionFactory connectionFactory;
    private StringRedisTemplate redis;
    private RedisBoxIdClaim claim;

    @BeforeAll
    static void startRedis() {
        String externalHost = System.getenv(EXTERNAL_REDIS_HOST_ENV);
        String externalPort = System.getenv(EXTERNAL_REDIS_PORT_ENV);
        if (externalHost != null && !externalHost.isBlank()
            && externalPort != null && !externalPort.isBlank()) {
            redisHost = externalHost;
            redisPort = Integer.parseInt(externalPort);
            useExternalRedis = true;
            return;
        }

        assumeTrue(DockerClientFactory.instance().isDockerAvailable(),
            "Docker Desktop/Testcontainers is not available");
        REDIS.start();
        redisHost = REDIS.getHost();
        redisPort = REDIS.getMappedPort(6379);
    }

    @AfterAll
    static void stopRedis() {
        if (!useExternalRedis) {
            REDIS.stop();
        }
    }

    @BeforeEach
    void setUp() {
        connectionFactory = new LettuceConnectionFactory(redisHost, redisPort);
        connectionFactory.afterPropertiesSet();

        redis = new StringRedisTemplate(connectionFactory);
        redis.afterPropertiesSet();
        redis.getConnectionFactory().getConnection().serverCommands().flushAll();

        claim = new RedisBoxIdClaim(redis);
    }

    @AfterEach
    void tearDown() {
        if (connectionFactory != null) {
            connectionFactory.destroy();
        }
    }

    @Test
    void claimsFreshBoxAndWritesUsedAt() {
        BoxId boxId = BoxId.generate();
        UUID tenantId = UUID.randomUUID();
        seedBox(boxId, tenantId, Instant.now().plusSeconds(300), null);

        BoxIdClaim.Outcome outcome = claim.claim(boxId, tenantId);

        assertEquals(BoxIdClaim.Status.CLAIMED, outcome.status());
        assertNotNull(outcome.usedAt());
        String usedAt = (String) redis.opsForHash().get(key(boxId), "used_at");
        assertNotNull(usedAt);
    }

    @Test
    void returnsAlreadyUsedWithoutOverwritingUsedAt() {
        BoxId boxId = BoxId.generate();
        UUID tenantId = UUID.randomUUID();
        String firstUsedAt = "2026-04-21T12:00:00Z";
        seedBox(boxId, tenantId, Instant.now().plusSeconds(300), firstUsedAt);

        BoxIdClaim.Outcome outcome = claim.claim(boxId, tenantId);

        assertEquals(BoxIdClaim.Status.ALREADY_USED, outcome.status());
        assertEquals(firstUsedAt, redis.opsForHash().get(key(boxId), "used_at"));
    }

    @Test
    void returnsWrongTenantWithoutWritingUsedAt() {
        BoxId boxId = BoxId.generate();
        UUID ownerTenant = UUID.randomUUID();
        UUID callerTenant = UUID.randomUUID();
        seedBox(boxId, ownerTenant, Instant.now().plusSeconds(300), null);

        BoxIdClaim.Outcome outcome = claim.claim(boxId, callerTenant);

        assertEquals(BoxIdClaim.Status.WRONG_TENANT, outcome.status());
        assertFalse(redis.opsForHash().hasKey(key(boxId), "used_at"));
    }

    @Test
    void returnsExpiredWhenEpochMillisIsInThePast() {
        BoxId boxId = BoxId.generate();
        UUID tenantId = UUID.randomUUID();
        seedBox(boxId, tenantId, Instant.now().minusSeconds(5), null);

        BoxIdClaim.Outcome outcome = claim.claim(boxId, tenantId);

        assertEquals(BoxIdClaim.Status.EXPIRED, outcome.status());
        assertFalse(redis.opsForHash().hasKey(key(boxId), "used_at"));
    }

    @Test
    void returnsNotFoundForMissingKey() {
        BoxIdClaim.Outcome outcome = claim.claim(BoxId.generate(), UUID.randomUUID());

        assertEquals(BoxIdClaim.Status.NOT_FOUND, outcome.status());
    }

    private void seedBox(BoxId boxId, UUID tenantId, Instant expiresAt, String usedAt) {
        Map<String, String> fields = new java.util.HashMap<>();
        fields.put("tenant", tenantId.toString());
        fields.put("expires_at_epoch_ms", String.valueOf(expiresAt.toEpochMilli()));
        if (usedAt != null) {
            fields.put("used_at", usedAt);
        }
        redis.opsForHash().putAll(key(boxId), fields);
    }

    private String key(BoxId boxId) {
        return "leona:box:" + boxId.value();
    }
}
