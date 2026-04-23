/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.ingestion.infra;

import io.leonasec.server.ingestion.domain.DeviceBindingStore;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.time.Duration;

@Repository
public class RedisDeviceBindingStore implements DeviceBindingStore {

    private static final String KEY_PREFIX = "leona:device-binding:";

    private final ReactiveStringRedisTemplate redis;

    public RedisDeviceBindingStore(ReactiveStringRedisTemplate redis) {
        this.redis = redis;
    }

    @Override
    public Mono<String> load(String installId) {
        return redis.opsForValue().get(KEY_PREFIX + installId);
    }

    @Override
    public Mono<Void> store(String installId, String publicKey, Duration ttl) {
        return redis.opsForValue().set(KEY_PREFIX + installId, publicKey, ttl).then();
    }
}
