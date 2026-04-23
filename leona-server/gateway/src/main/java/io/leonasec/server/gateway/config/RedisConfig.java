/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.gateway.config;

import io.leonasec.server.common.auth.ReactiveReplayGuard;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;

@Configuration
public class RedisConfig {

    @Bean
    public ReactiveReplayGuard replayGuard(ReactiveStringRedisTemplate redis) {
        return new ReactiveReplayGuard(redis);
    }
}
