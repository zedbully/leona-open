/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.gateway.config;

import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import reactor.core.publisher.Mono;

@Configuration
public class KeyResolverConfig {

    /**
     * Rate-limit SDK-facing endpoints per AppKey. The AppKey is public so
     * we could rate-limit per-IP instead, but AppKey scales better for our
     * use case — an app with many legitimate users behind one NAT should
     * not be lumped into a single bucket.
     */
    @Bean
    @Primary
    KeyResolver appKeyResolver() {
        return exchange -> {
            String key = exchange.getRequest().getHeaders().getFirst("X-Leona-App-Key");
            return Mono.justOrEmpty(key).defaultIfEmpty("anonymous");
        };
    }

    /**
     * Rate-limit customer-backend queries per tenant bearer. Tenants that
     * need more burst can request a dedicated tier; the default keeps
     * casual abuse contained.
     */
    @Bean
    KeyResolver tenantResolver() {
        return exchange -> {
            String auth = exchange.getRequest().getHeaders().getFirst("Authorization");
            if (auth == null || !auth.startsWith("Bearer ")) {
                return Mono.just("anonymous");
            }
            // Only use a hash prefix so we don't leak the secret into metrics.
            return Mono.just(auth.substring(7, Math.min(auth.length(), 7 + 12)));
        };
    }
}
