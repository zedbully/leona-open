/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Public entry point for the Leona backend.
 *
 * <p>Responsibilities:
 * <ul>
 *   <li>TLS termination (past Cloudflare).</li>
 *   <li>AppKey / SecretKey authentication.</li>
 *   <li>Request signing verification (timestamp + nonce + HMAC).</li>
 *   <li>Per-tenant and per-IP rate limiting.</li>
 *   <li>Circuit breaking in front of each downstream service.</li>
 *   <li>Propagating {@code X-Leona-Tenant} to downstream services.</li>
 * </ul>
 *
 * Once the gateway authenticates, downstream services trust the
 * {@code X-Leona-Tenant} header absolutely — that trust is earned by the
 * {@code NetworkPolicy} in Kubernetes that forbids direct traffic to
 * downstream services.
 */
@SpringBootApplication
public class GatewayApplication {
    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }
}
