/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.admin;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Admin service: tenant + key management and dashboard backend.
 *
 * <p>Low traffic, OAuth2-authenticated endpoints. Skeleton only in
 * v0.1.0-alpha.1 — the full surface lands once we have a first tenant.
 */
@SpringBootApplication
public class AdminApplication {
    public static void main(String[] args) {
        SpringApplication.run(AdminApplication.class, args);
    }
}
