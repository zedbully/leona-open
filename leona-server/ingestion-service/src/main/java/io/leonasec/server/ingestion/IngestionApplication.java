/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.ingestion;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Ingestion service: accepts encrypted payloads from the SDK, mints BoxIds,
 * and hands off to Kafka for persistence and analytics.
 *
 * <p>Reactive (WebFlux) because the hot path is network-bound and we prefer
 * handling many concurrent SDK uploads per instance over thread-per-request.
 */
@SpringBootApplication
public class IngestionApplication {
    public static void main(String[] args) {
        SpringApplication.run(IngestionApplication.class, args);
    }
}
