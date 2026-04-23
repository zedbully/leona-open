/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.query;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Query service: answers customer-backend {@code POST /v1/verdict} requests.
 *
 * <p>Unlike ingestion, this service is MVC (servlet + virtual threads). The
 * hot path is a tight Redis + Postgres round trip that benefits more from
 * thread-per-request than WebFlux's extra indirection.
 */
@SpringBootApplication
public class QueryApplication {
    public static void main(String[] args) {
        SpringApplication.run(QueryApplication.class, args);
    }
}
