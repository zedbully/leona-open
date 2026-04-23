/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.worker;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Worker service: consumes {@code leona.events.raw} from Kafka, parses the
 * TLV blob, computes a risk score, persists to PostgreSQL + ClickHouse.
 *
 * <p>In v0.1.0-alpha.1 this is a skeleton — the consumer wiring, TLV
 * parser, and risk scorer ship in the next iteration. The skeleton exists
 * so Docker Compose and K8s manifests can deploy the shape of the system
 * today.
 */
@SpringBootApplication
public class WorkerApplication {
    public static void main(String[] args) {
        SpringApplication.run(WorkerApplication.class, args);
    }
}
