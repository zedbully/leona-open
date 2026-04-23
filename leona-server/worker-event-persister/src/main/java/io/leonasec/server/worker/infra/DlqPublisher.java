/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.worker.infra;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.leonasec.server.common.kafka.KafkaTopics;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;

/**
 * Publishes failed worker payloads to the dead-letter topic so they can be
 * inspected without blocking the main consumer group.
 */
@Component
public class DlqPublisher {

    private final KafkaTemplate<String, byte[]> kafka;
    private final ObjectMapper mapper;
    private final MeterRegistry metrics;

    public DlqPublisher(KafkaTemplate<String, byte[]> kafka, ObjectMapper mapper,
                        MeterRegistry metrics) {
        this.kafka = kafka;
        this.mapper = mapper;
        this.metrics = metrics;
    }

    public void publish(byte[] originalPayload, Exception error) {
        try {
            FailedPayload failed = new FailedPayload(
                Instant.now(),
                error.getClass().getName(),
                error.getMessage(),
                Base64.getEncoder().encodeToString(originalPayload)
            );
            byte[] body = mapper.writeValueAsBytes(failed);
            kafka.send(KafkaTopics.EVENTS_DLQ, payloadKey(originalPayload), body);
            metrics.counter("leona.worker.dlq.published").increment();
        } catch (Exception ignored) {
            // Best-effort DLQ publishing; caller logs the original failure.
        }
    }

    private String payloadKey(byte[] payload) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(payload);
            String b64 = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
            return "dlq:" + b64.substring(0, Math.min(16, b64.length()));
        } catch (Exception e) {
            return "dlq:unknown";
        }
    }

    private record FailedPayload(
        Instant failedAt,
        String errorType,
        String errorMessage,
        String payloadBase64
    ) {}
}
