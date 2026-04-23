/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.ingestion.infra;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.leonasec.server.common.kafka.KafkaTopics;
import io.leonasec.server.common.kafka.ParsedEventEnvelope;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Publishes parsed event envelopes as JSON on {@link KafkaTopics#EVENTS_PARSED}.
 *
 * <p>JSON keeps the downstream worker's dependency surface small — no extra
 * codec beyond Jackson. Protobuf lives on the roadmap once we have 2+
 * worker variants.
 */
@Component
public class KafkaPublisher {

    private final KafkaTemplate<String, byte[]> kafka;
    private final ObjectMapper mapper;

    public KafkaPublisher(KafkaTemplate<String, byte[]> kafka, ObjectMapper mapper) {
        this.kafka = kafka;
        this.mapper = mapper;
    }

    public Mono<Void> publishParsed(ParsedEventEnvelope envelope) {
        byte[] body;
        try {
            body = mapper.writeValueAsBytes(envelope);
        } catch (JsonProcessingException e) {
            return Mono.error(e);
        }
        String key = envelope.boxId().value() + ":" + envelope.tenantId();
        return Mono.fromFuture(
            kafka.send(KafkaTopics.EVENTS_PARSED, key, body).toCompletableFuture()
        ).then();
    }
}
