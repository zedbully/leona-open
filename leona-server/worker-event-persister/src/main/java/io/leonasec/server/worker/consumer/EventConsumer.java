/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.worker.consumer;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.leonasec.server.common.api.RiskAssessment;
import io.leonasec.server.common.kafka.KafkaTopics;
import io.leonasec.server.common.kafka.ParsedEventEnvelope;
import io.leonasec.server.worker.domain.BoxEntity;
import io.leonasec.server.worker.domain.BoxRepository;
import io.leonasec.server.worker.domain.RiskScorer;
import io.leonasec.server.worker.infra.DlqPublisher;
import io.leonasec.server.worker.infra.RedisVerdictCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Main worker loop. For each inbound parsed event envelope:
 *
 * <ol>
 *   <li>Score the events → {@link RiskAssessment}.</li>
 *   <li>Persist to Postgres (idempotent on box_id primary key).</li>
 *   <li>Warm the Redis verdict cache so query-service is fast.</li>
 *   <li>Acknowledge the Kafka offset.</li>
 * </ol>
 *
 * <p>Idempotency: the worker may see a message twice (Kafka at-least-once).
 * Persisting is an upsert on the box_id primary key, and the Redis write
 * is last-write-wins on identical inputs, so duplicates are harmless.
 */
@Component
public class EventConsumer {

    private static final Logger log = LoggerFactory.getLogger(EventConsumer.class);

    private final ObjectMapper mapper;
    private final RiskScorer scorer;
    private final BoxRepository repository;
    private final RedisVerdictCache cache;
    private final DlqPublisher dlq;

    public EventConsumer(ObjectMapper mapper, RiskScorer scorer,
                         BoxRepository repository, RedisVerdictCache cache,
                         DlqPublisher dlq) {
        this.mapper = mapper;
        this.scorer = scorer;
        this.repository = repository;
        this.cache = cache;
        this.dlq = dlq;
    }

    @KafkaListener(topics = KafkaTopics.EVENTS_PARSED, groupId = "leona-event-persister")
    @Transactional
    public void consume(byte[] payload, Acknowledgment ack) {
        try {
            ParsedEventEnvelope envelope = mapper.readValue(payload, ParsedEventEnvelope.class);
            process(envelope);
            ack.acknowledge();
        } catch (Exception e) {
            dlq.publish(payload, e);
            log.error("event persist failed, moving offset anyway to avoid poison loop", e);
            ack.acknowledge();
        }
    }

    private void process(ParsedEventEnvelope envelope) throws Exception {
        RiskAssessment risk = scorer.score(envelope.tenantId(), envelope.events());
        String reasonsJson = mapper.writeValueAsString(risk.reasons());
        String eventsJson = mapper.writeValueAsString(envelope.events());

        BoxEntity entity = new BoxEntity(
            envelope.boxId().value(),
            envelope.tenantId(),
            /* deviceFingerprint = */ null,
            risk.level().name(),
            risk.score(),
            reasonsJson,
            eventsJson,
            envelope.observedAt(),
            envelope.expiresAt()
        );
        repository.save(entity);

        cache.store(
            envelope.boxId().value(),
            risk.level().name(),
            risk.score(),
            reasonsJson,
            eventsJson,
            envelope.observedAt(),
            envelope.expiresAt()
        );

        if (log.isDebugEnabled()) {
            log.debug("persisted boxId={} tenant={} score={} events={}",
                envelope.boxId().value(), envelope.tenantId(),
                risk.score(), envelope.events().size());
        }
    }
}
