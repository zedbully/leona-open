/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.ingestion.domain;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.leonasec.server.common.api.BoxId;
import io.leonasec.server.common.api.DetectionEvent;
import io.leonasec.server.common.api.RiskAssessment;
import io.leonasec.server.common.api.SenseResponse;
import io.leonasec.server.common.auth.SdkRequestCanonicalizer;
import io.leonasec.server.common.crypto.AesGcmCipher;
import io.leonasec.server.common.error.ErrorCode;
import io.leonasec.server.common.error.LeonaException;
import io.leonasec.server.common.kafka.ParsedEventEnvelope;
import io.leonasec.server.common.payload.TlvPayload;
import io.leonasec.server.common.risk.RiskScoringEngines;
import io.leonasec.server.common.risk.RiskScoringContext;
import io.leonasec.server.ingestion.infra.KafkaPublisher;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Full ingestion workflow. */
@Service
public class SenseService {

    private static final Duration BOX_ID_TTL = Duration.ofMinutes(15);
    private static final String CONTENT_TYPE = "application/octet-stream";

    private final SessionStore sessions;
    private final BoxIdRepository boxIds;
    private final KafkaPublisher kafka;
    private final ObjectMapper mapper;
    private final MeterRegistry metrics;
    private final AesGcmCipher cipher = new AesGcmCipher();

    public SenseService(SessionStore sessions, BoxIdRepository boxIds,
                        KafkaPublisher kafka, ObjectMapper mapper,
                        MeterRegistry metrics) {
        this.sessions = sessions;
        this.boxIds = boxIds;
        this.kafka = kafka;
        this.mapper = mapper.copy().findAndRegisterModules();
        this.metrics = metrics;
    }

    public Mono<SenseResponse> ingest(String sessionId,
                                      String tenantId,
                                      byte[] encrypted,
                                      String requestId,
                                      long timestamp,
                                      String nonce) {
        return ingest(sessionId, tenantId, encrypted, requestId, timestamp, nonce, SenseRequestRiskSignals.EMPTY);
    }

    public Mono<SenseResponse> ingest(String sessionId,
                                      String tenantId,
                                      byte[] encrypted,
                                      String requestId,
                                      long timestamp,
                                      String nonce,
                                      SenseRequestRiskSignals requestRiskSignals) {
        UUID tenant = parseTenant(tenantId);
        Instant observedAt = Instant.now();

        return sessions.load(sessionId)
            .switchIfEmpty(Mono.error(new LeonaException(
                ErrorCode.LEONA_AUTH_INVALID, "Unknown session id")))
            .publishOn(Schedulers.boundedElastic())
            .map(sessionKey -> decrypt(sessionKey, encrypted, sessionId, requestId, timestamp, nonce))
            .map(plain -> TlvPayload.parseScrambled(plain, observedAt))
            .flatMap(events -> persistAndPublish(tenant, observedAt, events, requestRiskSignals));
    }

    private byte[] decrypt(byte[] key,
                           byte[] encrypted,
                           String sessionId,
                           String requestId,
                           long timestamp,
                           String nonce) {
        try {
            byte[] aad = SdkRequestCanonicalizer.aadBytes(
                "POST",
                "/v1/sense",
                CONTENT_TYPE,
                sessionId,
                requestId,
                timestamp,
                nonce);
            return cipher.open(key, encrypted, aad);
        } catch (Exception e) {
            throw new LeonaException(ErrorCode.LEONA_PAYLOAD_MALFORMED, "Decryption failed", e);
        }
    }

    private Mono<SenseResponse> persistAndPublish(UUID tenant,
                                                 Instant observedAt,
                                                 List<DetectionEvent> events,
                                                 SenseRequestRiskSignals requestRiskSignals) {
        BoxId id = BoxId.generate();
        Instant expiresAt = observedAt.plus(BOX_ID_TTL);
        List<DetectionEvent> effectiveEvents = mergeRiskSignals(events, requestRiskSignals, observedAt);
        ParsedEventEnvelope envelope = new ParsedEventEnvelope(id, tenant, observedAt, expiresAt, effectiveEvents);
        RiskAssessment risk = RiskScoringEngines.active().score(effectiveEvents, RiskScoringContext.ingestion(tenant));
        String eventsJson = writeJson(effectiveEvents);

        return boxIds.store(id, tenant, observedAt, expiresAt, risk, eventsJson)
            .then(kafka.publishParsed(envelope))
            .doOnSuccess(ignored -> {
                metrics.counter("leona.sense.success").increment();
                metrics.counter("leona.sense.risk_level", "risk", risk.level().name()).increment();
            })
            .thenReturn(new SenseResponse(id, expiresAt));
    }

    private List<DetectionEvent> mergeRiskSignals(List<DetectionEvent> events,
                                                  SenseRequestRiskSignals requestRiskSignals,
                                                  Instant observedAt) {
        if (requestRiskSignals == null || requestRiskSignals.isEmpty()) {
            return events;
        }
        List<DetectionEvent> merged = new java.util.ArrayList<>(events);
        merged.addAll(requestRiskSignals.toDetectionEvents(observedAt));
        return List.copyOf(merged);
    }

    private UUID parseTenant(String tenantId) {
        try {
            return UUID.fromString(tenantId);
        } catch (IllegalArgumentException e) {
            throw new LeonaException(ErrorCode.LEONA_AUTH_INVALID, "Tenant header malformed", e);
        }
    }

    private String writeJson(Object value) {
        try {
            return mapper.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new LeonaException(ErrorCode.LEONA_INTERNAL_ERROR, "Failed to serialize verdict cache", e);
        }
    }
}
