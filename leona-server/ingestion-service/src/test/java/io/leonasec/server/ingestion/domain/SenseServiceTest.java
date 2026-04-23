/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.ingestion.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.leonasec.server.common.api.SenseResponse;
import io.leonasec.server.common.auth.SdkRequestCanonicalizer;
import io.leonasec.server.common.crypto.AesGcmCipher;
import io.leonasec.server.common.error.LeonaException;
import io.leonasec.server.ingestion.infra.KafkaPublisher;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SenseServiceTest {

    @Test
    void ingestAcceptsPayloadEncryptedWithCanonicalAssociatedData() throws Exception {
        SessionStore sessions = mock(SessionStore.class);
        BoxIdRepository boxIds = mock(BoxIdRepository.class);
        KafkaPublisher kafka = mock(KafkaPublisher.class);
        SenseService service = new SenseService(
            sessions, boxIds, kafka, new ObjectMapper(), new SimpleMeterRegistry());

        String sessionId = "01HSESSIONTEST00000000000000";
        String tenantId = UUID.randomUUID().toString();
        String requestId = "req-123";
        long timestamp = System.currentTimeMillis();
        String nonce = "nonce-abc";
        byte[] sessionKey = fixedKey();
        byte[] plain = scrambledPayloadWithSingleEvent();
        byte[] encrypted = new AesGcmCipher().seal(
            sessionKey,
            plain,
            SdkRequestCanonicalizer.aadBytes(
                "POST",
                "/v1/sense",
                "application/octet-stream",
                sessionId,
                requestId,
                timestamp,
                nonce));

        when(sessions.load(sessionId)).thenReturn(Mono.just(sessionKey));
        when(boxIds.store(any(), any(), any(), any(), any(), any())).thenReturn(Mono.empty());
        when(kafka.publishParsed(any())).thenReturn(Mono.empty());

        SenseResponse response = service.ingest(sessionId, tenantId, encrypted, requestId, timestamp, nonce).block();

        assertNotNull(response);
        assertNotNull(response.boxId());
        assertNotNull(response.expiresAt());
    }

    @Test
    void ingestFailsWhenPayloadWasEncryptedWithDifferentAssociatedData() throws Exception {
        SessionStore sessions = mock(SessionStore.class);
        BoxIdRepository boxIds = mock(BoxIdRepository.class);
        KafkaPublisher kafka = mock(KafkaPublisher.class);
        SenseService service = new SenseService(
            sessions, boxIds, kafka, new ObjectMapper(), new SimpleMeterRegistry());

        String sessionId = "01HSESSIONTEST00000000000000";
        String tenantId = UUID.randomUUID().toString();
        byte[] sessionKey = fixedKey();
        byte[] plain = scrambledPayloadWithSingleEvent();
        byte[] encrypted = new AesGcmCipher().seal(
            sessionKey,
            plain,
            "different-associated-data".getBytes(StandardCharsets.UTF_8));

        when(sessions.load(anyString())).thenReturn(Mono.just(sessionKey));

        assertThrows(LeonaException.class, () ->
            service.ingest(sessionId, tenantId, encrypted, "req-123", System.currentTimeMillis(), "nonce-abc").block());
    }

    @Test
    void ingestElevatesRiskWhenNativeHookHeadersArePresent() throws Exception {
        SessionStore sessions = mock(SessionStore.class);
        BoxIdRepository boxIds = mock(BoxIdRepository.class);
        KafkaPublisher kafka = mock(KafkaPublisher.class);
        SenseService service = new SenseService(
            sessions, boxIds, kafka, new ObjectMapper(), new SimpleMeterRegistry());

        String sessionId = "01HSESSIONTEST00000000000000";
        String tenantId = UUID.randomUUID().toString();
        String requestId = "req-123";
        long timestamp = System.currentTimeMillis();
        String nonce = "nonce-abc";
        byte[] sessionKey = fixedKey();
        byte[] plain = scrambledPayloadWithSingleEvent();
        byte[] encrypted = new AesGcmCipher().seal(
            sessionKey,
            plain,
            SdkRequestCanonicalizer.aadBytes(
                "POST",
                "/v1/sense",
                "application/octet-stream",
                sessionId,
                requestId,
                timestamp,
                nonce));

        when(sessions.load(sessionId)).thenReturn(Mono.just(sessionKey));
        when(boxIds.store(any(), any(), any(), any(), any(), any())).thenReturn(Mono.empty());
        when(kafka.publishParsed(any())).thenReturn(Mono.empty());

        service.ingest(
            sessionId,
            tenantId,
            encrypted,
            requestId,
            timestamp,
            nonce,
            SenseRequestRiskSignals.fromHeaders(
                "hook.frida.native,hook.injection.native",
                "injection.frida.known_library",
                3
            )
        ).block();

        ArgumentCaptor<io.leonasec.server.common.api.RiskAssessment> riskCaptor =
            ArgumentCaptor.forClass(io.leonasec.server.common.api.RiskAssessment.class);
        ArgumentCaptor<String> eventsJsonCaptor = ArgumentCaptor.forClass(String.class);
        verify(boxIds).store(any(), any(), any(), any(), riskCaptor.capture(), eventsJsonCaptor.capture());

        assertTrue(riskCaptor.getValue().score() >= 50);
        assertTrue(riskCaptor.getValue().reasons().contains("injection.frida.known_library"));
        assertTrue(eventsJsonCaptor.getValue().contains("injection.frida.known_library"));
        assertTrue(eventsJsonCaptor.getValue().contains("\"source\":\"request_headers\""));
    }

    private static byte[] fixedKey() {
        byte[] key = new byte[32];
        for (int i = 0; i < key.length; i++) key[i] = (byte) (i + 7);
        return key;
    }

    private static byte[] scrambledPayloadWithSingleEvent() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(new byte[] {'L', 'N', 'A', '1'});
        out.write(0x01);
        out.write(0x00);
        writeU16(out, 1);

        writeString(out, "injection.test.event");
        out.write(3);
        out.write(1);
        writeString(out, "Injected test event");
        writeString(out, "path=/tmp/test");

        byte[] plain = out.toByteArray();
        int state = 0x5C;
        for (int i = 0; i < plain.length; i++) {
            plain[i] = (byte) ((plain[i] & 0xFF) ^ state);
            state = ((state * 31) + 17) & 0xFF;
        }
        return plain;
    }

    private static void writeString(ByteArrayOutputStream out, String value) throws Exception {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        writeU16(out, bytes.length);
        out.write(bytes);
    }

    private static void writeU16(ByteArrayOutputStream out, int value) {
        out.write(value & 0xFF);
        out.write((value >> 8) & 0xFF);
    }
}
