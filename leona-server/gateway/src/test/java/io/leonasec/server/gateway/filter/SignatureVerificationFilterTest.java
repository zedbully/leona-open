/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.gateway.filter;

import io.leonasec.server.common.auth.HmacVerifier;
import io.leonasec.server.common.auth.ReactiveReplayGuard;
import io.leonasec.server.common.auth.RequestPrincipal;
import io.leonasec.server.common.error.LeonaException;
import io.leonasec.server.gateway.auth.RedisSessionKeyLookup;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SignatureVerificationFilterTest {

    @Test
    void senseRequestFailsWhenSessionHeaderIsMissing() {
        ReactiveReplayGuard replayGuard = mock(ReactiveReplayGuard.class);
        RedisSessionKeyLookup sessionKeys = mock(RedisSessionKeyLookup.class);
        SignatureVerificationFilter filter = new SignatureVerificationFilter(replayGuard, sessionKeys);

        long timestamp = System.currentTimeMillis();
        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.post("/v1/sense")
                .header("X-Leona-Request-Id", "req-1")
                .header("X-Leona-Timestamp", String.valueOf(timestamp))
                .header("X-Leona-Nonce", "nonce-1")
                .header("X-Leona-Signature", "sig")
                .body("010203")
        );

        GatewayFilterChain chain = ex -> Mono.empty();

        assertThrows(LeonaException.class, () -> filter.filter(exchange, chain).block());
    }

    @Test
    void senseRequestPassesWhenSdkSignatureMatches() {
        ReactiveReplayGuard replayGuard = mock(ReactiveReplayGuard.class);
        RedisSessionKeyLookup sessionKeys = mock(RedisSessionKeyLookup.class);
        SignatureVerificationFilter filter = new SignatureVerificationFilter(replayGuard, sessionKeys);

        byte[] sessionKey = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);
        byte[] bodyBytes = "ciphertext-body".getBytes(StandardCharsets.UTF_8);
        long timestamp = System.currentTimeMillis();
        String nonce = "nonce-sdk";
        String requestId = "req-sdk";
        String sessionId = "01HSESSIONTEST00000000000000";
        String signature = HmacVerifier.signSdk(
            sessionKey,
            "POST",
            "/v1/sense",
            "application/octet-stream",
            sessionId,
            requestId,
            timestamp,
            nonce,
            bodyBytes);

        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.post("/v1/sense")
                .header("X-Leona-Session-Id", sessionId)
                .header("X-Leona-Request-Id", requestId)
                .header("X-Leona-Timestamp", String.valueOf(timestamp))
                .header("X-Leona-Nonce", nonce)
                .header("X-Leona-Signature", signature)
                .body(new String(bodyBytes, StandardCharsets.UTF_8))
        );

        when(sessionKeys.load(sessionId)).thenReturn(Mono.just(sessionKey));
        when(replayGuard.claimOrReject(anyString(), any())).thenReturn(Mono.just(true));

        AtomicReference<ServerWebExchange> captured = new AtomicReference<>();
        GatewayFilterChain chain = ex -> {
            captured.set(ex);
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();

        assertEquals("1", captured.get().getRequest().getHeaders().getFirst(RequestPrincipal.HEADER_VERIFIED));
    }

    @Test
    void verdictRequestPassesWhenSignatureMatches() {
        ReactiveReplayGuard replayGuard = mock(ReactiveReplayGuard.class);
        RedisSessionKeyLookup sessionKeys = mock(RedisSessionKeyLookup.class);
        SignatureVerificationFilter filter = new SignatureVerificationFilter(replayGuard, sessionKeys);

        byte[] signingKey = "lk_live_sec_test_signing_key".getBytes(StandardCharsets.UTF_8);
        String body = "{\"boxId\":\"01HKF3XAQ8M9X1ZY5PQ123\"}";
        byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
        long timestamp = System.currentTimeMillis();
        String nonce = "nonce-2";
        String signature = HmacVerifier.sign(signingKey, timestamp, nonce, bodyBytes);

        MockServerWebExchange exchange = MockServerWebExchange.from(
            MockServerHttpRequest.post("/v1/verdict")
                .header("X-Leona-Timestamp", String.valueOf(timestamp))
                .header("X-Leona-Nonce", nonce)
                .header("X-Leona-Signature", signature)
                .body(body)
        );
        exchange.getAttributes().put(AppKeyAuthFilter.ATTR_SIGNING_KEY, signingKey);

        when(replayGuard.claimOrReject(anyString(), any())).thenReturn(Mono.just(true));

        AtomicReference<ServerWebExchange> captured = new AtomicReference<>();
        GatewayFilterChain chain = ex -> {
            captured.set(ex);
            return Mono.empty();
        };

        filter.filter(exchange, chain).block();

        assertEquals("1", captured.get().getRequest().getHeaders().getFirst(RequestPrincipal.HEADER_VERIFIED));
    }
}
