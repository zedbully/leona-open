/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.gateway.filter;

import io.leonasec.server.common.auth.HmacVerifier;
import io.leonasec.server.common.auth.ReactiveReplayGuard;
import io.leonasec.server.common.auth.RequestPrincipal;
import io.leonasec.server.common.auth.TimestampValidator;
import io.leonasec.server.common.error.ErrorCode;
import io.leonasec.server.common.error.LeonaException;
import io.leonasec.server.gateway.auth.RedisSessionKeyLookup;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.List;

/** Validates HMAC/timestamp/nonce on signed paths. */
@Component
@Order(-5)
public class SignatureVerificationFilter implements GlobalFilter {

    private static final List<String> SIGNED_PATHS = List.of("/v1/sense", "/v1/verdict");
    private static final int MAX_BODY = 128 * 1024;
    private static final String SDK_CONTENT_TYPE = "application/octet-stream";

    private final TimestampValidator timestamps = new TimestampValidator();
    private final ReactiveReplayGuard replayGuard;
    private final RedisSessionKeyLookup sessionKeys;

    public SignatureVerificationFilter(ReactiveReplayGuard replayGuard,
                                       RedisSessionKeyLookup sessionKeys) {
        this.replayGuard = replayGuard;
        this.sessionKeys = sessionKeys;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        if (SIGNED_PATHS.stream().noneMatch(path::startsWith)) {
            return chain.filter(exchange);
        }

        ServerHttpRequest req = exchange.getRequest();
        String ts = req.getHeaders().getFirst("X-Leona-Timestamp");
        String nonce = req.getHeaders().getFirst("X-Leona-Nonce");
        String signature = req.getHeaders().getFirst("X-Leona-Signature");

        if (ts == null || nonce == null || signature == null) {
            return Mono.error(new LeonaException(ErrorCode.LEONA_AUTH_MISSING));
        }

        long timestamp;
        try {
            timestamp = Long.parseLong(ts);
        } catch (NumberFormatException e) {
            return Mono.error(new LeonaException(
                ErrorCode.LEONA_TIMESTAMP_SKEW, "Timestamp not parseable"));
        }
        if (!timestamps.isAcceptable(timestamp)) {
            return Mono.error(new LeonaException(ErrorCode.LEONA_TIMESTAMP_SKEW));
        }

        return resolveSigningKey(exchange, path)
            .flatMap(signingKey -> replayGuard.claimOrReject(nonce, Duration.ofHours(1))
                .flatMap(firstSeen -> {
                    if (!firstSeen) {
                        return Mono.error(new LeonaException(ErrorCode.LEONA_NONCE_REPLAY));
                    }
                    return bufferBodyAndVerify(exchange, chain, signingKey, timestamp, nonce, signature);
                }));
    }

    private Mono<byte[]> resolveSigningKey(ServerWebExchange exchange, String path) {
        if (path.startsWith("/v1/sense")) {
            String sessionId = exchange.getRequest().getHeaders().getFirst("X-Leona-Session-Id");
            if (sessionId == null || sessionId.isBlank()) {
                return Mono.error(new LeonaException(
                    ErrorCode.LEONA_AUTH_MISSING, "X-Leona-Session-Id missing"));
            }
            return sessionKeys.load(sessionId)
                .switchIfEmpty(Mono.error(new LeonaException(
                    ErrorCode.LEONA_AUTH_INVALID, "Unknown session id")));
        }

        byte[] signingKey = (byte[]) exchange.getAttribute(AppKeyAuthFilter.ATTR_SIGNING_KEY);
        if (signingKey == null) {
            return Mono.error(new LeonaException(
                ErrorCode.LEONA_AUTH_INVALID, "Signing key not resolved"));
        }
        return Mono.just(signingKey);
    }

    private Mono<Void> bufferBodyAndVerify(
        ServerWebExchange exchange,
        GatewayFilterChain chain,
        byte[] signingKey,
        long timestamp,
        String nonce,
        String signature) {

        return DataBufferUtils.join(exchange.getRequest().getBody())
            .defaultIfEmpty(exchange.getResponse().bufferFactory().wrap(new byte[0]))
            .flatMap(buffer -> {
                byte[] body = extract(buffer);
                if (body.length > MAX_BODY) {
                    return Mono.error(new LeonaException(
                        ErrorCode.LEONA_PAYLOAD_TOO_LARGE,
                        "Body exceeds 128 KiB (" + body.length + ")"));
                }
                if (!verify(exchange, signingKey, timestamp, nonce, body, signature)) {
                    return Mono.error(new LeonaException(ErrorCode.LEONA_SIGNATURE_INVALID));
                }

                ServerHttpRequest mutated = exchange.getRequest().mutate()
                    .header(RequestPrincipal.HEADER_VERIFIED, "1")
                    .build();
                DataBuffer replay = exchange.getResponse().bufferFactory().wrap(body);
                ServerWebExchange next = exchange.mutate()
                    .request(new BodyReplayingRequest(mutated, Flux.just(replay)))
                    .build();
                return chain.filter(next);
            });
    }

    private boolean verify(ServerWebExchange exchange,
                           byte[] signingKey,
                           long timestamp,
                           String nonce,
                           byte[] body,
                           String signature) {
        String path = exchange.getRequest().getPath().value();
        if (path.startsWith("/v1/sense")) {
            String sessionId = exchange.getRequest().getHeaders().getFirst("X-Leona-Session-Id");
            String requestId = exchange.getRequest().getHeaders().getFirst("X-Leona-Request-Id");
            if (requestId == null || requestId.isBlank()) {
                throw new LeonaException(ErrorCode.LEONA_AUTH_MISSING, "X-Leona-Request-Id missing");
            }
            return HmacVerifier.verifySdk(
                signingKey,
                exchange.getRequest().getMethod().name(),
                "/v1/sense",
                SDK_CONTENT_TYPE,
                sessionId,
                requestId,
                timestamp,
                nonce,
                body,
                signature);
        }
        return HmacVerifier.verify(signingKey, timestamp, nonce, body, signature);
    }

    private byte[] extract(DataBuffer buffer) {
        byte[] out = new byte[buffer.readableByteCount()];
        buffer.read(out);
        DataBufferUtils.release(buffer);
        return out;
    }

    private static final class BodyReplayingRequest
        extends org.springframework.http.server.reactive.ServerHttpRequestDecorator {
        private final Flux<DataBuffer> body;
        BodyReplayingRequest(ServerHttpRequest delegate, Flux<DataBuffer> body) {
            super(delegate);
            this.body = body;
        }
        @Override
        public Flux<DataBuffer> getBody() { return body; }
    }
}
