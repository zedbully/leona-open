/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.gateway.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.leonasec.server.common.error.ErrorCode;
import io.leonasec.server.common.error.ErrorResponse;
import io.leonasec.server.common.error.LeonaException;
import io.leonasec.server.common.util.RequestIds;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebExceptionHandler;
import reactor.core.publisher.Mono;

import java.util.Map;

@Component
public class GlobalExceptionHandler implements WebExceptionHandler {

    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {
        String requestId = RequestIds.newId();
        ErrorResponse response;

        if (ex instanceof LeonaException leona) {
            response = new ErrorResponse(leona.code(), leona.getMessage(), requestId);
            exchange.getResponse().setStatusCode(leona.code().status());
        } else {
            response = new ErrorResponse(ErrorCode.LEONA_INTERNAL_ERROR, requestId);
            exchange.getResponse().setStatusCode(ErrorCode.LEONA_INTERNAL_ERROR.status());
        }

        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        exchange.getResponse().getHeaders().add(RequestIds.HEADER, requestId);

        byte[] body;
        try {
            body = mapper.writeValueAsBytes(Map.of(
                "code", response.code().name(),
                "message", response.message(),
                "requestId", response.requestId()
            ));
        } catch (Exception e) {
            body = new byte[0];
        }
        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(body);
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }
}
