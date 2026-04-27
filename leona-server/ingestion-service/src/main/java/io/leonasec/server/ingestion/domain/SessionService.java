/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.ingestion.domain;

import com.github.f4b6a3.ulid.UlidCreator;
import io.leonasec.server.common.api.HandshakeRequest;
import io.leonasec.server.common.api.HandshakeResponse;
import io.leonasec.server.common.auth.DeviceBindingVerifier;
import io.leonasec.server.common.crypto.EcdheSession;
import io.leonasec.server.common.error.ErrorCode;
import io.leonasec.server.common.error.LeonaException;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

/**
 * Establishes ECDHE sessions and binds installs to an Android Keystore key.
 */
@Service
public class SessionService {

    private static final Duration SESSION_TTL = Duration.ofHours(24);
    private static final Duration DEVICE_BINDING_TTL = Duration.ofDays(90);

    private final SessionStore sessionStore;
    private final MeterRegistry metrics;
    private final TamperBaselineProvider tamperBaselineProvider;
    private final DeviceBindingStore deviceBindingStore;
    private final DeviceAttestationVerifier attestationVerifier;

    public SessionService(
        SessionStore sessionStore,
        MeterRegistry metrics,
        TamperBaselineProvider tamperBaselineProvider,
        DeviceBindingStore deviceBindingStore,
        DeviceAttestationVerifier attestationVerifier
    ) {
        this.sessionStore = sessionStore;
        this.metrics = metrics;
        this.tamperBaselineProvider = tamperBaselineProvider;
        this.deviceBindingStore = deviceBindingStore;
        this.attestationVerifier = attestationVerifier;
    }

    public Mono<HandshakeResponse> establish(HandshakeRequest request) {
        validateRequest(request);
        return validateDeviceBinding(request)
            .flatMap(validation -> {
                EcdheSession ephemeral = EcdheSession.generate();
                String sessionId = UlidCreator.getUlid().toString();
                byte[] sessionKey = ephemeral.deriveSessionKey(
                    request.clientPublicKey(),
                    sessionId,
                    "leona/v2/session/" + request.installId());
                return sessionStore.store(sessionId, sessionKey, SESSION_TTL)
                    .doOnSuccess(ignored -> {
                        metrics.counter("leona.handshake.success").increment();
                        metrics.counter("leona.handshake.binding", "status", validation.bindingStatus()).increment();
                        recordAttestationMetric(validation.attestation());
                    })
                    .thenReturn(new HandshakeResponse(
                        ephemeral.publicKeyBase64Url(),
                        sessionId,
                        Instant.now().plus(SESSION_TTL),
                        tamperBaselineProvider.current(),
                        validation.bindingStatus(),
                        toAttestationSummary(validation.attestation()),
                        canonicalDeviceId(request)));
            });
    }

    private void validateRequest(HandshakeRequest request) {
        if (request == null || isBlank(request.clientPublicKey()) || isBlank(request.installId()) || isBlank(request.sdkVersion())) {
            throw new LeonaException(ErrorCode.LEONA_PAYLOAD_MALFORMED, "Handshake request missing required fields");
        }
    }

    private Mono<BindingValidation> validateDeviceBinding(HandshakeRequest request) {
        HandshakeRequest.DeviceBinding binding = request.deviceBinding();
        if (binding == null || isBlank(binding.publicKey()) || isBlank(binding.signature())) {
            metrics.counter("leona.handshake.binding_rejected", "reason", "missing").increment();
            return Mono.error(new LeonaException(ErrorCode.LEONA_AUTH_INVALID, "Device binding required"));
        }
        if (!DeviceBindingVerifier.verify(request)) {
            metrics.counter("leona.handshake.binding_rejected", "reason", "signature_invalid").increment();
            return Mono.error(new LeonaException(ErrorCode.LEONA_AUTH_INVALID, "Device binding signature invalid"));
        }
        DeviceAttestationVerifier.Result attestation = attestationVerifier.verify(request);
        if (!attestation.accepted()) {
            metrics.counter(
                "leona.handshake.binding_rejected",
                "reason", attestation.status(),
                "provider", metricValue(attestation.provider()),
                "code", metricValue(attestation.code()))
                .increment();
            recordAttestationMetric(attestation);
            return Mono.error(new LeonaException(
                ErrorCode.LEONA_AUTH_INVALID,
                "Device attestation rejected: " + attestation.status(),
                attestationDetails(attestation)));
        }
        return deviceBindingStore.load(request.installId())
            .defaultIfEmpty("")
            .flatMap(existing -> {
                if (!existing.isBlank() && !existing.equals(binding.publicKey())) {
                    metrics.counter("leona.handshake.binding_rejected", "reason", "install_rebound").increment();
                    return Mono.error(new LeonaException(ErrorCode.LEONA_AUTH_INVALID, "Install is bound to a different device key"));
                }
                return deviceBindingStore.store(request.installId(), binding.publicKey(), DEVICE_BINDING_TTL)
                    .thenReturn(new BindingValidation(buildBindingStatus(binding, attestation.status()), attestation));
            });
    }

    private String buildBindingStatus(HandshakeRequest.DeviceBinding binding, String attestationStatus) {
        String hardware = binding.hardwareBacked() ? "hardware" : "software";
        return "bound-" + hardware + "/" + attestationStatus;
    }

    private HandshakeResponse.AttestationSummary toAttestationSummary(DeviceAttestationVerifier.Result attestation) {
        if (attestation == null) {
            return null;
        }
        return new HandshakeResponse.AttestationSummary(
            attestation.provider(),
            attestation.status(),
            attestation.code(),
            attestation.retryable());
    }

    private String canonicalDeviceId(HandshakeRequest request) {
        HandshakeRequest.DeviceIdentity identity = request.deviceIdentity();
        if (identity == null) {
            return null;
        }
        String candidate = firstNonBlank(
            identity.canonicalDeviceId(),
            identity.resolvedDeviceId(),
            identity.fingerprintHash());
        if (isBlank(candidate)) {
            return null;
        }
        return candidate.startsWith("L") ? candidate : "L" + candidate;
    }

    private String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String value : values) {
            if (!isBlank(value)) {
                return value.trim();
            }
        }
        return null;
    }

    private Map<String, Object> attestationDetails(DeviceAttestationVerifier.Result attestation) {
        return Map.of(
            "attestation", Map.of(
                "provider", metricValue(attestation.provider()),
                "status", metricValue(attestation.status()),
                "code", metricValue(attestation.code()),
                "retryable", attestation.retryable() != null && attestation.retryable()
            )
        );
    }

    private void recordAttestationMetric(DeviceAttestationVerifier.Result attestation) {
        if (attestation == null) {
            return;
        }
        metrics.counter(
            "leona.handshake.attestation",
            "accepted", String.valueOf(attestation.accepted()),
            "provider", metricValue(attestation.provider()),
            "status", metricValue(attestation.status()),
            "code", metricValue(attestation.code()))
            .increment();
    }

    private String metricValue(String value) {
        return isBlank(value) ? "none" : value;
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private record BindingValidation(String bindingStatus, DeviceAttestationVerifier.Result attestation) {}
}
