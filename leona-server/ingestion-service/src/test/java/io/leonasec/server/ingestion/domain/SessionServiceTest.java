/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.ingestion.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.leonasec.server.common.api.HandshakeRequest;
import io.leonasec.server.common.api.HandshakeResponse;
import io.leonasec.server.common.crypto.EcdheSession;
import io.leonasec.server.common.error.LeonaException;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SessionServiceTest {

    @Test
    void establishRejectsMissingDeviceBinding() {
        SessionStore sessions = mock(SessionStore.class);
        DeviceBindingStore bindings = mock(DeviceBindingStore.class);
        SessionService service = new SessionService(
            sessions,
            new SimpleMeterRegistry(),
            new TamperBaselineProvider("", "", new ObjectMapper()),
            bindings,
            request -> DeviceAttestationVerifier.Result.accepted("not_provided")
        );

        HandshakeRequest request = new HandshakeRequest(
            "client-pub",
            "install-1",
            "1.0.0",
            null
        );

        assertThrows(LeonaException.class, () -> service.establish(request).block());
        verify(sessions, never()).store(anyString(), any(), any());
        verify(bindings, never()).store(anyString(), anyString(), any());
    }

    @Test
    void establishRejectsBlankBindingSignature() {
        SessionStore sessions = mock(SessionStore.class);
        DeviceBindingStore bindings = mock(DeviceBindingStore.class);
        SessionService service = new SessionService(
            sessions,
            new SimpleMeterRegistry(),
            new TamperBaselineProvider("", "", new ObjectMapper()),
            bindings,
            request -> DeviceAttestationVerifier.Result.accepted("not_provided")
        );

        HandshakeRequest request = new HandshakeRequest(
            "client-pub",
            "install-1",
            "1.0.0",
            new HandshakeRequest.DeviceBinding(
                "EC_P256",
                "public-key",
                "SHA256withECDSA",
                " ",
                true,
                null,
                null
            )
        );

        assertThrows(LeonaException.class, () -> service.establish(request).block());
        verify(sessions, never()).store(anyString(), any(), any());
    }

    @Test
    void establishAcceptsBoundRequest() throws Exception {
        SessionStore sessions = mock(SessionStore.class);
        DeviceBindingStore bindings = mock(DeviceBindingStore.class);
        when(sessions.store(anyString(), any(), any())).thenReturn(Mono.empty());
        when(bindings.load("install-1")).thenReturn(Mono.empty());
        when(bindings.store(anyString(), anyString(), any())).thenReturn(Mono.empty());

        SessionService service = new SessionService(
            sessions,
            new SimpleMeterRegistry(),
            new TamperBaselineProvider("", "{\"expectedPackageName\":\"io.demo\"}", new ObjectMapper()),
            bindings,
            request -> DeviceAttestationVerifier.Result.accepted(
                "verified",
                "play_integrity",
                "PLAY_INTEGRITY_VERIFIED",
                false)
        );

        HandshakeRequest request = signedRequest();

        HandshakeResponse response = service.establish(request).block();
        String bindingStatus = response.deviceBindingStatus();

        assertEquals("bound-hardware/verified", bindingStatus);
        assertEquals("io.demo", response.tamperBaseline().get("expectedPackageName"));
        assertNotNull(response.attestation());
        assertEquals("play_integrity", response.attestation().provider());
        assertEquals("PLAY_INTEGRITY_VERIFIED", response.attestation().code());
        verify(bindings).store(anyString(), anyString(), any());
        verify(sessions).store(anyString(), any(), any());
    }

    @Test
    void establishEchoesCanonicalDeviceIdFromDeviceIdentity() throws Exception {
        SessionStore sessions = mock(SessionStore.class);
        DeviceBindingStore bindings = mock(DeviceBindingStore.class);
        when(sessions.store(anyString(), any(), any())).thenReturn(Mono.empty());
        when(bindings.load("install-1")).thenReturn(Mono.empty());
        when(bindings.store(anyString(), anyString(), any())).thenReturn(Mono.empty());

        SessionService service = new SessionService(
            sessions,
            new SimpleMeterRegistry(),
            new TamperBaselineProvider("", "", new ObjectMapper()),
            bindings,
            request -> DeviceAttestationVerifier.Result.accepted("verified")
        );

        HandshakeRequest signed = signedRequest();
        HandshakeRequest request = new HandshakeRequest(
            signed.clientPublicKey(),
            signed.installId(),
            signed.sdkVersion(),
            signed.deviceBinding(),
            new HandshakeRequest.DeviceIdentity(
                "install-1",
                "temporary-id",
                "756bc06b9f5afc8e80548d41ce43062",
                "fp-123"
            )
        );

        HandshakeResponse response = service.establish(request).block();

        assertEquals("L756bc06b9f5afc8e80548d41ce43062", response.canonicalDeviceId());
    }

    @Test
    void establishReturnsStructuredAttestationDetailsOnRejection() throws Exception {
        SessionStore sessions = mock(SessionStore.class);
        DeviceBindingStore bindings = mock(DeviceBindingStore.class);
        SessionService service = new SessionService(
            sessions,
            new SimpleMeterRegistry(),
            new TamperBaselineProvider("", "", new ObjectMapper()),
            bindings,
            request -> DeviceAttestationVerifier.Result.rejected(
                "attestation_stale",
                "play_integrity",
                "PLAY_INTEGRITY_STALE",
                true)
        );

        LeonaException error = assertThrows(LeonaException.class, () -> service.establish(signedRequest()).block());

        assertTrue(error.getMessage().contains("attestation_stale"));
        @SuppressWarnings("unchecked")
        var attestation = (java.util.Map<String, Object>) error.details().get("attestation");
        assertEquals("play_integrity", attestation.get("provider"));
        assertEquals("PLAY_INTEGRITY_STALE", attestation.get("code"));
        assertEquals(Boolean.TRUE, attestation.get("retryable"));
        verify(sessions, never()).store(anyString(), any(), any());
    }

    private static HandshakeRequest signedRequest() throws Exception {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        var pair = generator.generateKeyPair();
        String publicKey = Base64.getUrlEncoder().withoutPadding().encodeToString(pair.getPublic().getEncoded());

        HandshakeRequest seed = new HandshakeRequest(
            EcdheSession.generate().publicKeyBase64Url(),
            "install-1",
            "1.0.0",
            new HandshakeRequest.DeviceBinding(
                "EC_P256",
                publicKey,
                "SHA256withECDSA",
                "",
                true,
                null,
                null
            )
        );

        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(pair.getPrivate());
        signer.update(io.leonasec.server.common.auth.DeviceBindingVerifier.canonical(seed).getBytes(StandardCharsets.UTF_8));
        String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());

        return new HandshakeRequest(
            seed.clientPublicKey(),
            seed.installId(),
            seed.sdkVersion(),
            new HandshakeRequest.DeviceBinding(
                "EC_P256",
                publicKey,
                "SHA256withECDSA",
                signature,
                true,
                null,
                null
            )
        );
    }
}
