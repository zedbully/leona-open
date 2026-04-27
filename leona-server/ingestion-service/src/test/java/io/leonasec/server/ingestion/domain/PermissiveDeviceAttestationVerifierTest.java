/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.ingestion.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.leonasec.server.common.api.HandshakeRequest;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PermissiveDeviceAttestationVerifierTest {

    @org.junit.jupiter.api.AfterEach
    void clearTrustedProvidersProperty() {
        System.clearProperty("leona.handshake.attestation.oem.trusted-providers");
        System.clearProperty("leona.handshake.attestation.oem.verifier-class");
        OemAttestationVerifiers.resetForTests();
    }

    @Test
    void rejectsWhenAttestationMissingAndRequired() throws Exception {
        PermissiveDeviceAttestationVerifier verifier = new PermissiveDeviceAttestationVerifier(
            true,
            false,
            "MEETS_DEVICE_INTEGRITY",
            300,
            new ObjectMapper()
        );

        DeviceAttestationVerifier.Result result = verifier.verify(signedRequest(null, null));

        assertFalse(result.accepted());
        assertEquals("attestation_missing", result.status());
        assertEquals("ATTESTATION_MISSING", result.code());
    }

    @Test
    void acceptsStructuredPlayIntegrityClaimsBoundToHandshakeChallenge() throws Exception {
        PermissiveDeviceAttestationVerifier verifier = new PermissiveDeviceAttestationVerifier(
            true,
            false,
            "MEETS_DEVICE_INTEGRITY",
            300,
            new ObjectMapper()
        );

        String challenge = handshakeChallenge("install-1", "1.0.0", CLIENT_PUBLIC_KEY);
        String token = """
            {
              "requestDetails": {
                "requestHash": "%s",
                "timestampMillis": %d
              },
              "appIntegrity": {
                "appRecognitionVerdict": "PLAY_RECOGNIZED"
              },
              "deviceIntegrity": {
                "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"]
              }
            }
            """.formatted(challenge, Instant.now().toEpochMilli());

        DeviceAttestationVerifier.Result result = verifier.verify(
            signedRequest("play_integrity", token)
        );

        assertTrue(result.accepted());
        assertEquals("play_integrity", result.provider());
        assertEquals("PLAY_INTEGRITY_VERIFIED", result.code());
    }

    @Test
    void rejectsWhenPlayIntegrityChallengeDoesNotMatchHandshake() throws Exception {
        PermissiveDeviceAttestationVerifier verifier = new PermissiveDeviceAttestationVerifier(
            true,
            false,
            "MEETS_DEVICE_INTEGRITY",
            300,
            new ObjectMapper()
        );

        String token = """
            {
              "requestDetails": {
                "requestHash": "deadbeef",
                "timestampMillis": %d
              },
              "appIntegrity": {
                "appRecognitionVerdict": "PLAY_RECOGNIZED"
              },
              "deviceIntegrity": {
                "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"]
              }
            }
            """.formatted(Instant.now().toEpochMilli());

        DeviceAttestationVerifier.Result result = verifier.verify(
            signedRequest("play_integrity", token)
        );

        assertFalse(result.accepted());
        assertEquals("attestation_challenge_mismatch", result.status());
        assertEquals("PLAY_INTEGRITY_CHALLENGE_MISMATCH", result.code());
    }

    @Test
    void verifiesOemAttestationThroughPrivateBridgeWhenInstalled() {
        System.setProperty("leona.handshake.attestation.oem.trusted-providers", "mainland_demo");
        System.setProperty(
            "leona.handshake.attestation.oem.verifier-class",
            FakePrivateOemAttestationVerifier.class.getName());
        PermissiveDeviceAttestationVerifier verifier = new PermissiveDeviceAttestationVerifier(
            true,
            false,
            "MEETS_DEVICE_INTEGRITY",
            300,
            new ObjectMapper()
        );
        HandshakeRequest request = new HandshakeRequest(
            "client-pub",
            "install-123",
            "1.0.0",
            new HandshakeRequest.DeviceBinding(
                "EC_P256",
                "public-key",
                "SHA256withECDSA",
                "signature",
                true,
                "oem_attestation",
                """
                    {
                      "version": 1,
                      "provider": "mainland_demo",
                      "trustTier": "oem_attested",
                      "issuedAtMillis": %d,
                      "challenge": "%s",
                      "installId": "install-123",
                      "packageName": "com.example.app",
                      "evidenceLabels": ["boot_locked", "tee_key"]
                    }
                    """.formatted(Instant.now().toEpochMilli(), handshakeChallenge("install-123", "1.0.0", "client-pub"))
            )
        );

        DeviceAttestationVerifier.Result result = verifier.verify(request);

        assertTrue(result.accepted());
        assertEquals("mainland_demo", result.provider());
        assertEquals("OEM_ATTESTATION_VERIFIED", result.code());
        assertEquals("oem_attestation/oem_attested", result.status());
    }

    @Test
    void rejectsMalformedOemAttestationPayload() {
        System.setProperty("leona.handshake.attestation.oem.trusted-providers", "mainland_demo");
        System.setProperty(
            "leona.handshake.attestation.oem.verifier-class",
            FakePrivateOemAttestationVerifier.class.getName());
        PermissiveDeviceAttestationVerifier verifier = new PermissiveDeviceAttestationVerifier(
            true,
            false,
            "MEETS_DEVICE_INTEGRITY",
            300,
            new ObjectMapper()
        );
        HandshakeRequest request = new HandshakeRequest(
            "client-pub",
            "install-123",
            "1.0.0",
            new HandshakeRequest.DeviceBinding(
                "EC_P256",
                "public-key",
                "SHA256withECDSA",
                "signature",
                true,
                "oem_attestation",
                "{"
            )
        );

        DeviceAttestationVerifier.Result result = verifier.verify(request);

        assertFalse(result.accepted());
        assertEquals("attestation_parse_failed", result.status());
        assertEquals("OEM_ATTESTATION_PARSE_FAILED", result.code());
    }

    private static HandshakeRequest signedRequest(String attestationFormat, String attestationToken) throws Exception {
        return new HandshakeRequest(
            CLIENT_PUBLIC_KEY,
            "install-1",
            "1.0.0",
            new HandshakeRequest.DeviceBinding(
                "EC_P256",
                "public-key",
                "SHA256withECDSA",
                "signature",
                true,
                attestationFormat,
                attestationToken
            )
        );
    }

    private static String handshakeChallenge(String installId, String sdkVersion, String clientPublicKey) {
        return sha256Hex((installId + "\n" + sdkVersion + "\n" + clientPublicKey).getBytes(StandardCharsets.UTF_8));
    }

    private static String sha256Hex(byte[] bytes) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
            StringBuilder builder = new StringBuilder(digest.length * 2);
            for (byte value : digest) {
                builder.append(Character.forDigit((value >> 4) & 0xF, 16));
                builder.append(Character.forDigit(value & 0xF, 16));
            }
            return builder.toString();
        } catch (Exception error) {
            throw new IllegalStateException(error);
        }
    }

    private static final String CLIENT_PUBLIC_KEY = Base64.getUrlEncoder()
        .withoutPadding()
        .encodeToString(new byte[32]);

    public static final class FakePrivateOemAttestationVerifier {
        private final ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();

        public DeviceAttestationVerifier.Result verify(HandshakeRequest request) {
            try {
                var claims = mapper.readTree(request.deviceBinding().attestationToken());
                String provider = claims.path("provider").asText("");
                String trusted = System.getProperty("leona.handshake.attestation.oem.trusted-providers", "");
                boolean allowed = java.util.Arrays.stream(trusted.split(","))
                    .map(String::trim)
                    .anyMatch(provider::equals);
                if (!allowed) {
                    return DeviceAttestationVerifier.Result.rejected(
                        "attestation_provider_untrusted",
                        provider,
                        "OEM_ATTESTATION_PROVIDER_UNTRUSTED",
                        false);
                }
                String trustTier = claims.path("trustTier").asText("oem_attested");
                return DeviceAttestationVerifier.Result.accepted(
                    "oem_attestation/" + trustTier,
                    provider,
                    "OEM_ATTESTATION_VERIFIED",
                    false);
            } catch (Exception error) {
                return DeviceAttestationVerifier.Result.rejected(
                    "attestation_parse_failed",
                    "oem_attestation",
                    "OEM_ATTESTATION_PARSE_FAILED",
                    false);
            }
        }
    }
}
