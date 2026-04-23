/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.ingestion.domain;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.leonasec.server.common.api.HandshakeRequest;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PermissiveDeviceAttestationVerifierTest {

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
    }

    private static HandshakeRequest signedRequest(String attestationFormat, String attestationToken) throws Exception {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        var pair = generator.generateKeyPair();
        String publicKey = Base64.getUrlEncoder().withoutPadding().encodeToString(pair.getPublic().getEncoded());

        HandshakeRequest seed = new HandshakeRequest(
            CLIENT_PUBLIC_KEY,
            "install-1",
            "1.0.0",
            new HandshakeRequest.DeviceBinding(
                "EC_P256",
                publicKey,
                "SHA256withECDSA",
                "",
                true,
                attestationFormat,
                attestationToken
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
                attestationFormat,
                attestationToken
            )
        );
    }

    private static String handshakeChallenge(String installId, String sdkVersion, String clientPublicKey) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256")
            .digest((installId + "\n" + sdkVersion + "\n" + clientPublicKey).getBytes(StandardCharsets.UTF_8));
        StringBuilder builder = new StringBuilder(digest.length * 2);
        for (byte value : digest) {
            builder.append(Character.forDigit((value >> 4) & 0xF, 16));
            builder.append(Character.forDigit(value & 0xF, 16));
        }
        return builder.toString();
    }

    private static final String CLIENT_PUBLIC_KEY = Base64.getUrlEncoder()
        .withoutPadding()
        .encodeToString(new byte[32]);
}
