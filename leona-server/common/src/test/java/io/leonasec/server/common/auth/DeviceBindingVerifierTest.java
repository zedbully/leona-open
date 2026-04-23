/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.auth;

import io.leonasec.server.common.api.HandshakeRequest;
import io.leonasec.server.common.spi.TestCryptoSupport;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DeviceBindingVerifierTest {

    static {
        TestCryptoSupport.install();
    }

    @Test
    void verifyAcceptsValidSignature() throws Exception {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        var pair = generator.generateKeyPair();
        String publicKey = Base64.getUrlEncoder().withoutPadding().encodeToString(pair.getPublic().getEncoded());

        HandshakeRequest seed = new HandshakeRequest(
            "client-pub",
            "install-1",
            "0.1.0",
            new HandshakeRequest.DeviceBinding(
                "EC_P256",
                publicKey,
                "SHA256withECDSA",
                "",
                true,
                "play_integrity",
                "token-123"
            )
        );
        String canonical = DeviceBindingVerifier.canonical(seed);
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(pair.getPrivate());
        signer.update(canonical.getBytes(StandardCharsets.UTF_8));
        String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());

        HandshakeRequest request = new HandshakeRequest(
            seed.clientPublicKey(),
            seed.installId(),
            seed.sdkVersion(),
            new HandshakeRequest.DeviceBinding(
                "EC_P256",
                publicKey,
                "SHA256withECDSA",
                signature,
                true,
                "play_integrity",
                "token-123"
            )
        );

        assertTrue(DeviceBindingVerifier.verify(request));
    }

    @Test
    void verifyRejectsTamperedSignature() {
        HandshakeRequest request = new HandshakeRequest(
            "client-pub",
            "install-1",
            "0.1.0",
            new HandshakeRequest.DeviceBinding(
                "EC_P256",
                Base64.getUrlEncoder().withoutPadding().encodeToString("not-a-key".getBytes(StandardCharsets.UTF_8)),
                "SHA256withECDSA",
                "deadbeef",
                false,
                null,
                null
            )
        );

        assertFalse(DeviceBindingVerifier.verify(request));
    }
}
