/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.auth;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * HMAC signer for {@code /v1/verdict} responses.
 *
 * <p>Canonical format:
 *
 * <pre>{@code
 *   canonical = generatedAt || "\n" || sha256(body)
 *   signature = base64url(HMAC-SHA256(secret, canonical))
 * }</pre>
 *
 * <p>This lets customer backends verify that the verdict body was produced by
 * Leona and was not modified in transit after the gateway authenticated the
 * original request.
 */
public final class VerdictResponseSigner {

    private VerdictResponseSigner() {}

    public static String sign(byte[] secret, String generatedAt, byte[] body) {
        try {
            byte[] bodyHash = MessageDigest.getInstance("SHA-256").digest(body);
            String canonical = generatedAt + "\n" + bytesToHex(bodyHash);
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            byte[] sig = mac.doFinal(canonical.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(sig);
        } catch (Exception e) {
            throw new IllegalStateException("Verdict response signing failed", e);
        }
    }

    public static boolean verify(byte[] secret, String generatedAt, byte[] body, String providedSignature) {
        String expected = sign(secret, generatedAt, body);
        return MessageDigest.isEqual(
            expected.getBytes(StandardCharsets.US_ASCII),
            providedSignature.getBytes(StandardCharsets.US_ASCII)
        );
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}
