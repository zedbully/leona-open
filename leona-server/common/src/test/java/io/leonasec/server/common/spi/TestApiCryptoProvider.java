/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.spi;

import io.leonasec.server.common.api.HandshakeRequest;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

public final class TestApiCryptoProvider implements ApiCryptoProvider {

    private static final SecureRandom RNG = new SecureRandom();

    @Override
    public String aad(String method, String path, String contentType, String sessionId,
                      String requestId, long timestamp, String nonce) {
        return method.toUpperCase()
            + "\n" + path
            + "\n" + contentType.toLowerCase()
            + "\n" + sessionId
            + "\n" + requestId
            + "\n" + timestamp
            + "\n" + nonce;
    }

    @Override
    public String signable(String method, String path, String contentType, String sessionId,
                           String requestId, long timestamp, String nonce, byte[] body) {
        return aad(method, path, contentType, sessionId, requestId, timestamp, nonce)
            + "\n" + sha256Hex(body);
    }

    @Override
    public byte[] aadBytes(String method, String path, String contentType, String sessionId,
                           String requestId, long timestamp, String nonce) {
        return aad(method, path, contentType, sessionId, requestId, timestamp, nonce)
            .getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public String sha256Hex(byte[] body) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(body);
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public String signLegacy(byte[] secret, long timestamp, String nonce, byte[] body) {
        return hmac(secret, timestamp + "\n" + nonce + "\n" + sha256Hex(body));
    }

    @Override
    public String signSdk(byte[] secret, String method, String path, String contentType,
                          String sessionId, String requestId, long timestamp, String nonce, byte[] body) {
        return hmac(secret, signable(method, path, contentType, sessionId, requestId, timestamp, nonce, body));
    }

    @Override
    public boolean verifyLegacy(byte[] secret, long timestamp, String nonce, byte[] body, String providedSignature) {
        return MessageDigest.isEqual(
            signLegacy(secret, timestamp, nonce, body).getBytes(StandardCharsets.US_ASCII),
            Objects.requireNonNullElse(providedSignature, "").getBytes(StandardCharsets.US_ASCII));
    }

    @Override
    public boolean verifySdk(byte[] secret, String method, String path, String contentType,
                             String sessionId, String requestId, long timestamp, String nonce,
                             byte[] body, String providedSignature) {
        return MessageDigest.isEqual(
            signSdk(secret, method, path, contentType, sessionId, requestId, timestamp, nonce, body)
                .getBytes(StandardCharsets.US_ASCII),
            Objects.requireNonNullElse(providedSignature, "").getBytes(StandardCharsets.US_ASCII));
    }

    @Override
    public String deviceBindingCanonical(HandshakeRequest request) {
        HandshakeRequest.DeviceBinding binding = request.deviceBinding();
        String tokenHash = "";
        if (binding != null && binding.attestationToken() != null && !binding.attestationToken().isBlank()) {
            tokenHash = sha256Hex(binding.attestationToken().getBytes(StandardCharsets.UTF_8));
        }
        return request.installId()
            + "\n" + request.sdkVersion()
            + "\n" + request.clientPublicKey()
            + "\n" + (binding == null ? "" : binding.publicKey())
            + "\n" + (binding != null && binding.hardwareBacked() ? "1" : "0")
            + "\n" + (binding == null ? "" : (binding.attestationFormat() == null ? "" : binding.attestationFormat()))
            + "\n" + tokenHash;
    }

    @Override
    public boolean verifyDeviceBinding(HandshakeRequest request) {
        HandshakeRequest.DeviceBinding binding = request.deviceBinding();
        if (binding == null) return false;
        if (!"EC_P256".equalsIgnoreCase(binding.keyAlgorithm())) return false;
        if (!"SHA256withECDSA".equalsIgnoreCase(binding.signatureAlgorithm())) return false;
        if (binding.publicKey() == null || binding.publicKey().isBlank()) return false;
        if (binding.signature() == null || binding.signature().isBlank()) return false;
        try {
            byte[] publicKeyBytes = Base64.getUrlDecoder().decode(binding.publicKey());
            byte[] signatureBytes = Base64.getUrlDecoder().decode(binding.signature());
            PublicKey publicKey = KeyFactory.getInstance("EC")
                .generatePublic(new X509EncodedKeySpec(publicKeyBytes));
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(publicKey);
            verifier.update(deviceBindingCanonical(request).getBytes(StandardCharsets.UTF_8));
            return verifier.verify(signatureBytes);
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public byte[] aesGcmSeal(byte[] key, byte[] plaintext, byte[] associatedData) throws Exception {
        byte[] nonce = new byte[12];
        RNG.nextBytes(nonce);
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, nonce));
        if (associatedData != null && associatedData.length > 0) cipher.updateAAD(associatedData);
        byte[] ct = cipher.doFinal(plaintext);
        return ByteBuffer.allocate(nonce.length + ct.length).put(nonce).put(ct).array();
    }

    @Override
    public byte[] aesGcmOpen(byte[] key, byte[] wireFormat, byte[] associatedData) throws Exception {
        byte[] nonce = new byte[12];
        System.arraycopy(wireFormat, 0, nonce, 0, 12);
        byte[] ct = new byte[wireFormat.length - 12];
        System.arraycopy(wireFormat, 12, ct, 0, ct.length);
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, nonce));
        if (associatedData != null && associatedData.length > 0) cipher.updateAAD(associatedData);
        return cipher.doFinal(ct);
    }

    @Override
    public EcdheSessionHandle generateEcdheSession() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("X25519");
            generator.initialize(NamedParameterSpec.X25519);
            var pair = generator.generateKeyPair();
            return new EcdheSessionHandle() {
                @Override
                public String publicKeyBase64Url() {
                    byte[] encoded = pair.getPublic().getEncoded();
                    byte[] raw = new byte[32];
                    System.arraycopy(encoded, encoded.length - 32, raw, 0, 32);
                    return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
                }

                @Override
                public byte[] deriveSessionKey(String clientPublicKeyBase64Url, String sessionIdSalt, String contextInfo) {
                    throw new UnsupportedOperationException("Not needed in common unit tests");
                }
            };
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public String fingerprint(byte[] key) {
        return sha256Hex(key).substring(0, 12);
    }

    private String hmac(byte[] secret, String canonical) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            byte[] sig = mac.doFinal(canonical.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(sig);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
