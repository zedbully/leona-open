/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.ingestion.domain;

import io.leonasec.server.common.api.HandshakeRequest;

import java.lang.reflect.Method;

/**
 * Optionally bridges public ingestion code to the closed-source OEM attestation
 * verifier when that module is present on the runtime classpath.
 */
final class OemAttestationVerifiers {

    private static final String PRIVATE_VERIFIER_CLASS =
        "io.leonasec.server.privatebackend.attestation.PrivateOemAttestationVerifier";
    private static final String TEST_OVERRIDE_PROPERTY =
        "leona.handshake.attestation.oem.verifier-class";

    private static volatile OemAttestationVerifier active;

    private OemAttestationVerifiers() {}

    static OemAttestationVerifier active() {
        OemAttestationVerifier current = active;
        if (current != null) {
            return current;
        }
        synchronized (OemAttestationVerifiers.class) {
            current = active;
            if (current == null) {
                current = resolve();
                active = current;
            }
            return current;
        }
    }

    static void resetForTests() {
        active = null;
    }

    interface OemAttestationVerifier {
        DeviceAttestationVerifier.Result verify(HandshakeRequest request);
    }

    private static OemAttestationVerifier resolve() {
        try {
            Class<?> verifierClass = Class.forName(verifierClassName());
            Object verifier = verifierClass.getDeclaredConstructor().newInstance();
            Method verifyMethod = verifierClass.getMethod("verify", HandshakeRequest.class);
            return request -> toResult(invoke(verifyMethod, verifier, request));
        } catch (Throwable ignored) {
            return MissingOemAttestationVerifier.INSTANCE;
        }
    }

    private static String verifierClassName() {
        String override = System.getProperty(TEST_OVERRIDE_PROPERTY);
        return override == null || override.isBlank() ? PRIVATE_VERIFIER_CLASS : override.trim();
    }

    private static Object invoke(Method method, Object target, HandshakeRequest request) {
        try {
            return method.invoke(target, request);
        } catch (ReflectiveOperationException error) {
            throw new IllegalStateException("Failed to invoke private OEM attestation verifier", error);
        }
    }

    private static DeviceAttestationVerifier.Result toResult(Object verdict) {
        if (verdict == null) {
            return DeviceAttestationVerifier.Result.rejected(
                "attestation_verifier_failed",
                "oem_attestation",
                "OEM_ATTESTATION_VERIFIER_FAILED",
                false);
        }
        Class<?> verdictClass = verdict.getClass();
        boolean accepted = Boolean.TRUE.equals(call(verdictClass, verdict, "accepted"));
        String status = asString(call(verdictClass, verdict, "status"));
        String provider = asString(call(verdictClass, verdict, "provider"));
        String code = asString(call(verdictClass, verdict, "code"));
        Boolean retryable = asBoolean(call(verdictClass, verdict, "retryable"));
        return accepted
            ? DeviceAttestationVerifier.Result.accepted(status, provider, code, retryable)
            : DeviceAttestationVerifier.Result.rejected(status, provider, code, retryable);
    }

    private static Object call(Class<?> type, Object target, String methodName) {
        try {
            return type.getMethod(methodName).invoke(target);
        } catch (ReflectiveOperationException error) {
            throw new IllegalStateException(
                "Private OEM attestation verdict missing method: " + methodName,
                error);
        }
    }

    private static String asString(Object value) {
        return value instanceof String text ? text : null;
    }

    private static Boolean asBoolean(Object value) {
        return value instanceof Boolean flag ? flag : null;
    }

    private enum MissingOemAttestationVerifier implements OemAttestationVerifier {
        INSTANCE;

        @Override
        public DeviceAttestationVerifier.Result verify(HandshakeRequest request) {
            return DeviceAttestationVerifier.Result.rejected(
                "attestation_verifier_missing",
                "oem_attestation",
                "OEM_ATTESTATION_VERIFIER_MISSING",
                false);
        }
    }
}
