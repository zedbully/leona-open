/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.auth;

import io.leonasec.server.common.api.HandshakeRequest;
import io.leonasec.server.common.spi.ApiCryptoProviders;

public final class DeviceBindingVerifier {

    private DeviceBindingVerifier() {}

    public static String canonical(HandshakeRequest request) {
        return ApiCryptoProviders.provider().deviceBindingCanonical(request);
    }

    public static boolean verify(HandshakeRequest request) {
        return ApiCryptoProviders.provider().verifyDeviceBinding(request);
    }
}
