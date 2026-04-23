/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.auth;

/**
 * Authenticated context set by the gateway and propagated downstream via
 * headers. Downstream services trust this because the cluster
 * {@code NetworkPolicy} forbids direct traffic.
 *
 * <p>Header names are the public contract between the gateway and
 * downstream services. Change them and you break the network protocol
 * between our own services.
 */
public final class RequestPrincipal {

    public static final String HEADER_TENANT = "X-Leona-Tenant";
    public static final String HEADER_APP_KEY = "X-Leona-App-Key";
    public static final String HEADER_ROLE = "X-Leona-Role";
    public static final String HEADER_VERIFIED = "X-Leona-Request-Verified";

    private RequestPrincipal() {}
}
