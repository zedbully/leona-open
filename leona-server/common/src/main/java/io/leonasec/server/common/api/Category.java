/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.api;

/** Coarse grouping of detection events for routing and dashboards. */
public enum Category {
    INJECTION,
    ENVIRONMENT,
    UNIDBG,
    TAMPERING,
    HONEYPOT_TRIPPED,
    NETWORK,
    OTHER,
}
