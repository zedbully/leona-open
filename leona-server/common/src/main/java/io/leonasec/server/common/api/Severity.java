/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.api;

/** Severity ordinal for detection events. Must match the Android SDK's Kotlin enum. */
public enum Severity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;

    public boolean atLeast(Severity other) {
        return ordinal() >= other.ordinal();
    }
}
