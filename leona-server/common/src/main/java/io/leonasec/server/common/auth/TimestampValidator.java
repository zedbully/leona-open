/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.auth;

import java.time.Clock;
import java.time.Duration;

/**
 * Validates that a request timestamp is within acceptable clock skew of the
 * server.
 *
 * <p>Tighter than you might expect — we allow ±5 minutes which is the maximum
 * tolerable for an app with reasonable NTP. Attackers who control the device
 * clock can fake fresh timestamps, but that only lets them replay within this
 * window, which the nonce cache still catches.
 */
public class TimestampValidator {

    private static final Duration DEFAULT_SKEW = Duration.ofMinutes(5);

    private final Clock clock;
    private final Duration maxSkew;

    public TimestampValidator() {
        this(Clock.systemUTC(), DEFAULT_SKEW);
    }

    public TimestampValidator(Clock clock, Duration maxSkew) {
        this.clock = clock;
        this.maxSkew = maxSkew;
    }

    /** True if the provided {@code epochMillis} is within {@link #maxSkew} of now. */
    public boolean isAcceptable(long epochMillis) {
        long now = clock.millis();
        long delta = Math.abs(now - epochMillis);
        return delta <= maxSkew.toMillis();
    }
}
