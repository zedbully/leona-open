/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.auth;

import java.time.Duration;

/**
 * A once-and-only-once nonce store. Each service wires up a Redis-backed
 * implementation so nonce tracking is shared across replicas.
 *
 * <p>The contract: {@link #claimOrReject(String, Duration)} atomically returns
 * {@code true} the first time a nonce is seen and {@code false} on every
 * replay within the TTL window.
 */
public interface ReplayGuard {

    /** The default window during which a nonce is remembered. */
    Duration DEFAULT_TTL = Duration.ofHours(1);

    /**
     * Atomically claim the nonce. If this returns {@code false} the caller
     * must reject the request with {@link io.leonasec.server.common.error.ErrorCode#LEONA_NONCE_REPLAY}.
     */
    boolean claimOrReject(String nonce, Duration ttl);

    default boolean claimOrReject(String nonce) {
        return claimOrReject(nonce, DEFAULT_TTL);
    }
}
