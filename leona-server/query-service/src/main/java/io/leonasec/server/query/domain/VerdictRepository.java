/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.query.domain;

import io.leonasec.server.common.api.BoxId;
import io.leonasec.server.common.api.VerdictResponse;

import java.time.Instant;
import java.util.Optional;

/**
 * Load a previously-stored verdict by BoxId. In v0.1.0-alpha.1 the worker
 * has not yet computed a real risk score; we return a skeleton verdict so
 * the end-to-end flow works.
 */
public interface VerdictRepository {

    /** Load the verdict and stamp {@code usedAt} on the returned object. */
    Optional<VerdictResponse> load(BoxId id, Instant usedAt);
}
