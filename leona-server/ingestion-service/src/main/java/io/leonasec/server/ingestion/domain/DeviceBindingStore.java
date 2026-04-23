/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.ingestion.domain;

import reactor.core.publisher.Mono;

import java.time.Duration;

/** Persists the installId → device public key binding. */
public interface DeviceBindingStore {
    Mono<String> load(String installId);
    Mono<Void> store(String installId, String publicKey, Duration ttl);
}
