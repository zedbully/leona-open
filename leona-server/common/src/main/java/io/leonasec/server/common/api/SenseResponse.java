/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.api;

import java.time.Instant;

/** Response body for {@code POST /v1/sense}. */
public record SenseResponse(BoxId boxId, Instant expiresAt) {}
