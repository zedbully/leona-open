/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.api;

/** Request body for {@code POST /v1/verdict}. */
public record VerdictRequest(BoxId boxId) {}
