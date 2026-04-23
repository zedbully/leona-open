/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.util;

import com.github.f4b6a3.ulid.UlidCreator;

/** Generates correlation ids for the {@code X-Request-Id} response header. */
public final class RequestIds {

    public static final String HEADER = "X-Request-Id";

    private RequestIds() {}

    public static String newId() {
        return UlidCreator.getUlid().toString();
    }
}
