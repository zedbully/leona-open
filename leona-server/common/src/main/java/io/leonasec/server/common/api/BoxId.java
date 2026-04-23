/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.api;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.github.f4b6a3.ulid.Ulid;
import com.github.f4b6a3.ulid.UlidCreator;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * An opaque identifier for a detection payload, minted by ingestion.
 *
 * <p>Internally a ULID (26 chars, Crockford base32, time-sortable,
 * 80 bits of entropy). The format is <strong>not</strong> part of the
 * contract — clients treat the string opaquely. Leona internals may
 * reason about its prefix for routing.
 */
public record BoxId(String value) {

    private static final Pattern ULID_PATTERN =
        Pattern.compile("^[0-9A-HJKMNP-TV-Z]{26}$");

    public BoxId {
        Objects.requireNonNull(value, "BoxId value must not be null");
        if (!ULID_PATTERN.matcher(value).matches()) {
            throw new IllegalArgumentException("BoxId is not a valid ULID: " + value);
        }
    }

    /** Generate a new BoxId with current timestamp. */
    public static BoxId generate() {
        return new BoxId(UlidCreator.getUlid().toString());
    }

    /** Parse a raw string into a BoxId. Throws if format is wrong. */
    @JsonCreator(mode = JsonCreator.Mode.DELEGATING)
    public static BoxId of(String raw) {
        return new BoxId(raw);
    }

    /** Extract the creation timestamp encoded in the ULID prefix. */
    public long createdAtEpochMillis() {
        return Ulid.from(value).getTime();
    }

    @JsonValue
    @Override
    public String toString() {
        return value;
    }
}
