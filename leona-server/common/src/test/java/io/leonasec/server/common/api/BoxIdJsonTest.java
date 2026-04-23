/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class BoxIdJsonTest {

    private final ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());

    @Test
    void serializesAsPlainString() throws Exception {
        BoxId boxId = BoxId.generate();

        String json = mapper.writeValueAsString(boxId);

        assertEquals('"' + boxId.value() + '"', json);
    }

    @Test
    void deserializesFromPlainString() throws Exception {
        BoxId boxId = BoxId.generate();

        BoxId decoded = mapper.readValue('"' + boxId.value() + '"', BoxId.class);

        assertEquals(boxId, decoded);
    }
}
