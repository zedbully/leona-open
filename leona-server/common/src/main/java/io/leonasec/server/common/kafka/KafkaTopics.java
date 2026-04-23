/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.kafka;

/** Stable topic names shared by producer + consumer services. */
public final class KafkaTopics {

    /** Every minted BoxId's parsed event list lands here. */
    public static final String EVENTS_PARSED = "leona.events.parsed";

    /** Dead-letter for payloads the parser rejected. */
    public static final String EVENTS_DLQ = "leona.events.dlq";

    private KafkaTopics() {}
}
