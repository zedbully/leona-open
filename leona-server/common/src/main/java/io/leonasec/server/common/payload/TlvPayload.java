/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.payload;

import io.leonasec.server.common.api.Category;
import io.leonasec.server.common.api.DetectionEvent;
import io.leonasec.server.common.api.Severity;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Parser for the binary TLV format produced by the SDK's native
 * {@code report/collector.cpp}.
 *
 * <p>Format (after the native XOR scramble has been removed):
 *
 * <pre>
 *   magic       "LNA1" (4 bytes)
 *   version     (1 byte, currently 0x01)
 *   flags       (1 byte, reserved, currently 0x00)
 *   event_count (u16 little-endian)
 *   events[count]:
 *     id_len        (u16 LE)
 *     id            (UTF-8 bytes)
 *     severity      (u8 — ordinal, matches DetectionSeverity in Kotlin)
 *     category_code (u8 — 1=injection, 2=environment, 3=unidbg)
 *     msg_len       (u16 LE)
 *     msg           (UTF-8 bytes)
 *     evidence_len  (u16 LE)
 *     evidence      ("k1=v1;k2=v2" ASCII bytes)
 * </pre>
 *
 * <p>The scramble step (matches {@code report/collector.cpp:scramble}):
 *
 * <pre>
 *   state = 0x5C
 *   for each byte b:
 *     b ^= state
 *     state = (state * 31 + 17) &amp; 0xFF
 * </pre>
 *
 * Self-inverse under the identical key schedule. Re-running scramble on
 * scrambled data recovers the plaintext.
 */
public final class TlvPayload {

    private static final byte[] MAGIC = {'L', 'N', 'A', '1'};
    private static final byte SUPPORTED_VERSION = 0x01;

    /** Parse a payload that is still XOR-scrambled (wire format). */
    public static List<DetectionEvent> parseScrambled(byte[] scrambled, Instant observedAt) {
        byte[] plain = unscramble(scrambled);
        return parsePlain(plain, observedAt);
    }

    /** Parse an already-unscrambled payload. Useful for tests. */
    public static List<DetectionEvent> parsePlain(byte[] bytes, Instant observedAt) {
        if (bytes.length < 8) {
            throw new IllegalArgumentException("payload too short (" + bytes.length + " bytes)");
        }
        ByteBuffer buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);

        byte[] magic = new byte[4];
        buf.get(magic);
        for (int i = 0; i < 4; i++) {
            if (magic[i] != MAGIC[i]) {
                throw new IllegalArgumentException("bad magic — payload not a Leona TLV blob");
            }
        }
        byte version = buf.get();
        if (version != SUPPORTED_VERSION) {
            throw new IllegalArgumentException("unsupported payload version: " + version);
        }
        buf.get();  // flags, reserved
        int count = Short.toUnsignedInt(buf.getShort());

        List<DetectionEvent> events = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            String id = readString(buf);
            Severity severity = Severity.values()[Byte.toUnsignedInt(buf.get())];
            Category category = categoryFromCode(Byte.toUnsignedInt(buf.get()));
            String message = readString(buf);
            String evidence = readString(buf);
            events.add(new DetectionEvent(
                id, category, severity, observedAt, parseEvidence(evidence)));
        }
        return events;
    }

    /** XOR scramble / unscramble. Self-inverse. Package-public for testing. */
    public static byte[] unscramble(byte[] in) {
        byte[] out = new byte[in.length];
        int state = 0x5C;
        for (int i = 0; i < in.length; i++) {
            out[i] = (byte) ((in[i] & 0xFF) ^ state);
            state = ((state * 31) + 17) & 0xFF;
        }
        return out;
    }

    private static String readString(ByteBuffer buf) {
        int len = Short.toUnsignedInt(buf.getShort());
        byte[] raw = new byte[len];
        buf.get(raw);
        return new String(raw, StandardCharsets.UTF_8);
    }

    private static Category categoryFromCode(int code) {
        return switch (code) {
            case 1 -> Category.INJECTION;
            case 2 -> Category.ENVIRONMENT;
            case 3 -> Category.UNIDBG;
            case 4 -> Category.TAMPERING;
            case 5 -> Category.HONEYPOT_TRIPPED;
            case 6 -> Category.NETWORK;
            default -> Category.OTHER;
        };
    }

    private static Map<String, String> parseEvidence(String kv) {
        if (kv == null || kv.isEmpty()) return Map.of();
        Map<String, String> out = new HashMap<>();
        for (String pair : kv.split(";")) {
            int eq = pair.indexOf('=');
            if (eq < 0) continue;
            out.put(pair.substring(0, eq), pair.substring(eq + 1));
        }
        return out;
    }

    private TlvPayload() {}
}
