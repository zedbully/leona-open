/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.wrapper;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Stable server-side transport boundary for the optional Leo crypto facade.
 *
 * <p>This class owns only the public envelope contract. A customer-owned
 * {@link Engine} must bind the decoded request to the Leo C server SDK (or an
 * equivalent private service). The customer server, not the Android client,
 * derives {@link ServerScope} and owns all key material.</p>
 */
public final class LeonaCryptoServerTransport {
    public static final String CONTENT_TYPE = "application/vnd.leona.crypto.v1+octet-stream";
    public static final int PROTOCOL_MAJOR = 1;
    public static final int MAX_TOTAL_BYTES = 8 * 1024 * 1024;
    public static final int MAX_ASSERTION_BYTES = 1024 * 1024;
    private static final int MAX_TEXT_BYTES = 4096;
    private static final int MAX_FORMAT_BYTES = 128;
    private static final int MAX_CHALLENGE_BYTES = 4096;
    private static final byte REQUEST_KIND = 1;
    private static final byte RESPONSE_KIND = 2;
    private static final byte[] MAGIC = "LEONA-CRYPTO".getBytes(StandardCharsets.US_ASCII);

    private LeonaCryptoServerTransport() {}

    /** Customer backend binding to the external Leo server SDK. */
    public interface Engine extends AutoCloseable {
        OpenedRequest open(SealedRequest request, ServerScope scope, long nowMs)
            throws CryptoException;

        SealedResponse seal(HttpResponse response, ServerScope scope, long nowMs)
            throws CryptoException;

        @Override
        default void close() {}
    }

    /** A server-derived scope; values are never decoded from the client envelope. */
    public static final class ServerScope {
        public final byte[] deployment;
        public final byte[] tenant;
        public final byte[] policy;

        public ServerScope(byte[] deployment, byte[] tenant, byte[] policy) {
            this.deployment = exact32(deployment, "deployment");
            this.tenant = exact32(tenant, "tenant");
            this.policy = exact32(policy, "policy");
        }
    }

    public static final class AssertionContext {
        public final String format;
        public final String audience;
        public final byte[] challenge;
        public final long issuedAtMs;
        public final long expiresAtMs;

        public AssertionContext(
            String format,
            String audience,
            byte[] challenge,
            long issuedAtMs,
            long expiresAtMs
        ) {
            if (format == null || format.isBlank() || utf8Size(format) > MAX_FORMAT_BYTES) {
                throw new IllegalArgumentException("invalid assertion format");
            }
            if (audience == null || audience.isBlank() || utf8Size(audience) > MAX_TEXT_BYTES) {
                throw new IllegalArgumentException("invalid assertion audience");
            }
            if (challenge == null || challenge.length == 0 || challenge.length > MAX_CHALLENGE_BYTES) {
                throw new IllegalArgumentException("invalid assertion challenge");
            }
            if (issuedAtMs < 0 || expiresAtMs <= issuedAtMs) {
                throw new IllegalArgumentException("invalid assertion lifetime");
            }
            this.format = format;
            this.audience = audience;
            this.challenge = challenge.clone();
            this.issuedAtMs = issuedAtMs;
            this.expiresAtMs = expiresAtMs;
        }
    }

    public static final class AssertionEnvelope {
        public final AssertionContext context;
        public final byte[] contextDigest;
        public final byte[] assertion;

        public AssertionEnvelope(AssertionContext context, byte[] contextDigest, byte[] assertion) {
            if (context == null) throw new IllegalArgumentException("context is required");
            this.contextDigest = exact32(contextDigest, "contextDigest");
            if (assertion == null || assertion.length == 0 || assertion.length > MAX_ASSERTION_BYTES) {
                throw new IllegalArgumentException("invalid assertion");
            }
            this.context = context;
            this.assertion = assertion.clone();
        }
    }

    public static final class SealedRequest {
        public final byte[] encryptedWire;
        public final AssertionEnvelope assertionEnvelope;

        public SealedRequest(byte[] encryptedWire, AssertionEnvelope assertionEnvelope) {
            if (encryptedWire == null || encryptedWire.length == 0) {
                throw new IllegalArgumentException("encryptedWire is required");
            }
            if (assertionEnvelope == null) throw new IllegalArgumentException("assertionEnvelope is required");
            if ((long) encryptedWire.length + assertionEnvelope.assertion.length > MAX_TOTAL_BYTES) {
                throw new IllegalArgumentException("request exceeds input limit");
            }
            this.encryptedWire = encryptedWire.clone();
            this.assertionEnvelope = assertionEnvelope;
        }
    }

    public static final class OpenedRequest {
        public final String method;
        public final String authority;
        public final String path;
        public final String query;
        public final String contentType;
        public final byte[] protectedHeaders;
        public final byte[] body;

        public OpenedRequest(
            String method,
            String authority,
            String path,
            String query,
            String contentType,
            byte[] protectedHeaders,
            byte[] body
        ) {
            this.method = requiredText(method, "method");
            this.authority = requiredText(authority, "authority");
            this.path = requiredText(path, "path");
            this.query = boundedText(query == null ? "" : query, "query");
            this.contentType = boundedText(contentType == null ? "" : contentType, "contentType");
            this.protectedHeaders = boundedBytes(protectedHeaders, "protectedHeaders");
            this.body = boundedBytes(body, "body");
            if ((long) this.protectedHeaders.length + this.body.length > MAX_TOTAL_BYTES) {
                throw new IllegalArgumentException("opened request exceeds input limit");
            }
        }
    }

    public static final class HttpResponse {
        public final int statusCode;
        public final byte[] protectedHeaders;
        public final byte[] body;

        public HttpResponse(int statusCode, byte[] protectedHeaders, byte[] body) {
            if (statusCode < 100 || statusCode > 599) {
                throw new IllegalArgumentException("invalid response status");
            }
            this.statusCode = statusCode;
            this.protectedHeaders = boundedBytes(protectedHeaders, "protectedHeaders");
            this.body = boundedBytes(body, "body");
            if ((long) this.protectedHeaders.length + this.body.length > MAX_TOTAL_BYTES) {
                throw new IllegalArgumentException("response exceeds input limit");
            }
        }
    }

    public static final class SealedResponse {
        public final byte[] encryptedWire;

        public SealedResponse(byte[] encryptedWire) {
            if (encryptedWire == null || encryptedWire.length == 0 || encryptedWire.length > MAX_TOTAL_BYTES) {
                throw new IllegalArgumentException("invalid encrypted response wire");
            }
            this.encryptedWire = encryptedWire.clone();
        }
    }

    public static final class CryptoException extends Exception {
        public CryptoException(String message) {
            super(message);
        }

        public CryptoException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** Decode the public envelope, then delegate authenticated opening to the customer engine. */
    public static OpenedRequest open(
        byte[] encodedRequest,
        Engine engine,
        ServerScope serverScope,
        long nowMs
    ) throws CryptoException {
        if (engine == null || serverScope == null || nowMs < 0) {
            throw new IllegalArgumentException("engine, scope, and nonnegative time are required");
        }
        return engine.open(decodeRequest(encodedRequest), serverScope, nowMs);
    }

    /** Delegate authenticated response sealing, then encode only the response wire. */
    public static byte[] seal(
        HttpResponse response,
        Engine engine,
        ServerScope serverScope,
        long nowMs
    ) throws CryptoException {
        if (response == null || engine == null || serverScope == null || nowMs < 0) {
            throw new IllegalArgumentException("response, engine, scope, and nonnegative time are required");
        }
        return encodeResponse(engine.seal(response, serverScope, nowMs));
    }

    public static SealedRequest decodeRequest(byte[] encoded) {
        Reader reader = new Reader(encoded);
        reader.header(REQUEST_KIND);
        byte[] wire = reader.bytes(MAX_TOTAL_BYTES, true);
        AssertionContext context = new AssertionContext(
            reader.text(MAX_FORMAT_BYTES, true),
            reader.text(MAX_TEXT_BYTES, true),
            reader.bytes(MAX_CHALLENGE_BYTES, true),
            reader.longValue(),
            reader.longValue()
        );
        byte[] digest = reader.fixed(32);
        byte[] assertion = reader.bytes(MAX_ASSERTION_BYTES, true);
        reader.finish();
        return new SealedRequest(wire, new AssertionEnvelope(context, digest, assertion));
    }

    public static byte[] encodeResponse(SealedResponse response) {
        if (response == null) throw new IllegalArgumentException("response is required");
        Writer writer = new Writer();
        writer.header(RESPONSE_KIND);
        // A response envelope carries only the encrypted wire. The status and
        // protected headers are inside the authenticated Leo response payload.
        writer.bytes(response.encryptedWire, MAX_TOTAL_BYTES);
        return writer.finish();
    }

    public static SealedResponse decodeResponse(byte[] encoded) {
        Reader reader = new Reader(encoded);
        reader.header(RESPONSE_KIND);
        byte[] wire = reader.bytes(MAX_TOTAL_BYTES, true);
        reader.finish();
        return new SealedResponse(wire);
    }

    public static byte[] encodeRequest(SealedRequest request) {
        if (request == null) throw new IllegalArgumentException("request is required");
        Writer writer = new Writer();
        writer.header(REQUEST_KIND);
        writer.bytes(request.encryptedWire, MAX_TOTAL_BYTES);
        AssertionContext context = request.assertionEnvelope.context;
        writer.text(context.format, MAX_FORMAT_BYTES);
        writer.text(context.audience, MAX_TEXT_BYTES);
        writer.bytes(context.challenge, MAX_CHALLENGE_BYTES);
        writer.longValue(context.issuedAtMs);
        writer.longValue(context.expiresAtMs);
        writer.fixed(request.assertionEnvelope.contextDigest, 32);
        writer.bytes(request.assertionEnvelope.assertion, MAX_ASSERTION_BYTES);
        return writer.finish();
    }

    private static byte[] exact32(byte[] value, String name) {
        if (value == null || value.length != 32) throw new IllegalArgumentException(name + " must be 32 bytes");
        return value.clone();
    }

    private static String requiredText(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " is required");
        return boundedText(value, name);
    }

    private static String boundedText(String value, String name) {
        if (value == null || utf8Size(value) > MAX_TEXT_BYTES) {
            throw new IllegalArgumentException(name + " exceeds input limit");
        }
        return value;
    }

    private static byte[] boundedBytes(byte[] value, String name) {
        if (value == null) throw new IllegalArgumentException(name + " is required");
        if (value.length > MAX_TOTAL_BYTES) throw new IllegalArgumentException(name + " exceeds input limit");
        return value.clone();
    }

    private static int utf8Size(String value) {
        return value.getBytes(StandardCharsets.UTF_8).length;
    }

    private static final class Writer {
        private final ByteArrayOutputStream output = new ByteArrayOutputStream();

        void header(byte kind) {
            output.writeBytes(MAGIC);
            output.write(PROTOCOL_MAJOR);
            output.write(kind);
            output.write(0);
            output.write(0);
        }

        void text(String value, int maxBytes) {
            bytes(value.getBytes(StandardCharsets.UTF_8), maxBytes);
        }

        void bytes(byte[] value, int maxBytes) {
            if (value == null || value.length > maxBytes) throw new IllegalArgumentException("field exceeds input limit");
            intValue(value.length);
            output.writeBytes(value);
        }

        void fixed(byte[] value, int expectedBytes) {
            if (value == null || value.length != expectedBytes) throw new IllegalArgumentException("fixed field has wrong length");
            output.writeBytes(value);
        }

        void intValue(int value) {
            output.write((value >>> 24) & 0xff);
            output.write((value >>> 16) & 0xff);
            output.write((value >>> 8) & 0xff);
            output.write(value & 0xff);
        }

        void longValue(long value) {
            byte[] encoded = ByteBuffer.allocate(Long.BYTES).order(ByteOrder.BIG_ENDIAN).putLong(value).array();
            output.writeBytes(encoded);
        }

        byte[] finish() {
            byte[] result = output.toByteArray();
            if (result.length > MAX_TOTAL_BYTES) throw new IllegalArgumentException("envelope exceeds input limit");
            return result;
        }
    }

    private static final class Reader {
        private final byte[] encoded;
        private int offset;

        Reader(byte[] encoded) {
            if (encoded == null || encoded.length > MAX_TOTAL_BYTES) throw new IllegalArgumentException("invalid envelope");
            this.encoded = encoded;
        }

        void header(byte expectedKind) {
            if (!Arrays.equals(read(MAGIC.length), MAGIC)) throw new IllegalArgumentException("invalid envelope magic");
            if (u8() != PROTOCOL_MAJOR) throw new IllegalArgumentException("unsupported envelope version");
            if (u8() != (expectedKind & 0xff)) throw new IllegalArgumentException("unexpected envelope kind");
            if (u8() != 0 || u8() != 0) throw new IllegalArgumentException("invalid envelope flags");
        }

        String text(int maxBytes, boolean required) {
            byte[] value = bytes(maxBytes, required);
            String decoded;
            try {
                decoded = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(value))
                    .toString();
            } catch (CharacterCodingException error) {
                throw new IllegalArgumentException("invalid UTF-8", error);
            }
            if (required && decoded.isBlank()) throw new IllegalArgumentException("required text is blank");
            return decoded;
        }

        byte[] bytes(int maxBytes, boolean required) {
            int length = intValue();
            if (length < 0 || length > maxBytes) throw new IllegalArgumentException("field exceeds input limit");
            if (required && length == 0) throw new IllegalArgumentException("required bytes are empty");
            return read(length);
        }

        byte[] fixed(int expectedBytes) {
            return read(expectedBytes);
        }

        int intValue() {
            byte[] value = read(4);
            return ((value[0] & 0xff) << 24)
                | ((value[1] & 0xff) << 16)
                | ((value[2] & 0xff) << 8)
                | (value[3] & 0xff);
        }

        long longValue() {
            return ByteBuffer.wrap(read(Long.BYTES)).order(ByteOrder.BIG_ENDIAN).getLong();
        }

        void finish() {
            if (offset != encoded.length) throw new IllegalArgumentException("trailing envelope bytes");
        }

        private int u8() {
            return read(1)[0] & 0xff;
        }

        private byte[] read(int length) {
            if (length < 0 || encoded.length - offset < length) throw new IllegalArgumentException("truncated envelope");
            byte[] value = Arrays.copyOfRange(encoded, offset, offset + length);
            offset += length;
            return value;
        }
    }
}
