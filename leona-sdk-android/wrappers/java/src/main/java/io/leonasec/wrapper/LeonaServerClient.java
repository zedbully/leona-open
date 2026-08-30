package io.leonasec.wrapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Evidence-only client facade for a customer-owned Leo backend transport.
 *
 * <p>This class deliberately has no HTTP client, SecretKey, plaintext
 * fallback, or HMAC request path. The supplied transport must pass the logical
 * method, route, headers, and body through the paired Leo provider, send only
 * the provider's encrypted envelope over HTTPS, and open the response before
 * returning it. Constructing this client without that transport is rejected.</p>
 */
public final class LeonaServerClient implements AutoCloseable {
    private static final int MAX_TEXT_BYTES = 4096;
    private static final int MAX_BODY_BYTES = 8 * 1024 * 1024;
    private static final Pattern BOX_ID_PATTERN = Pattern.compile(
        "\\b(?:01[A-Z0-9]{10,}|box_[A-Za-z0-9_-]{8,})\\b"
    );
    private static final Pattern SENSITIVE_KEY_PATTERN = Pattern.compile(
        "(authorization|secret|token|signature|credential|deviceid|installid|androidid|serial|rawboxid|rawappkey|appkeysecret)",
        Pattern.CASE_INSENSITIVE
    );

    private final LeoCryptoBackendTransport transport;

    public LeonaServerClient(LeoCryptoBackendTransport transport) {
        if (transport == null) {
            throw new IllegalArgumentException("Leo crypto backend transport is required");
        }
        this.transport = transport;
    }

    public String verdict(String boxId) throws IOException, InterruptedException {
        return send("POST", "/v1/verdict", "{\"boxId\":\"" + escapeJson(boxId) + "\"}");
    }

    public String evidenceReport(String boxId) throws IOException, InterruptedException {
        return send("GET", "/v1/internal/private/evidence-reports/" + urlPath(boxId), "");
    }

    public String supportBundle(String boxId) throws IOException, InterruptedException {
        return send(
            "GET",
            "/v1/internal/private/evidence-reports/" + urlPath(boxId) + "/support-bundle",
            ""
        );
    }

    public String submitFeedback(String jsonBody) throws IOException, InterruptedException {
        return send("POST", "/v1/internal/private/evidence-feedback", jsonBody);
    }

    /** A caller-owned Leo transport; no implementation is shipped here. */
    public interface LeoCryptoBackendTransport extends AutoCloseable {
        /**
         * Seal every logical field with Leo, perform the HTTPS exchange, open
         * the authenticated response, and return only the opened result.
         */
        LeoResponse execute(LeoRequest request) throws IOException, InterruptedException;

        @Override
        default void close() {}
    }

    /** Logical request handed to the external Leo provider before wire sealing. */
    public static final class LeoRequest {
        public final String method;
        public final String path;
        public final String contentType;
        public final Map<String, String> protectedHeaders;
        public final byte[] body;

        public LeoRequest(
            String method,
            String path,
            String contentType,
            Map<String, String> protectedHeaders,
            byte[] body
        ) {
            this.method = boundedRequired(method, "method").toUpperCase(Locale.ROOT);
            this.path = boundedRequired(path, "path");
            if (!this.path.startsWith("/") || this.path.indexOf('?') >= 0 || this.path.indexOf('#') >= 0) {
                throw new IllegalArgumentException("path must be an absolute logical route without query or fragment");
            }
            this.contentType = boundedRequired(contentType, "contentType");
            if (protectedHeaders == null) {
                throw new IllegalArgumentException("protectedHeaders is required");
            }
            this.protectedHeaders = Collections.unmodifiableMap(new LinkedHashMap<>(protectedHeaders));
            if (body == null || body.length > MAX_BODY_BYTES) {
                throw new IllegalArgumentException("body exceeds input limit");
            }
            this.body = body.clone();
        }
    }

    /** Response already authenticated and opened by the Leo provider. */
    public static final class LeoResponse {
        public final int statusCode;
        public final byte[] body;

        public LeoResponse(int statusCode, byte[] body) {
            if (statusCode < 100 || statusCode > 599) {
                throw new IllegalArgumentException("invalid response status");
            }
            if (body == null || body.length > MAX_BODY_BYTES) {
                throw new IllegalArgumentException("response body exceeds input limit");
            }
            this.statusCode = statusCode;
            this.body = body.clone();
        }
    }

    private String send(String method, String path, String body)
        throws IOException, InterruptedException {
        String requestBody = body == null ? "" : body;
        LeoResponse response = transport.execute(
            new LeoRequest(
                method,
                path,
                "application/json",
                Collections.emptyMap(),
                requestBody.getBytes(StandardCharsets.UTF_8)
            )
        );
        if (response == null) {
            throw new IOException("Leo transport returned no response");
        }
        if (response.statusCode < 200 || response.statusCode >= 300) {
            throw new IOException("Leona request failed after authenticated Leo response: HTTP " + response.statusCode);
        }
        return new String(response.body, StandardCharsets.UTF_8);
    }

    private static String boundedRequired(String value, String name) {
        if (value == null || value.isBlank() || value.getBytes(StandardCharsets.UTF_8).length > MAX_TEXT_BYTES) {
            throw new IllegalArgumentException(name + " is required or exceeds input limit");
        }
        return value;
    }

    public static Object redact(Object value) {
        if (value == null) return null;
        if (value instanceof String) {
            return BOX_ID_PATTERN.matcher((String) value).replaceAll("[redacted-box-id]");
        }
        if (value instanceof Map<?, ?>) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                String key = String.valueOf(entry.getKey());
                out.put(
                    key,
                    SENSITIVE_KEY_PATTERN.matcher(key).find()
                        ? "[redacted]"
                        : redact(entry.getValue())
                );
            }
            return out;
        }
        return value;
    }

    @Override
    public void close() throws Exception {
        transport.close();
    }

    private static String urlPath(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("boxId is required");
        }
        return value.replace(" ", "%20").replace("/", "%2F");
    }

    private static String escapeJson(String value) {
        if (value == null) return "";
        StringBuilder out = new StringBuilder(value.length() + 8);
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '\\': out.append("\\\\"); break;
                case '"': out.append("\\\""); break;
                case '\b': out.append("\\b"); break;
                case '\f': out.append("\\f"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (character < 0x20) {
                        out.append(String.format("\\u%04x", (int) character));
                    } else {
                        out.append(character);
                    }
            }
        }
        return out.toString();
    }
}
