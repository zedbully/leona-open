package io.leonasec.wrapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class LeonaServerClient {
    private static final Pattern BOX_ID_PATTERN = Pattern.compile(
        "\\b(?:01[A-Z0-9]{10,}|box_[A-Za-z0-9_-]{8,})\\b"
    );
    private static final Pattern SENSITIVE_KEY_PATTERN = Pattern.compile(
        "(authorization|secret|token|signature|credential|deviceid|installid|androidid|serial|rawboxid|rawappkey|appkeysecret)",
        Pattern.CASE_INSENSITIVE
    );
    private static final SecureRandom RANDOM = new SecureRandom();

    private final String baseUrl;
    private final String secretKey;
    private final HttpClient httpClient;
    private final Duration timeout;

    public LeonaServerClient(String baseUrl, String secretKey) {
        this(baseUrl, secretKey, HttpClient.newHttpClient(), Duration.ofSeconds(5));
    }

    public LeonaServerClient(String baseUrl, String secretKey, HttpClient httpClient, Duration timeout) {
        if (baseUrl == null || baseUrl.isBlank()) {
            throw new IllegalArgumentException("baseUrl is required");
        }
        if (secretKey == null || secretKey.isBlank()) {
            throw new IllegalArgumentException("secretKey is required");
        }
        this.baseUrl = validateBaseUrl(baseUrl);
        this.secretKey = secretKey;
        this.httpClient = httpClient;
        this.timeout = timeout == null ? Duration.ofSeconds(5) : timeout;
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

    public static SignedRequest buildSignedRequest(
        String secretKey,
        String method,
        String path,
        String body,
        String timestamp,
        String nonce
    ) {
        String requestBody = body == null ? "" : body;
        String bodySha256 = sha256Hex(requestBody);
        String normalizedMethod = method.toUpperCase(java.util.Locale.ROOT);
        String signingText = "backend-v2"
            + "\n" + normalizedMethod
            + "\n" + path
            + "\n" + timestamp
            + "\n" + nonce
            + "\n" + bodySha256;
        return new SignedRequest(
            normalizedMethod,
            path,
            requestBody,
            bodySha256,
            "Bearer " + secretKey,
            timestamp,
            nonce,
            hmacSha256Base64Url(secretKey, signingText)
        );
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

    private String send(String method, String path, String body) throws IOException, InterruptedException {
        SignedRequest signed = buildSignedRequest(
            secretKey,
            method,
            path,
            body,
            Long.toString(Instant.now().toEpochMilli()),
            randomNonce()
        );
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path))
            .timeout(timeout)
            .header("Authorization", signed.authorization)
            .header("Content-Type", "application/json")
            .header("X-Leona-Timestamp", signed.timestamp)
            .header("X-Leona-Nonce", signed.nonce)
            .header("X-Leona-Signature", signed.signature);
        if ("GET".equals(method)) {
            builder.GET();
        } else {
            builder.method(method, HttpRequest.BodyPublishers.ofString(signed.body));
        }

        HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("Leona request failed: HTTP " + response.statusCode());
        }
        return response.body();
    }

    private static String sha256Hex(String text) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(text.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("sha256 failed", e);
        }
    }

    private static String hmacSha256Base64Url(String secret, String text) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(mac.doFinal(text.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("hmac failed", e);
        }
    }

    private static String randomNonce() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String stripTrailingSlash(String value) {
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    private static String validateBaseUrl(String value) {
        String normalized = stripTrailingSlash(value.trim());
        final URI uri;
        try {
            uri = URI.create(normalized);
        } catch (IllegalArgumentException error) {
            throw new IllegalArgumentException("baseUrl must be a valid absolute URL", error);
        }

        String scheme = uri.getScheme();
        boolean https = "https".equalsIgnoreCase(scheme);
        boolean loopbackHttp = "http".equalsIgnoreCase(scheme) && isLoopbackHost(uri.getHost());
        if (uri.getHost() == null || uri.getHost().isBlank()) {
            throw new IllegalArgumentException("baseUrl must include a host");
        }
        if (!https && !loopbackHttp) {
            throw new IllegalArgumentException(
                "baseUrl must use HTTPS; HTTP is only allowed for loopback test endpoints"
            );
        }
        if (uri.getUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null) {
            throw new IllegalArgumentException("baseUrl must not contain user-info, query, or fragment components");
        }
        return normalized;
    }

    private static boolean isLoopbackHost(String host) {
        return "127.0.0.1".equals(host)
            || "localhost".equalsIgnoreCase(host)
            || "::1".equals(host)
            || "[::1]".equals(host);
    }

    private static String urlPath(String value) {
        return value.replace(" ", "%20").replace("/", "%2F");
    }

    private static String escapeJson(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    public static final class SignedRequest {
        public final String method;
        public final String path;
        public final String body;
        public final String bodySha256;
        public final String authorization;
        public final String timestamp;
        public final String nonce;
        public final String signature;

        private SignedRequest(
            String method,
            String path,
            String body,
            String bodySha256,
            String authorization,
            String timestamp,
            String nonce,
            String signature
        ) {
            this.method = method;
            this.path = path;
            this.body = body;
            this.bodySha256 = bodySha256;
            this.authorization = authorization;
            this.timestamp = timestamp;
            this.nonce = nonce;
            this.signature = signature;
        }
    }
}
