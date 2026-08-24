package io.leonasec.wrapper;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

public final class LeonaServerClientHttpSmoke {
    private static final String SECRET = "test_secret_do_not_use";
    private static final String BOX_ID = "box_test_000000000000000000";

    public static void main(String[] args) throws Exception {
        assertRejectsRemotePlaintextBaseUrl();
        List<String> seen = new ArrayList<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> handle(exchange, seen));
        server.start();
        try {
            String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
            LeonaServerClient client = new LeonaServerClient(
                baseUrl,
                SECRET,
                java.net.http.HttpClient.newHttpClient(),
                Duration.ofSeconds(5)
            );

            assertContains(client.verdict(BOX_ID), "\"evidenceOnly\":true", "verdict response");
            assertContains(client.evidenceReport(BOX_ID), "\"boxIdHint\":\"box_...0000\"", "report response");
            assertContains(
                client.supportBundle(BOX_ID),
                "\"format\":\"leona.customer-support-bundle.v1\"",
                "bundle response"
            );
            assertContains(
                client.submitFeedback(
                    "{\"boxId\":\"" + BOX_ID + "\",\"label\":\"false_positive\",\"customerReason\":\"integration smoke\"}"
                ),
                "\"accepted\":true",
                "feedback response"
            );
        } finally {
            server.stop(0);
        }

        assertEquals("POST /v1/verdict", seen.get(0), "verdict route");
        assertEquals("GET /v1/internal/private/evidence-reports/" + BOX_ID, seen.get(1), "report route");
        assertEquals(
            "GET /v1/internal/private/evidence-reports/" + BOX_ID + "/support-bundle",
            seen.get(2),
            "bundle route"
        );
        assertEquals("POST /v1/internal/private/evidence-feedback", seen.get(3), "feedback route");
        System.out.println("LeonaServerClient HTTP smoke passed");
    }

    private static void assertRejectsRemotePlaintextBaseUrl() {
        try {
            new LeonaServerClient("http://example.invalid", SECRET);
            throw new AssertionError("remote plaintext baseUrl must be rejected");
        } catch (IllegalArgumentException expected) {
            if (!expected.getMessage().contains("HTTPS")) {
                throw new AssertionError("unexpected baseUrl validation message", expected);
            }
        }
    }

    private static void handle(HttpExchange exchange, List<String> seen) throws IOException {
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        try {
            verifySignedRequest(exchange, body);
            seen.add(exchange.getRequestMethod() + " " + exchange.getRequestURI().getRawPath());

            String method = exchange.getRequestMethod();
            String path = exchange.getRequestURI().getRawPath();
            if ("POST".equals(method) && "/v1/verdict".equals(path)) {
                assertContains(body, "\"boxId\":\"" + BOX_ID + "\"", "verdict body");
                writeJson(exchange, 200, "{\"boxIdHint\":\"box_...0000\",\"evidenceOnly\":true}");
                return;
            }
            if ("GET".equals(method) && ("/v1/internal/private/evidence-reports/" + BOX_ID).equals(path)) {
                writeJson(exchange, 200, "{\"report\":{\"boxIdHint\":\"box_...0000\"}}");
                return;
            }
            if (
                "GET".equals(method) &&
                ("/v1/internal/private/evidence-reports/" + BOX_ID + "/support-bundle").equals(path)
            ) {
                writeJson(exchange, 200, "{\"bundle\":{\"format\":\"leona.customer-support-bundle.v1\"}}");
                return;
            }
            if ("POST".equals(method) && "/v1/internal/private/evidence-feedback".equals(path)) {
                assertContains(body, "\"label\":\"false_positive\"", "feedback body");
                writeJson(exchange, 200, "{\"accepted\":true}");
                return;
            }

            writeJson(exchange, 404, "{\"error\":\"not found\"}");
        } catch (RuntimeException error) {
            writeJson(exchange, 500, "{\"error\":\"" + error.getMessage().replace("\"", "'") + "\"}");
        }
    }

    private static void verifySignedRequest(HttpExchange exchange, String body) {
        String timestamp = header(exchange, "X-Leona-Timestamp");
        String nonce = header(exchange, "X-Leona-Nonce");
        LeonaServerClient.SignedRequest expected = LeonaServerClient.buildSignedRequest(
            SECRET,
            exchange.getRequestMethod(),
            exchange.getRequestURI().getRawPath(),
            body,
            timestamp,
            nonce
        );
        assertEquals("Bearer " + SECRET, header(exchange, "Authorization"), "authorization");
        assertEquals("application/json", header(exchange, "Content-Type"), "content type");
        assertEquals(expected.signature, header(exchange, "X-Leona-Signature"), "signature");
    }

    private static String header(HttpExchange exchange, String name) {
        String value = exchange.getRequestHeaders().getFirst(name);
        if (value == null || value.isBlank()) {
            throw new AssertionError("missing header: " + name);
        }
        return value;
    }

    private static void writeJson(HttpExchange exchange, int status, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private static void assertContains(String value, String expectedPart, String name) {
        if (!value.contains(expectedPart)) {
            throw new AssertionError(name + " missing " + expectedPart + " in " + value);
        }
    }

    private static void assertEquals(String expected, String actual, String name) {
        if (!expected.equals(actual)) {
            throw new AssertionError(name + " mismatch: expected " + expected + " but got " + actual);
        }
    }
}
