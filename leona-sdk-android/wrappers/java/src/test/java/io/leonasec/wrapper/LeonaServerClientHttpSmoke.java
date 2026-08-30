package io.leonasec.wrapper;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Verifies that the server facade only calls a caller-owned Leo transport.
 * The provider/HTTPS implementation is intentionally external to this public
 * skeleton; this test does not pretend to prove provider cryptography.
 */
public final class LeonaServerClientHttpSmoke {
    private static final String BOX_ID = "box_test_000000000000000000";

    public static void main(String[] args) throws Exception {
        assertRejectsMissingLeoTransport();
        List<String> seen = new ArrayList<>();
        RecordingTransport transport = new RecordingTransport(seen);
        LeonaServerClient client = new LeonaServerClient(transport);

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

        assertEquals("POST /v1/verdict", seen.get(0), "verdict route");
        assertEquals("GET /v1/internal/private/evidence-reports/" + BOX_ID, seen.get(1), "report route");
        assertEquals(
            "GET /v1/internal/private/evidence-reports/" + BOX_ID + "/support-bundle",
            seen.get(2),
            "bundle route"
        );
        assertEquals("POST /v1/internal/private/evidence-feedback", seen.get(3), "feedback route");
        System.out.println("LeonaServerClient Leo transport smoke passed");
    }

    private static void assertRejectsMissingLeoTransport() {
        try {
            new LeonaServerClient(null);
            throw new AssertionError("missing Leo transport must fail closed");
        } catch (IllegalArgumentException expected) {
            if (!expected.getMessage().contains("Leo")) {
                throw new AssertionError("unexpected missing transport message", expected);
            }
        }
    }

    private static final class RecordingTransport implements LeonaServerClient.LeoCryptoBackendTransport {
        private final List<String> seen;

        private RecordingTransport(List<String> seen) {
            this.seen = seen;
        }

        @Override
        public LeonaServerClient.LeoResponse execute(LeonaServerClient.LeoRequest request) {
            seen.add(request.method + " " + request.path);
            String body = new String(request.body, StandardCharsets.UTF_8);
            if ("POST".equals(request.method) && "/v1/verdict".equals(request.path)) {
                assertContains(body, "\"boxId\":\"" + BOX_ID + "\"", "verdict body");
                return response("{\"boxIdHint\":\"box_...0000\",\"evidenceOnly\":true}");
            }
            if ("GET".equals(request.method) && request.path.endsWith("/support-bundle")) {
                return response("{\"bundle\":{\"format\":\"leona.customer-support-bundle.v1\"}}");
            }
            if ("GET".equals(request.method)) {
                return response("{\"report\":{\"boxIdHint\":\"box_...0000\"}}");
            }
            if ("POST".equals(request.method)) {
                assertContains(body, "\"label\":\"false_positive\"", "feedback body");
                return response("{\"accepted\":true}");
            }
            throw new AssertionError("unexpected logical request: " + request.method + " " + request.path);
        }

        private static LeonaServerClient.LeoResponse response(String body) {
            return new LeonaServerClient.LeoResponse(200, body.getBytes(StandardCharsets.UTF_8));
        }
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
