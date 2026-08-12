package io.leonasec.wrapper;

import java.util.LinkedHashMap;
import java.util.Map;

public final class LeonaServerClientSelfTest {
    public static void main(String[] args) {
        LeonaServerClient.SignedRequest signed = LeonaServerClient.buildSignedRequest(
            "test_secret_do_not_use",
            "POST",
            "/v1/verdict",
            "{\"boxId\":\"box_test_000000000000000000\"}",
            "1700000000000",
            "nonce_for_dry_run"
        );
        assertEquals(
            "c7aba2a73265ed90feeaa0eb8d8b35591dbc157e15ac1122b6bec17d00da430d",
            signed.bodySha256,
            "bodySha256"
        );
        assertEquals(
            "xm_a5DaT482f2Nv_hewtgbB3cm43eg2-wopU4AxH928",
            signed.signature,
            "signature"
        );

        Map<String, Object> input = new LinkedHashMap<>();
        input.put("secretKey", "test_secret_do_not_use");
        input.put("note", "seen box_test_000000000000000000");
        @SuppressWarnings("unchecked")
        Map<String, Object> redacted = (Map<String, Object>) LeonaServerClient.redact(input);
        assertEquals("[redacted]", (String) redacted.get("secretKey"), "redacted secret");
        assertEquals("seen [redacted-box-id]", (String) redacted.get("note"), "redacted box");
        System.out.println("LeonaServerClient self-test passed");
    }

    private static void assertEquals(String expected, String actual, String name) {
        if (!expected.equals(actual)) {
            throw new AssertionError(name + " mismatch: expected " + expected + " but got " + actual);
        }
    }
}
