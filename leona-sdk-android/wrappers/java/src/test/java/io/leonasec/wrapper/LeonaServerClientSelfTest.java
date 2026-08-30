package io.leonasec.wrapper;

import java.util.LinkedHashMap;
import java.util.Map;

public final class LeonaServerClientSelfTest {
    public static void main(String[] args) {
        try {
            new LeonaServerClient(null);
            throw new AssertionError("missing Leo transport must fail closed");
        } catch (IllegalArgumentException expected) {
            // Expected fail-closed result.
        }

        Map<String, Object> input = new LinkedHashMap<>();
        input.put("secretKey", "test_secret_do_not_use");
        input.put("note", "seen box_test_000000000000000000");
        @SuppressWarnings("unchecked")
        Map<String, Object> redacted = (Map<String, Object>) LeonaServerClient.redact(input);
        assertEquals("[redacted]", (String) redacted.get("secretKey"), "redacted secret");
        assertEquals("seen [redacted-box-id]", (String) redacted.get("note"), "redacted box");
        System.out.println("LeonaServerClient Leo-only self-test passed");
    }

    private static void assertEquals(String expected, String actual, String name) {
        if (!expected.equals(actual)) {
            throw new AssertionError(name + " mismatch: expected " + expected + " but got " + actual);
        }
    }
}
