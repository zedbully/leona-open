package io.leonasec.wrapper;

import java.util.Arrays;

public final class LeonaCryptoServerTransportSelfTest {
    public static void main(String[] args) throws Exception {
        LeonaCryptoServerTransport.AssertionContext context =
            new LeonaCryptoServerTransport.AssertionContext(
                "leo-test",
                "api.example.test",
                new byte[] {1, 2, 3},
                100L,
                200L
            );
        byte[] digest = new byte[32];
        for (int i = 0; i < digest.length; i++) digest[i] = (byte) i;
        LeonaCryptoServerTransport.SealedRequest request =
            new LeonaCryptoServerTransport.SealedRequest(
                new byte[] {9, 8, 7},
                new LeonaCryptoServerTransport.AssertionEnvelope(
                    context,
                    digest,
                    new byte[] {6, 5, 4}
                )
            );

        byte[] encoded = LeonaCryptoServerTransport.encodeRequest(request);
        LeonaCryptoServerTransport.SealedRequest decoded =
            LeonaCryptoServerTransport.decodeRequest(encoded);
        assertArrayEquals(request.encryptedWire, decoded.encryptedWire, "request wire");
        assertArrayEquals(
            request.assertionEnvelope.contextDigest,
            decoded.assertionEnvelope.contextDigest,
            "context digest"
        );
        assertArrayEquals(
            request.assertionEnvelope.assertion,
            decoded.assertionEnvelope.assertion,
            "assertion"
        );

        LeonaCryptoServerTransport.SealedResponse response =
            new LeonaCryptoServerTransport.SealedResponse(new byte[] {4, 3, 2, 1});
        LeonaCryptoServerTransport.SealedResponse responseDecoded =
            LeonaCryptoServerTransport.decodeResponse(
                LeonaCryptoServerTransport.encodeResponse(response)
            );
        assertArrayEquals(response.encryptedWire, responseDecoded.encryptedWire, "response wire");

        try {
            LeonaCryptoServerTransport.decodeRequest(Arrays.copyOf(encoded, encoded.length + 1));
            throw new AssertionError("trailing bytes must be rejected");
        } catch (IllegalArgumentException expected) {
            // fail closed
        }
        System.out.println("LeonaCryptoServerTransport self-test passed");
    }

    private static void assertArrayEquals(byte[] expected, byte[] actual, String name) {
        if (!Arrays.equals(expected, actual)) {
            throw new AssertionError(name + " mismatch");
        }
    }
}
