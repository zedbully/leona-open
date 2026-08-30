# BoxId verdict integration boundary

This directory intentionally contains no executable HTTP client. All network
communication and protected fields must use the Leo cryptographic channel.
The former language examples used direct JSON/HMAC requests and have been
removed so they cannot be copied into a production integration.

Use the public wrapper contracts instead:

- Java: `leona-sdk-android/wrappers/java/`
- Node.js: `leona-sdk-android/wrappers/nodejs/`

Those wrappers accept only a caller-owned Leo transport. The transport must
seal the logical request, send the binary `LEONA-CRYPTO` envelope over HTTPS,
verify/open the response, and enforce replay/freshness policy. No plaintext,
direct HTTP, or HMAC-only fallback is supported by the public surface.

The Leo provider AAR, server verifier, key/bootstrap material, and customer
endpoint remain private inputs. This repository does not fabricate provider
cryptography or production credentials.
