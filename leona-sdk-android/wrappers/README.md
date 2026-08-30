# Leona Backend Wrappers

These skeletons are public-safe server-side wrappers for customer backends.
They are not Android SDK code and must never run inside an APK.

Current slices:

- `nodejs/`: Node.js 18+ wrapper skeleton with tests.
- `java/`: Java 11+ wrapper skeleton using only the JDK standard library.
- `java/.../LeonaCryptoServerTransport.java`: Java 11 envelope and Engine
  boundary for a customer-owned binding to the external Leo server crypto SDK.

Scope:

- delegate backend-only Leona requests to a caller-owned Leo crypto transport
- query evidence reports and support bundles
- submit customer feedback labels
- redact Leona identifiers before logs or support export
- decode/encode the Leo encrypted HTTP envelope without accepting
  client-supplied scope commitments

Non-goals:

- no final business `allow`, `reject`, `block`, or `deny` decision
- no embedded real SecretKey, provider credential, token, full BoxId, or raw
  device identifier
- no dependency on private Leona server implementation; the caller supplies
  the provider binding
- no server keys, verifier, scope derivation, or native crypto binary in this
  public wrapper
- no direct HTTP client, plaintext JSON fallback, or HMAC-only compatibility
  path

Run local checks:

```bash
./scripts/verify-backend-wrapper-skeletons.sh
```

The verification script also performs package dry-runs:

- `npm pack --dry-run` for the Node.js wrapper
- Gradle `jar`, `sourcesJar`, `javadocJar`, and generated Maven POM for the Java
  wrapper
