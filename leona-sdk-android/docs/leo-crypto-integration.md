# Leo crypto SDK integration

This repository integrates the external Leo crypto facade through an optional,
version-gated adapter. The regular Leona Android SDK and its evidence upload
path remain independent of the external AAR. The integration is therefore
safe to build, test, and ship for domestic deployments that do not use Google
runtime services.

## Contract

The stable contract is in
`sdk/src/main/kotlin/io/leonasec/leona/crypto/LeonaCryptoTransport.kt`:

- `LeonaCryptoHttpRequest` carries method, authority, path/query, content type,
  protected headers, and body. Protected headers and body are the only places
  application data enters the encrypted request.
- `LeonaCryptoTransport.seal(...)` returns an encrypted wire and the exact
  opaque assertion envelope produced by the external facade.
- `LeonaCryptoTransport.openResponse(...)` accepts only the encrypted response
  wire and locally expected 32-byte scope commitments.
- `LeonaCryptoEnvelopeCodec` defines a strict, length-bounded binary HTTP body
  envelope with content type
  `application/vnd.leona.crypto.v1+octet-stream`.

The outer envelope contains the request wire and assertion context/digest/
assertion. It never contains scope commitments: the server derives those from
authenticated deployment, tenant, and policy state. A response envelope
contains only the encrypted response wire; status, protected headers, and body
are released only after authenticated response opening.

Cleartext HTTP headers are routing/transport metadata only. Do not put business
parameters, authorization material, device identifiers, or provider tokens in
them. Supply application headers through `protectedHeaders` instead. TLS is
still required for remote endpoints; this envelope is not a replacement for
TLS.

## Android activation

The optional source module is `crypto-adapter`. It is included only when an
external AAR path is provided:

```bash
LEONA_CRYPTO_AAR=/private/path/leo-android-facade-release.aar \
  ./gradlew :crypto-adapter:assembleRelease
```

The application must add the same AAR directly, for example with a private
dependency repository or a local private file. The AAR must package the
`leo_android_facade` JNI library for each ABI used by the application. The
adapter module itself uses `compileOnly`, so it does not silently bundle a
vendor binary or an absolute developer path.

The application creates `LeoFacadeCryptoTransport` through
`LeoFacadeCryptoTransportFactory.create(...)` with:

1. the provider-owned native configuration;
2. the provider-owned session bootstrap;
3. an application-owned assertion bridge; and
4. an application-owned scope provider.

The API client is deliberately explicit about the fixed outer route and the
server-derived response commitments (the provider-specific construction of
those values is omitted here):

```kotlin
val transport: LeonaCryptoTransport = when (
    val result = LeoFacadeCryptoTransportFactory.create(
        nativeConfiguration = privateNativeConfiguration,
        bootstrap = privateSessionBootstrap,
        providerVersion = "13.0.0", // pin to the supplied AAR manifest
        assertions = assertionProvider,
        scopes = scopeProvider,
    )
) {
    is LeonaCryptoResult.Success -> result.value
    is LeonaCryptoResult.Failure -> error("Leo crypto unavailable: ${result.code}")
}

val client = LeoFacadeOkHttpClient(
    transport = transport,
    assertions = assertionProvider,
    scopes = scopeProvider,
    responseCommitments = { locallyExpectedCommitments },
    endpoint = HttpUrl.get("https://api.example.test/v1/crypto"),
)
val response = client.execute(
    LeonaCryptoHttpRequest(
        method = "POST",
        authority = "api.example.test",
        path = "/v1/customer/action",
        query = "account=opaque-value",
        contentType = "application/json",
        protectedHeaders = protectedApplicationHeaders,
        body = requestJsonBytes,
    )
)
```

`privateNativeConfiguration`, `privateSessionBootstrap`, provider outputs, and
`locallyExpectedCommitments` above are placeholders for customer-controlled
private inputs, not repository fixtures. Do not log or persist them.

The adapter currently accepts only provider major version `13.x` and protocol
major `1`. A provider update is a separate compatibility gate: build the
adapter with the new AAR, run its compile/test gate and the provider's own
facade tests, then update the pinned major only after the public facade
contract is reviewed. A missing JNI library, malformed input, unsupported
major, or provider failure returns a failure result; it never downgrades to a
plaintext request.

For a fixed API route, `LeoFacadeOkHttpClient` posts the encoded request to an
HTTPS endpoint and opens only a successful, authenticated response. It does
not copy the protected request path/query into the cleartext URL and rejects
remote HTTP endpoints. A loopback HTTP URL is allowed only for local tests.

### Local API and HTTPS smoke

The adapter test suite includes a disposable local API using MockWebServer. It
creates an in-memory localhost certificate, serves the fixed `/v1/crypto`
route over HTTPS, trusts that certificate only in the test client, and checks
the binary request and response envelopes end to end:

```bash
LEONA_CRYPTO_AAR=/private/path/leo-android-facade-release.aar \
  ./gradlew :crypto-adapter:test --rerun-tasks --no-daemon --console=plain
```

The certificate, private key, API port, and test payloads are disposable test
state; none are written to the repository. This is a local transport/API
smoke, not a production certificate or a substitute for a customer-managed
HTTPS deployment.

Do not pass an Android device identifier or a business verdict through the
crypto provider bridge. Attestation/assertion bytes are opaque transport
inputs. The Android Leona SDK remains collection/reporting only, and the
customer backend remains the owner of identity correlation and business risk
decisions.

## Server/API activation

`wrappers/java/src/main/java/io/leonasec/wrapper/LeonaCryptoServerTransport.java`
provides the matching Java 11 boundary without depending on the private Leo
server library. The customer service supplies an `Engine` implementation that
maps to the external C server SDK:

- `Engine.open(...)` must call the paired commercial server open operation,
  pass the exact assertion envelope, verify the assertion, and use only a
  server-derived `ServerScope`;
- `Engine.seal(...)` must call the paired commercial server response seal
  operation with that same server-derived scope; and
- `LeonaCryptoServerTransport.open(...)` / `seal(...)` handle the public outer
  envelope and reject malformed, over-limit, wrong-version, or trailing data.

The expected C calls are the provider's paired
`leo_v4_commercial_server_open_request` and
`leo_v4_commercial_server_seal_response` functions. The current public
repository does not ship the private server library, credentials, verifier,
scope derivation, or native binaries. Those stay in the customer-controlled
server deployment. The public Java wrapper must not be placed in an Android
APK.

## Update and release rule

The core Android SDK has no compile or runtime dependency on the Leo AAR, so a
Leo AAR update cannot break the default SDK build. The optional adapter is
deliberately the only version-sensitive seam. Before publishing an adapter
update, verify:

```bash
./gradlew :sdk:test --no-daemon --console=plain
LEONA_CRYPTO_AAR=/private/path/leo-android-facade-release.aar \
  ./gradlew :crypto-adapter:test :crypto-adapter:assembleRelease \
  --no-daemon --console=plain
../scripts/verify-backend-wrapper-skeletons.sh
```

Keep the AAR, native libraries, configuration, bootstrap, assertion keys,
scope commitments, tokens, and customer endpoint configuration outside Git.
Only the public adapter source and redacted compatibility evidence belong in
the public repository.
