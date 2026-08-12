# Leona BoxId Verdict Examples

These examples show how a customer backend exchanges a mobile SDK `BoxId` for
the collected Leona device/environment evidence.

Do not run these examples in an Android app. `LEONA_SECRET_KEY` is a backend
secret and must never be embedded in an APK.

All values shown in this directory are placeholders for local verification.
Do not commit real keys, tokens, customer BoxIds, or production response bodies.

## Contract

Endpoint:

```text
POST https://leona.xiyanshan.com/v1/verdict
```

Request body:

```json
{"boxId":"<BOX_ID_FROM_APP>"}
```

Required headers:

```text
Authorization: Bearer <LEONA_SECRET_KEY>
Content-Type: application/json
X-Leona-Timestamp: <unix-time-ms>
X-Leona-Nonce: <random-nonce>
X-Leona-Signature: <base64url-hmac-sha256>
```

Signature:

```text
signingText = timestamp + "\n" + nonce + "\n" + sha256(requestBody)
signature = base64url_no_padding(HMAC-SHA256(secretKey, signingText))
```

`/v1/verdict` is single-use. A successful query consumes the BoxId. Your backend
should cache the returned evidence report against its own login/order/payment
risk record before applying business policy.

```text
Android SDK sense()
  -> app sends leonaBoxId to customer backend
  -> backend checks local evidence cache for this business record
  -> cache miss: backend calls POST /v1/verdict with SecretKey signature
  -> backend stores the evidence report and raw response status
  -> backend applies customer-owned allow/challenge/deny/review policy
  -> later reads use the cached report, not the consumed BoxId
```

## Environment variables

```bash
export LEONA_SECRET_KEY='your_backend_only_secret_key'
export BOX_ID='<BOX_ID_FROM_APP>'
export LEONA_ENDPOINT='https://leona.xiyanshan.com/v1/verdict'
```

`LEONA_ENDPOINT` is optional and defaults to the hosted Leona endpoint above.
All examples require HTTPS and the exact `/v1/verdict` path, reject URL
credentials/query/fragment values, and do not follow redirects. Local fixture
tests may opt in to loopback-only HTTP with `LEONA_ALLOW_LOOPBACK_HTTP=1`;
never enable that flag for a non-loopback host. Dry-run output redacts the
request body, bearer secret, and signature.

## Run

Python:

```bash
python3 python/query_boxid.py
```

Python dry-run signature test:

```bash
python3 -m unittest python/query_boxid_test.py
LEONA_DRY_RUN=1 \
LEONA_SECRET_KEY=test_only \
BOX_ID=123e4567-e89b-42d3-a456-426614174000 \
LEONA_TIMESTAMP=1700000000000 \
LEONA_NONCE=nonce_for_dry_run \
python3 python/query_boxid.py
```

Java 11+:

```bash
javac java/QueryBoxId.java
java -cp java QueryBoxId
```

Java dry-run signature test:

```bash
javac java/QueryBoxId.java
java -cp java QueryBoxId --self-test
LEONA_DRY_RUN=1 \
LEONA_SECRET_KEY=test_only \
BOX_ID=123e4567-e89b-42d3-a456-426614174000 \
LEONA_TIMESTAMP=1700000000000 \
LEONA_NONCE=nonce_for_dry_run \
java -cp java QueryBoxId
```

Go:

```bash
go run go/query_boxid.go
```

Go dry-run signature test:

```bash
cd go
go test
LEONA_DRY_RUN=1 \
LEONA_SECRET_KEY=test_only \
BOX_ID=123e4567-e89b-42d3-a456-426614174000 \
LEONA_TIMESTAMP=1700000000000 \
LEONA_NONCE=nonce_for_dry_run \
go run query_boxid.go
```

Node.js 18+:

```bash
node nodejs/query_boxid.mjs
```

Node.js dry-run signature test:

```bash
node --test nodejs/query_boxid.test.mjs
LEONA_DRY_RUN=1 \
LEONA_SECRET_KEY=test_only \
BOX_ID=123e4567-e89b-42d3-a456-426614174000 \
LEONA_TIMESTAMP=1700000000000 \
LEONA_NONCE=nonce_for_dry_run \
node nodejs/query_boxid.mjs
```

C with libcurl + OpenSSL:

```bash
cc c/query_boxid.c -o /tmp/leona-query-c $(pkg-config --cflags --libs openssl libcurl)
/tmp/leona-query-c
```

Linux packages:

```bash
# Debian / Ubuntu
sudo apt-get install build-essential pkg-config libssl-dev libcurl4-openssl-dev

# Fedora
sudo dnf install gcc gcc-c++ pkgconf-pkg-config openssl-devel libcurl-devel
```

macOS packages:

```bash
brew install openssl@3 curl pkg-config
export PKG_CONFIG_PATH="$(brew --prefix openssl@3)/lib/pkgconfig:$(brew --prefix curl)/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
cc c/query_boxid.c -o /tmp/leona-query-c $(pkg-config --cflags --libs openssl libcurl)
```

C++17 with libcurl + OpenSSL:

```bash
c++ -std=c++17 cpp/query_boxid.cpp -o /tmp/leona-query-cpp $(pkg-config --cflags --libs openssl libcurl)
/tmp/leona-query-cpp
```

macOS C++ build uses the same Homebrew `PKG_CONFIG_PATH` shown above.
If `pkg-config` is unavailable, install the OpenSSL and libcurl development
packages and pass their include/library paths explicitly.

Optional compile-only CI check:

```bash
cc c/query_boxid.c -o /tmp/leona-query-c $(pkg-config --cflags --libs openssl libcurl)
c++ -std=c++17 cpp/query_boxid.cpp -o /tmp/leona-query-cpp $(pkg-config --cflags --libs openssl libcurl)
```

These compile checks do not need real Leona credentials and do not call the
network unless you run the resulting binaries with `LEONA_SECRET_KEY` and
`BOX_ID`.

## Response fields to persist

- `boxId`
- `deviceFingerprint`
- `canonicalDeviceId`
- `events`
- `authoritativeRiskTags`
- `telemetryRiskTags`
- `riskTagsBySource`
- `provenance`
- `policyExplanation`

Leona returns evidence. The customer backend owns all business actions such as
allow, challenge, deny, honeypot, or manual review.

## Customer integration checklist

- Android app uses a Leona-issued AppKey only; no SecretKey is packaged in the APK.
- Android app calls `Leona.sense()` at the protected business moment and sends the opaque `BoxId` to the customer backend.
- Backend stores `LEONA_SECRET_KEY` in backend secret storage and signs `POST /v1/verdict`.
- Backend sends `X-Leona-Timestamp`, `X-Leona-Nonce`, and `X-Leona-Signature` with each verdict request.
- Backend persists the first successful verdict response because the BoxId is consumed after one successful query.
- Backend treats `410 LEONA_BOX_ALREADY_USED` as a cache lookup or duplicate-submit condition, not as a reason to query from the app.
- Backend logs and handles auth/signature/time/network/server errors separately.
- Backend applies customer-owned business policy from the evidence report; Leona does not return final allow/reject/block decisions.
