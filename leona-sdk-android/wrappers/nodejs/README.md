# Leona Node.js Server Wrapper

Public-safe Node.js wrapper skeleton for customer backends.

This package is server-side only. It delegates Leo-protected backend requests,
fetches evidence reports, submits feedback labels, and redacts Leona identifiers before
logs or support export. It does not run in an Android app and does not produce
business `allow`, `reject`, or `block` decisions.

All network access is delegated to a caller-owned Leo crypto transport. The
wrapper itself has no `fetch`, SecretKey, HMAC, JSON-over-HTTP, or plaintext
fallback. The transport must seal every logical field/body with Leo, use HTTPS
for the outer request, and open/authenticate the response before returning it.
Creating a client without that transport fails closed.

`baseUrl` must use HTTPS for remote servers. Plain HTTP is accepted only for
loopback test fixtures (`127.0.0.1`, `localhost`, or `::1`).

```js
import { createLeonaClient } from "@leonasec/leona-server-wrapper";

const leona = createLeonaClient({
  transport: leoCryptoBackendTransport,
});

const report = await leona.verdict("<BOX_ID_FROM_APP>");
```

`leoCryptoBackendTransport` is a customer-owned adapter around the external Leo
server SDK. This public package does not invent its provider API, keys, or
bootstrap. Never commit real SecretKeys, provider credentials, tokens, full
BoxIds, or raw device identifiers.
