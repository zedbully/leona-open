# Leona Node.js Server Wrapper

Public-safe Node.js wrapper skeleton for customer backends.

This package is server-side only. It signs Leona backend requests, fetches
evidence reports, submits feedback labels, and redacts Leona identifiers before
logs or support export. It does not run in an Android app and does not produce
business `allow`, `reject`, or `block` decisions.

`baseUrl` must use HTTPS for remote servers. Plain HTTP is accepted only for
loopback test fixtures (`127.0.0.1`, `localhost`, or `::1`).

```js
import { createLeonaClient } from "@leonasec/leona-server-wrapper";

const leona = createLeonaClient({
  baseUrl: "https://api.example.leona",
  secretKey: process.env.LEONA_SECRET_KEY,
});

const report = await leona.verdict("<BOX_ID_FROM_APP>");
```

Never commit real SecretKeys, provider credentials, tokens, full BoxIds, or raw
device identifiers.
