# Optional Leo crypto Android adapter

This module is intentionally excluded from the default Gradle graph. It is
compiled only when `LEONA_CRYPTO_AAR` points to an external Leo Android facade
AAR. The external AAR and its JNI DSO are never copied into this repository.

```bash
LEONA_CRYPTO_AAR=/private/path/leo-android-facade-release.aar \
  ./gradlew :crypto-adapter:assembleRelease
```

The consuming application must add the exact same external AAR directly, so
the AAR's `leo_android_facade` JNI library is packaged. The adapter does not
fall back to plaintext when the provider is absent or incompatible.

See [`../docs/leo-crypto-integration.md`](../docs/leo-crypto-integration.md)
for the Android and server/API contract.
