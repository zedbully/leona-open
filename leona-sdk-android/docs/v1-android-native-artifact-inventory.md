# Android native AAR inventory contract

The public SDK AAR contains only the project-owned `libleona.so` for the
allowlisted ABIs `arm64-v8a`, `armeabi-v7a`, and `x86_64`. The native CMake
target uses `-Wall -Wextra -Wpedantic -Werror`; architecture-specific timing
helpers are compiled only for arm64, while other ABIs return typed evidence
absence rather than a fabricated timing signal.

Run the deterministic inventory gate against each completed AAR with the
NDK's `llvm-readelf` and `llvm-nm` as the native inspection authority:

```sh
ANDROID_HOME=/Users/a/Library/Android/sdk \
ANDROID_NDK_ROOT=/Users/a/Library/Android/sdk/ndk/26.3.11579264 \
python3 scripts/verify-android-aar-native.py \
  sdk/build/outputs/aar/sdk-release.aar \
  --output /tmp/leona-sdk-release-native-inventory.json
```

The gate fails closed on unsafe ZIP paths, duplicate entries, stored or
extracted-size overflow, ABI drift, ELF class/machine/SONAME/DT_NEEDED drift,
unexpected JNI exports, debug sections, RPATH/RUNPATH, text relocations,
executable stacks, absolute build paths, or key/token material. A successful
inventory reports only the AAR/native hashes and sizes, ABI names, JNI exports,
and dynamic dependencies. ZIP timestamps are not treated as reproducibility
evidence.

The public artifact explicitly reports
`PROVIDER_ARTIFACT_NOT_INCLUDED`. No Leo provider binary, private key, provider
ABI, or crypto-adapter version gate is embedded or inferred by this package.

This is build/artifact evidence only. API23--36 device runtime, Leo provider
runtime, release signing, and commercial admission remain separate gates.
