# AGP built-in Kotlin clean-build contract

AGP 9.3.1 owns the conventional Kotlin directories for the sample app:
`src/main/kotlin`, `src/debug/kotlin`, and `src/release/kotlin`. They must not
be added a second time through `AndroidSourceSet.kotlin.directories`. Duplicate
registration can produce the expected classes under
`build/intermediates/built_in_kotlinc/<variant>/compile*Kotlin/classes` while
leaving the clean built-in Kotlin unit-test classpath without those classes.

The `cloudTest` and `huaweiRelease` build types intentionally reuse the
release-only implementation overlay, so those non-conventional relationships
remain explicit in `sample-app/build.gradle.kts`.

The regression is the existing Kotlin tests that directly reference the four
sample bridges, executed from a clean, cache-independent build:

```sh
ANDROID_HOME=/Users/a/Library/Android/sdk \
ANDROID_SDK_ROOT=/Users/a/Library/Android/sdk \
./gradlew clean :sdk:testDebugUnitTest :sample-app:testDebugUnitTest \
  --no-configuration-cache --no-build-cache --no-daemon --max-workers=1
```

This is a host/JVM build-classpath check only. It does not imply Android device
runtime, Leo provider, or release/admission acceptance.
