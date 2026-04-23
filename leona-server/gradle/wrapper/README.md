# Gradle wrapper

The `gradlew` / `gradlew.bat` scripts are committed, but the wrapper JAR
(`gradle-wrapper.jar`) is binary and must be regenerated once on your
machine:

```bash
# Install Gradle 8.10+ via SDKMAN or brew, then:
gradle wrapper --gradle-version=8.10.2
```

This writes `gradle/wrapper/gradle-wrapper.jar` into place. After that,
all future invocations can use `./gradlew ...` without a system-wide
Gradle install.

## Why not commit the JAR

The JAR is a native-enough binary blob that code review tools don't
inspect it meaningfully, which is a minor supply-chain footgun. Teams
that prefer committed wrappers should regenerate once and commit the
resulting `gradle-wrapper.jar`. Both approaches are valid — pick one
and document it.
