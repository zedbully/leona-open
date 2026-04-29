## What this does

<!-- Brief summary; linking to an issue is ideal. -->

## How I tested it

<!-- Device / emulator / Unidbg / unit test run — be specific. -->

## Risk

- [ ] Adds a new detection signal (describe false-positive surface)
- [ ] Changes the public API (list what changed)
- [ ] Changes the JNI boundary (confirms header versioning)
- [ ] Pure refactor / docs

## Checklist

- [ ] Code compiles with `./gradlew :sdk:assembleDebug`
- [ ] Unit tests pass with `./gradlew :sdk:testDebugUnitTest`
- [ ] Public API additions are documented in the KDoc header
- [ ] No client-side decision surfaces added (see [architectural principle #A](../docs/architecture.md))
