# Contributing to Leona Android SDK

Welcome. Leona is a defensive security project; we want help and we also
care about *who* commits signatures, so we've put a little structure around
contributions.

## Ways to help

1. **Report a bypass.** If you find a way to dodge one of our detectors,
   open a confidential issue with the `bypass` label. See
   [SECURITY.md](SECURITY.md) for the process.
2. **Add a detection signature.** Attack tools update; if you've found a
   new Frida / Xposed / Magisk marker not yet covered, please PR.
3. **Fix a false positive.** Our canary list of retail devices that should
   never trigger a detection is small. Help us grow it.
4. **Improve docs.** Every paragraph that reads like Chinese-translated-to-
   English-by-a-robot is a paragraph we want rewritten.

## Development setup

```
git clone https://github.com/leonasec/leona-sdk-android
cd leona-sdk-android
./gradlew :sdk:assembleDebug :sample-app:assembleDebug
./gradlew :sdk:testDebugUnitTest
```

Requirements: JDK 17+, Android SDK 34+, NDK r26+, Gradle 8.10+.

## Style

- **Kotlin** — default style (`./gradlew ktlintCheck` before push).
- **C++** — `.clang-format` ships in the repo; `clang-format -i` on change.
- **Commits** — conventional commits (`feat:`, `fix:`, `docs:`, etc.).
- **PR size** — prefer small focused PRs. A PR that touches > 10 files
  should split unless it's an atomic rename.

## Architectural principles (non-negotiable)

We reject PRs that violate these:

1. **No client-side decision surfaces.** No method in the public API may
   return a boolean that an app would use to decide "trust / don't trust".
2. **Single JNI boundary.** All native detection calls go through
   `NativeBridge`. Adding a new JNI entry point requires an RFC issue.
3. **No reflection** in the SDK's hot path. Reflection is itself a hook
   surface.
4. **Every new detection is independently bypassable.** Do not design a
   check that, once patched, disables other checks.

See the repository-level
[open source policy](../docs/open-source-policy.md) for the public/private
boundary.

## PR checklist

- [ ] Code compiles with `./gradlew :sdk:assembleDebug`
- [ ] `./gradlew :sdk:testDebugUnitTest` passes
- [ ] New public API documented in KDoc
- [ ] New detection has a corresponding entry in `docs/field-testing.md`
- [ ] New external dependency added to `libs.versions.toml` with reason
- [ ] No secrets committed (check with `git diff --staged`)

## Code of Conduct

[Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
TL;DR: be kind, focus on the work, lift others up.

## License

By contributing you agree your changes ship under the
[Apache 2.0 License](LICENSE). We do not require a CLA.
