# Changelog

All notable changes to Leona Android SDK are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha.1] - 2026-04-21

### Added
- Public Android SDK API surface:
  - `Leona.init()`
  - `Leona.sense()`
  - `Leona.senseAsync()`
  - `BoxId`
  - `LeonaConfig`
  - `Honeypot`
  - decoy `quickCheck()`
- Kotlin ↔ JNI ↔ C++ runtime collection path
- Native runtime detection for:
  - Frida / ptrace / trampoline signals
  - emulator signals
  - root / Magisk / KernelSU / Riru traces
  - Xposed / LSPosed / EdXposed traces
  - Unidbg traces
- X25519 + HKDF + AES-GCM + HMAC upload path
- Sample app for local stub mode and real server demo mode
- Minimal demo backend for verdict query demonstration

### Changed
- Sample app now supports Gradle property injection for real demo flow:
  - `LEONA_API_KEY`
  - `LEONA_REPORTING_ENDPOINT`
  - `LEONA_CLOUD_CONFIG_ENDPOINT`
  - `LEONA_DEMO_BACKEND_BASE_URL`
- Project status is now documented as an engineering alpha focused on
  Android SDK ↔ server loop closure

### Known limitations
- Sample app still defaults to local stub mode
- Real Android ↔ server ↔ demo backend acceptance is archived on emulator; real-device archive is still pending
- Public API should still be treated as alpha and may change before beta

## [Unreleased]

### Planned
- AAR release packaging hardening
- More real-device acceptance evidence
- Additional field validation on real devices and attacker sandboxes
