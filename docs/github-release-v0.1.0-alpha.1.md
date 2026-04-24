# Leona v0.1.0-alpha.1

First public alpha of the Leona open-source shell.

## Included

- Android SDK public API shell
- Android sample app
- demo backend
- server-side BoxId pipeline skeleton
- release docs, runbooks, and verification scripts

## Release direction

This repository is intentionally the **public shell**:

- public API
- sample integration
- docs / runbooks
- fallback runtime and fallback policy

Higher-value detector logic and production backend strategy remain in private modules and are not part of this release.

## Verified before release

- Android unit tests
- demo backend `go test ./...`
- private/public split verification
- release preflight checks

## Key docs

- `README.md`
- `docs/closeout-strategy.md`
- `docs/open-vs-private-final-matrix.md`
- `docs/open-source-release-checklist.md`
