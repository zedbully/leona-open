# Leona

Leona is an **Android runtime security alpha** with a **server-side BoxId verdict pipeline**.

This repository is the **open-source shell** of the project:

- public Android SDK API
- Android sample app
- server-side BoxId pipeline skeleton
- demo backend
- docs, runbooks, release checklists, and E2E scaffolding

Higher-value detection logic and backend strategy are intentionally kept behind a
**private core / private backend** boundary and are **not** included in the
open-source release.

## Repository layout

- `/Users/a/back/Game/cq/leona-sdk-android` — Android SDK and sample app
- `/Users/a/back/Game/cq/leona-server` — backend services
- `/Users/a/back/Game/cq/demo-backend` — minimal demo backend
- `/Users/a/back/Game/cq/leona` — CLI skeleton
- `/Users/a/back/Game/cq/docs` — current status, closeout strategy, release docs
- `/Users/a/back/Game/cq/scripts` — verification and release preflight scripts

## Start here

If you want the current project status and release boundary first, read:

1. `/Users/a/back/Game/cq/docs/closeout-strategy.md`
2. `/Users/a/back/Game/cq/docs/open-vs-private-final-matrix.md`
3. `/Users/a/back/Game/cq/docs/open-source-release-checklist.md`
4. `/Users/a/back/Game/cq/docs/final-acceptance-summary.md`

## Current public release

- current public tag: `v0.1.0-alpha.1`
- release notes: `/Users/a/back/Game/cq/docs/alpha-release-notes.md`
- latest public repo: [zedbully/leona-open](https://github.com/zedbully/leona-open)

## Release boundary

This public repo is frozen toward:

- shell
- sample
- docs
- fallback runtime / fallback policy

Future higher-value detector logic, heuristics, internal ops, and production-only
backend strategy should continue only in private modules.

## Verification

Private split verification:

```bash
cd /Users/a/back/Game/cq
./scripts/verify-private-modules.sh
```

Release preflight for a real Git worktree:

```bash
cd <your-release-workspace>
/Users/a/back/Game/cq/scripts/release-preflight.sh --strict leona-sdk-android leona-server
```

Publish current alpha tag:

```bash
cd /Users/a/back/Game/cq
git tag -a v0.1.0-alpha.1 -m "Leona public alpha release v0.1.0-alpha.1"
git push origin v0.1.0-alpha.1
gh release create v0.1.0-alpha.1 --title "v0.1.0-alpha.1" --notes-file /Users/a/back/Game/cq/docs/alpha-release-notes.md --prerelease
```

## License

Apache License 2.0.
