# Final release inspection — 2026-04-25

This file is the last practical inspection snapshot before any further public
release/push activity.

## 1. Facts confirmed from the current repo state

### Git / release state

- git remote: `git@github.com:zedbully/leona-open.git`
- current branch: `main`
- tag already exists: `v0.1.0-alpha.1`
- GitHub prerelease already exists:
  - `https://github.com/zedbully/leona-open/releases/tag/v0.1.0-alpha.1`

### Important implication

The repo is **not** in a fresh clean release state right now.

There is a large dirty working tree containing both:

- tracked modified files
- untracked new files

So the next action is **not** "publish immediately".
The next action is **cleanup / staging decision / preflight**.

## 2. Current blockers before any new public release step

### Blocker A — working tree is dirty

Current repo state includes many modified files across:

- `docs/`
- `leona-sdk-android/`
- `leona-server/`

This means:

- `git diff --cached` and staged intent must be checked manually
- you should not tag or cut a new release from this state blindly
- you should not assume all current changes belong to one publishable batch

### Blocker B — mainland/non-GMS work is mixed with other active changes

The current dirty tree is not only mainland-related. It also includes:

- existing Android SDK/runtime changes
- existing server ingestion/common changes
- workflow/docs/script changes

So mainland closeout should be treated as a **subset** of the current local
changes, not as the only active topic in the tree.

### Blocker C — existing prerelease already exists

`v0.1.0-alpha.1` is already published as a GitHub prerelease.

That means the next public action must be one of:

- update repo content for a future tag
- create a new tag/release
- or stop and keep `v0.1.0-alpha.1` as the public alpha baseline

It should **not** be treated as an unpublished state.

## 3. Mainland/non-GMS status at this inspection point

### Public side

Ready in public repo shape:

- sample OEM modes
- public OEM routing shell
- public fallback path
- risk posture docs
- release gate docs
- closeout summary
- final ops checklist

### Private side

Still required before production-ready mainland support:

- real OEM Android provider integration
- real OEM server verifier policy/config
- trusted provider production configuration
- real staging evidence for at least one OEM path

## 4. Recommended next execution order

### Option A — stay on the current public alpha baseline

Use this if you do **not** want to publish another public release immediately.

1. keep `v0.1.0-alpha.1` as current public baseline
2. continue private implementation only
3. avoid public tag/release changes until staging OEM path is real

### Option B — prepare the next public batch safely

Use this if you want to turn the current local work into the next public batch.

1. run strict preflight
2. inspect `git status` + `git diff --cached`
3. separate mainland/public-safe changes from unrelated local work
4. rerun public-only verification
5. rerun private split verification
6. decide next tag/version
7. only then push/tag/release

## 5. Commands to run next

### Global preflight

```bash
cd /Users/a/back/Game/cq
/Users/a/back/Game/cq/scripts/release-preflight.sh --strict leona-sdk-android leona-server
```

### Inspect staged intent

```bash
cd /Users/a/back/Game/cq
git status --short
git diff --cached --name-only
```

### Mainland final checklist

```bash
cat /Users/a/back/Game/cq/docs/mainland-final-ops-checklist.md
```

### Existing public release

```bash
gh release view v0.1.0-alpha.1
```

## 6. Decision summary

At the current inspection point:

- mainland/non-GMS **public documentation and shell are closed out**
- mainland/non-GMS **private productionization is not finished**
- the repo **is not in a clean release-ready working-tree state**
- `v0.1.0-alpha.1` **already exists publicly**

So the immediate next step is:

> **run preflight and separate the dirty tree before any further public release action.**
