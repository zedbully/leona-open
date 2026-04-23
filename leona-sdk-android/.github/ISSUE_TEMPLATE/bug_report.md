---
name: Bug report
about: Detection false positive / false negative / crash
title: "[bug] "
labels: bug
---

## What happened

<!-- one paragraph: what did Leona do and what did you expect? -->

## Environment

- Leona version:
- Android version + API level:
- Device / emulator model:
- ABI (arm64-v8a, armeabi-v7a, x86_64):
- Gradle plugin version:
- NDK version:

## Reproduction

1. …
2. …

## Relevant output

<!--
If possible, please attach:
 - The full logcat with `leona` tag filtered
 - Your /proc/self/maps if trampoline detection misbehaved
 - Your cpuinfo and parent-process cmdline if Unidbg detection misfired
-->

```
<paste logs here>
```
