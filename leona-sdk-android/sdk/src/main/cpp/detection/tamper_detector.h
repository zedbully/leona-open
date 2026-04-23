/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
#pragma once

#include "../leona.h"

namespace leona::detection {

// Tamper / repackaging detector.
//
// v0.1 skeleton:
//   - consumes an opaque integrity snapshot prepared on the Kotlin side
//   - emits events for debuggable builds, missing installer info, malformed
//     APK paths, and absent signing cert digests
//
// Future versions should replace heuristic-only checks with baseline
// comparisons against server-provisioned cert/package/source expectations.
EventList scan_tamper();

}  // namespace leona::detection
