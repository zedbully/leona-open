/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
#pragma once

#include "../leona.h"

namespace leona::detection {

// Detect execution inside Unidbg (a JVM-hosted Unicorn-based ARM emulator
// used by reverse engineers to run SO files without a device).
//
// Strategy is multi-signal: any single check can be bypassed by a motivated
// attacker, but convincing Unidbg to pass all of them simultaneously
// requires significant custom engineering.
EventList scan_unidbg();

}  // namespace leona::detection
