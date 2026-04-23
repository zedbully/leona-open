/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
#pragma once

#include "../leona.h"

namespace leona::detection {

// Root / privilege-escalation detection.
// Covers classical `su` binaries, Magisk (including hidden mode), KernelSU,
// and Zygisk module traces. All signals are additive — we emit one event per
// finding so the server has every breadcrumb.
EventList scan_root();

}  // namespace leona::detection
