/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
#pragma once

#include "../leona.h"
#include "process_maps.h"

namespace leona::detection {

// Fact-only public baseline checks over process maps. This helper is separate
// from scan_injection() so host-side fixture tests can exercise the mapping
// logic without dereferencing live process addresses for trampoline scanning.
EventList scan_injection_mapping_baseline(
    const std::vector<MapRegion>& maps,
    const std::string& integrity_blob);

// Public entry called by JNI.
EventList scan_injection();

}  // namespace leona::detection
