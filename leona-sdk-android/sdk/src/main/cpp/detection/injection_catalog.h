/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
#pragma once

#include <vector>

namespace leona::detection {

// Public fallback catalog.
//
// Sensitive injection heuristics can live in the private module via
// `private_injection_catalog.h`. The OSS build keeps these catalogs empty so
// the strongest Frida / scan-tuning fingerprints are not exposed.
inline std::vector<const char*> injection_scan_exclusions() {
    return {};
}

inline std::vector<const char*> injection_library_needles() {
    return {};
}

}  // namespace leona::detection
