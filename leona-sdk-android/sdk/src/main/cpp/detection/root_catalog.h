/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
#pragma once

#include <vector>

#include "../leona.h"

namespace leona::detection {

struct RootPathCheck {
    const char* path;
    const char* id;
    Severity severity;
    const char* message;
};

struct RootBuildPropCheck {
    const char* prop;
    const char* equals_value;
    const char* contains_value;
    const char* id;
    Severity severity;
    const char* message;
};

// Public fallback catalog.
//
// Root / Magisk / KernelSU / Zygisk fingerprints can live in the private
// module via `private_root_catalog.h`. The OSS build intentionally keeps
// the file/path and build-prop rule set empty.
inline std::vector<RootPathCheck> root_path_checks() {
    return {};
}

inline std::vector<RootBuildPropCheck> root_build_prop_checks() {
    return {};
}

}  // namespace leona::detection
