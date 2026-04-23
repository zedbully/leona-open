/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
#pragma once

#include <vector>

#include "../leona.h"

namespace leona::detection {

struct EnvironmentPropMatch {
    const char* prop;
    const char* needle;
    const char* id;
    const char* message;
    Severity severity;
};

struct EnvironmentFileMatch {
    const char* path;
    const char* id;
    const char* message;
    Severity severity;
};

// Public fallback catalog.
//
// Emulator / cloud-phone fingerprints can live in the private module via
// `private_environment_catalog.h`. The OSS build intentionally keeps this
// catalog empty so the most useful environment signatures do not need to
// remain in the public repository.
inline std::vector<EnvironmentPropMatch> environment_prop_matches() {
    return {};
}

inline std::vector<EnvironmentFileMatch> environment_file_matches() {
    return {};
}

}  // namespace leona::detection
