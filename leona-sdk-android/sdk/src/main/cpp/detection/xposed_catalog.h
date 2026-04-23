/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
#pragma once

#include <vector>

#include "../leona.h"

namespace leona::detection {

struct XposedPathCheck {
    const char* path;
    const char* id;
    const char* message;
    Severity severity;
};

struct XposedMapNeedle {
    const char* needle;
    const char* id;
    const char* message;
    Severity severity;
};

// Public fallback catalog.
//
// Xposed-family file indicators and mapped-library needles can live in the
// private module via `private_xposed_catalog.h`. The OSS build intentionally
// keeps these catalogs empty.
inline std::vector<XposedPathCheck> xposed_path_checks() {
    return {};
}

inline std::vector<XposedMapNeedle> xposed_map_needles() {
    return {};
}

}  // namespace leona::detection
