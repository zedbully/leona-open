/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
#pragma once

#include "frida_signatures.h"

namespace leona::detection::frida {

// Public fallback catalog.
//
// Sensitive machine-code fingerprints can live in the private module via
// `private_frida_signatures_catalog.h`. The OSS build intentionally ships an
// empty fallback so the most valuable signatures do not need to remain in the
// public repo.
inline std::vector<Signature> catalog_signatures_for_current_arch() {
    return {};
}

}  // namespace leona::detection::frida
