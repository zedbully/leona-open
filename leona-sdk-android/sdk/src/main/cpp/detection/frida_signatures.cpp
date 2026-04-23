/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
#include "frida_signatures.h"
#if __has_include("private_frida_signatures_catalog.h")
#include "private_frida_signatures_catalog.h"
#else
#include "frida_signatures_catalog.h"
#endif

namespace leona::detection::frida {

std::vector<Signature> signatures_for_current_arch() {
    return catalog_signatures_for_current_arch();
}

std::vector<size_t> find_signatures(
    const uint8_t* haystack, size_t haystack_size, const Signature& sig) {

    std::vector<size_t> hits;
    if (haystack_size < sig.length) return hits;

    const size_t last = haystack_size - sig.length;
    for (size_t i = 0; i <= last; ++i) {
        bool match = true;
        for (size_t j = 0; j < sig.length; ++j) {
            if ((haystack[i + j] & sig.mask[j]) != (sig.bytes[j] & sig.mask[j])) {
                match = false;
                break;
            }
        }
        if (match) hits.push_back(i);
    }
    return hits;
}

}  // namespace leona::detection::frida
