/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 *
 * Irreducible machine-code fingerprints for Frida and its derivatives.
 *
 * These are the bytes that remain identical regardless of:
 *   - library rename  (frida-gadget.so → libwhatever.so)
 *   - build variant   (upstream tag / fork)
 *   - minor version bumps (12.x → 16.x share these)
 *
 * They change across MAJOR architectural shifts, which is why each signature
 * is versioned and scoped to a CPU architecture.
 *
 * Philosophy: we scan executable memory pages for these patterns. A match is
 * not proof on its own; we combine it with secondary evidence (page size,
 * location in anonymous mapping, adjacency to JIT stubs) to raise severity.
 */
#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string_view>

namespace leona::detection::frida {

enum class Arch {
    ARM64,
    ARM32,
    X86_64,
    X86,
};

struct Signature {
    std::string_view id;          // stable identifier, e.g. "frida.trampoline.arm64.v1"
    Arch arch;
    const uint8_t* bytes;         // literal machine code to match
    const uint8_t* mask;          // per-byte mask (0xFF = must match, 0x00 = wildcard)
    size_t length;
};

// Returns all signatures that apply to the running architecture.
std::vector<Signature> signatures_for_current_arch();

// Search `haystack` for any of the given signatures. Returns offsets into
// haystack. Implementation: naive masked search — good enough for maps
// typically < 16MB; a Boyer-Moore or SIMD pass lands in v0.2 if needed.
std::vector<size_t> find_signatures(
    const uint8_t* haystack, size_t haystack_size,
    const Signature& sig);

}  // namespace leona::detection::frida
