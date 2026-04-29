/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace leona::detection {

// A single line from /proc/self/maps, already parsed.
struct MapRegion {
    uintptr_t start = 0;
    uintptr_t end   = 0;
    char perms[5]   = {};    // e.g. "r-xp"
    std::string path;        // may be empty ([anon]) or e.g. "/data/local/tmp/frida-gadget.so"

    bool executable() const { return perms[2] == 'x'; }
    bool readable() const   { return perms[0] == 'r'; }
    size_t size() const     { return end - start; }
    bool is_anon() const    { return path.empty() || path[0] == '['; }
};

// Parse one /proc/<pid>/maps line. Exposed so host-side tests can exercise the
// parser with fixtures without reading the current process map.
bool parse_maps_line(const char* line, MapRegion* out);

// Parse the current process's memory map. Returns empty vector on failure.
// Safe to call on any Android version.
std::vector<MapRegion> read_self_maps();

// Parse a numeric field out of /proc/self/status. Returns -1 on miss.
// Used for TracerPid (debugger detection).
long read_status_field(const char* key);

}  // namespace leona::detection
