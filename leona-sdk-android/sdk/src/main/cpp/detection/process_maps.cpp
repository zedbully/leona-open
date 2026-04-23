/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
#include "process_maps.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace leona::detection {

std::vector<MapRegion> read_self_maps() {
    std::vector<MapRegion> out;
    FILE* f = std::fopen("/proc/self/maps", "r");
    if (!f) return out;

    // Longest sensible line: path can be ~4KB. Stack-allocate a generous buffer.
    char line[8192];
    while (std::fgets(line, sizeof(line), f)) {
        MapRegion r;
        char perms[8] = {};
        unsigned long long start = 0, end = 0;
        // Format: start-end perms offset dev inode path?
        // We only care about start, end, perms, path.
        int consumed = 0;
        int matched = std::sscanf(line, "%llx-%llx %7s %*llx %*s %*llu %n",
                                  &start, &end, perms, &consumed);
        if (matched < 3) continue;

        r.start = static_cast<uintptr_t>(start);
        r.end   = static_cast<uintptr_t>(end);
        std::strncpy(r.perms, perms, sizeof(r.perms) - 1);

        // Trim trailing newline from the path tail.
        if (consumed > 0 && consumed < static_cast<int>(std::strlen(line))) {
            const char* p = line + consumed;
            while (*p == ' ' || *p == '\t') ++p;
            const char* end_p = p + std::strlen(p);
            while (end_p > p && (end_p[-1] == '\n' || end_p[-1] == '\r')) --end_p;
            r.path.assign(p, end_p);
        }

        out.push_back(std::move(r));
    }
    std::fclose(f);
    return out;
}

long read_status_field(const char* key) {
    FILE* f = std::fopen("/proc/self/status", "r");
    if (!f) return -1;

    char line[512];
    size_t keylen = std::strlen(key);
    long value = -1;
    while (std::fgets(line, sizeof(line), f)) {
        if (std::strncmp(line, key, keylen) == 0 && line[keylen] == ':') {
            value = std::strtol(line + keylen + 1, nullptr, 10);
            break;
        }
    }
    std::fclose(f);
    return value;
}

}  // namespace leona::detection
