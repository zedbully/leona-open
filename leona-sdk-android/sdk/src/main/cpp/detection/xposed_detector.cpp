/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
#include "xposed_detector.h"
#if __has_include("private_xposed_catalog.h")
#include "private_xposed_catalog.h"
#else
#include "xposed_catalog.h"
#endif

#include <sys/stat.h>
#include <string>

#include "process_maps.h"
#include "../util/evidence_builder.h"

namespace leona::detection {

namespace {

bool file_exists(const char* path) {
    struct stat s;
    return ::stat(path, &s) == 0;
}

void check_paths(EventList& out) {
    for (const auto& p : xposed_path_checks()) {
        if (file_exists(p.path)) {
            EvidenceBuilder ev;
            ev.add("path", p.path);
            out.push_back({
                p.id,
                p.severity,
                p.message,
                ev.build(),
            });
        }
    }
}

// LSPosed hooks Zygote via Zygisk and leaves library traces in process
// memory maps. Searching for its distinctive library name is a high-signal
// check against an unsophisticated attacker.
void check_lsposed_in_maps(EventList& out) {
    auto regions = read_self_maps();
    const auto needles = xposed_map_needles();
    for (const auto& r : regions) {
        if (r.path.empty()) continue;
        for (const auto& needle : needles) {
            if (r.path.find(needle.needle) != std::string::npos) {
                EvidenceBuilder ev;
                ev.add("path", r.path);
                out.push_back({
                    needle.id,
                    needle.severity,
                    needle.message,
                    ev.build(),
                });
                return;  // one is enough
            }
        }
    }
}

}  // namespace

EventList scan_xposed() {
    EventList events;
    check_paths(events);
    check_lsposed_in_maps(events);
    return events;
}

}  // namespace leona::detection
