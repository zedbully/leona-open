/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 *
 * Emulator fingerprint scanner.
 *
 * Covers the mainstream Android emulators used in 2026:
 *   - Android Studio AVD (Goldfish, Ranchu kernels)
 *   - Genymotion (VirtualBox-backed, vbox86 signature)
 *   - LDPlayer   (very popular for game cheating)
 *   - NoxPlayer
 *   - MuMu / MuMu Pro
 *   - BlueStacks
 *   - Cloud phones (YunMi, Redfinger, Cloud-equivalents) — partial
 */
#include "environment_detector.h"
#if __has_include("private_environment_catalog.h")
#include "private_environment_catalog.h"
#else
#include "environment_catalog.h"
#endif

#include <sys/stat.h>
#include <sys/system_properties.h>
#include <string>

#include "../util/evidence_builder.h"

namespace leona::detection {

namespace {

std::string read_prop(const char* key) {
    char buf[PROP_VALUE_MAX] = {};
    __system_property_get(key, buf);
    return std::string(buf);
}

bool file_exists(const char* path) {
    struct stat s;
    return ::stat(path, &s) == 0;
}

bool contains(const std::string& haystack, const char* needle) {
    return haystack.find(needle) != std::string::npos;
}

void check_props(EventList& out) {
    for (const auto& p : environment_prop_matches()) {
        const std::string v = read_prop(p.prop);
        if (v.empty()) continue;
        if (contains(v, p.needle)) {
            EvidenceBuilder ev;
            ev.add("prop", p.prop);
            ev.add("value", v);
            out.push_back({ p.id, p.severity, p.message, ev.build() });
        }
    }
}

void check_files(EventList& out) {
    for (const auto& f : environment_file_matches()) {
        if (file_exists(f.path)) {
            EvidenceBuilder ev;
            ev.add("path", f.path);
            out.push_back({
                f.id,
                f.severity,
                f.message,
                ev.build(),
            });
        }
    }
}

}  // namespace

EventList scan_environment() {
    EventList events;
    check_props(events);
    check_files(events);
    return events;
}

}  // namespace leona::detection
