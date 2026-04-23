/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 *
 * Root indicator scanner.
 *
 * Root in 2026 is mostly Magisk + Zygisk, with a long tail of SuperSU
 * legacy and KernelSU. Each leaves different fingerprints:
 *
 *   - Magisk:     /sbin/.magisk, /data/adb/magisk, /data/adb/modules,
 *                 ro.boot.mode=recovery patterns, MagiskSU binary
 *   - Magisk Hide: forces us to check via secondary signals since the
 *                 primary paths are hidden inside the app's mount namespace
 *   - Zygisk:     /data/adb/modules/zygisk_*, specific mmap regions
 *   - KernelSU:   /data/adb/ksu, kernel with prctl(0xdeadbeef, ...) handler
 *   - SuperSU:    /system/bin/su, /system/xbin/su, /sbin/su
 *   - Legacy:     /su/bin/su, /system/app/Superuser.apk
 *
 * Note: a skilled attacker with Magisk Hide + Shamiko can defeat every
 * single file-based probe here. The value isn't absolute detection — it's
 * raising the bar and collecting the long tail that hasn't configured hide
 * correctly. The *real* root detection comes through behavioural signals
 * correlated server-side with the BoxId from earlier sessions.
 */
#include "root_detector.h"
#if __has_include("private_root_catalog.h")
#include "private_root_catalog.h"
#else
#include "root_catalog.h"
#endif

#include <sys/stat.h>
#include <sys/system_properties.h>
#include <string>

#include "../util/evidence_builder.h"

namespace leona::detection {

namespace {

bool file_exists(const char* path) {
    struct stat s;
    return ::stat(path, &s) == 0;
}

std::string read_prop(const char* key) {
    char buf[PROP_VALUE_MAX] = {};
    __system_property_get(key, buf);
    return std::string(buf);
}

void check_path_indicators(EventList& out) {
    for (const auto& c : root_path_checks()) {
        if (file_exists(c.path)) {
            EvidenceBuilder ev;
            ev.add("path", c.path);
            out.push_back({ c.id, c.severity, c.message, ev.build() });
        }
    }
}

void check_build_props(EventList& out) {
    for (const auto& rule : root_build_prop_checks()) {
        const std::string value = read_prop(rule.prop);
        if (value.empty()) {
            continue;
        }
        const bool equals_match =
            rule.equals_value != nullptr && value == rule.equals_value;
        const bool contains_match =
            rule.contains_value != nullptr &&
            value.find(rule.contains_value) != std::string::npos;
        if (equals_match || contains_match) {
            EvidenceBuilder ev;
            ev.add(rule.prop, value);
            out.push_back({
                rule.id,
                rule.severity,
                rule.message,
                ev.build(),
            });
        }
    }
}

}  // namespace

EventList scan_root() {
    EventList events;
    check_path_indicators(events);
    check_build_props(events);
    return events;
}

}  // namespace leona::detection
