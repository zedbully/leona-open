/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 *
 * Runtime injection detector.
 *
 * Current v0.1.0-alpha.1 checks:
 *   1) TracerPid    — debugger or gdbserver attached
 *   2) frida-gadget — library name present in /proc/self/maps (weak)
 *   3) Frida trampolines — machine-code pattern scan in executable pages
 *   4) Public maps baseline — fact-only generic executable mapping evidence
 *
 * The third check is the point of the exercise. The first two are table
 * stakes — every competitor already does them. The third is the wedge.
 *
 * --- Layered-defense notes (architectural principle #C) ---
 *
 * This file sits at Layer 2/3 of the onion. Layer 1 is the public
 * [Leona.quickCheck] API (decoy) — attackers can patch it freely and this
 * detector continues to fire.
 *
 * Future hardening passes on this file:
 *   - Split trampoline scan into *two* independent implementations invoked
 *     via a function pointer picked at init time, so patching one
 *     implementation still leaves the other. The layer-2 implementation can
 *     even deliberately be the easier target.
 *   - Have the trampoline scanner self-check by running its own code
 *     through the signature list; if the scanner's own bytes don't match
 *     the pattern we expect, someone patched us.
 *   - Stagger scans so no single JNI call contains the full sweep — the
 *     attacker can't narrow their hook to one function.
 *
 * Those come in v0.1.0. Alpha keeps one clean implementation so the
 * architecture is legible while we iterate.
 */
#include "injection_detector.h"
#if __has_include("private_injection_catalog.h")
#include "private_injection_catalog.h"
#else
#include "injection_catalog.h"
#endif

#include <cctype>
#include <cstring>
#include <string>
#include <unordered_set>
#include <vector>

#include "process_maps.h"
#include "frida_signatures.h"
#include "../util/evidence_builder.h"

namespace leona::detection {

namespace {

struct TrustedRuntimePaths {
    std::string native_library_dir;
    std::string source_dir;
    std::vector<std::string> split_source_dirs;
};

bool has_deleted_suffix(const std::string& path) {
    constexpr const char* kDeletedSuffix = " (deleted)";
    const size_t suffix_len = std::strlen(kDeletedSuffix);
    return path.size() >= suffix_len
        && path.compare(path.size() - suffix_len, suffix_len, kDeletedSuffix) == 0;
}

std::string normalize_maps_path(std::string path) {
    constexpr const char* kDeletedSuffix = " (deleted)";
    const size_t suffix_len = std::strlen(kDeletedSuffix);
    if (has_deleted_suffix(path)) {
        path.resize(path.size() - suffix_len);
    }
    return path;
}

std::string basename_of(const std::string& path) {
    std::string normalized = normalize_maps_path(path);
    if (normalized.empty()) return {};
    auto slash = normalized.find_last_of('/');
    return slash == std::string::npos ? normalized : normalized.substr(slash + 1);
}

bool is_leona_runtime_library_name(const std::string& path) {
    std::string name = basename_of(path);
    return name == "libleona.so" || name == "libleona_private.so";
}

std::string snapshot_value(const std::string& blob, const char* key) {
    const std::string prefix = std::string(key) + "=";
    size_t start = 0;
    while (start < blob.size()) {
        size_t end = blob.find('\n', start);
        if (end == std::string::npos) end = blob.size();
        if (blob.compare(start, prefix.size(), prefix) == 0) {
            return blob.substr(start + prefix.size(), end - start - prefix.size());
        }
        start = end + 1;
    }
    return {};
}

std::vector<std::string> split_semicolon_paths(const std::string& raw) {
    std::vector<std::string> values;
    size_t start = 0;
    while (start <= raw.size()) {
        size_t end = raw.find(';', start);
        if (end == std::string::npos) end = raw.size();
        std::string value = raw.substr(start, end - start);
        if (!value.empty()) values.push_back(value);
        start = end + 1;
        if (end == raw.size()) break;
    }
    return values;
}

TrustedRuntimePaths trusted_runtime_paths() {
    return {
        snapshot_value(globals().integrity_blob, "nativeLibraryDir"),
        snapshot_value(globals().integrity_blob, "sourceDir"),
        split_semicolon_paths(snapshot_value(globals().integrity_blob, "splitSourceDirs")),
    };
}

TrustedRuntimePaths trusted_runtime_paths_from_blob(const std::string& integrity_blob) {
    return {
        snapshot_value(integrity_blob, "nativeLibraryDir"),
        snapshot_value(integrity_blob, "sourceDir"),
        split_semicolon_paths(snapshot_value(integrity_blob, "splitSourceDirs")),
    };
}

bool starts_with(const std::string& value, const std::string& prefix) {
    return !prefix.empty() && value.rfind(prefix, 0) == 0;
}

bool ends_with(const std::string& value, const std::string& suffix) {
    return value.size() >= suffix.size()
        && value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string lower_ascii(std::string value) {
    for (char& c : value) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return value;
}

bool contains_any(const std::string& value, const std::vector<const char*>& needles) {
    for (auto needle : needles) {
        if (value.find(needle) != std::string::npos) return true;
    }
    return false;
}

bool is_trusted_leona_runtime_library(const std::string& path,
                                      const TrustedRuntimePaths& trusted) {
    if (!is_leona_runtime_library_name(path)) return false;
    if (has_deleted_suffix(path)) return false;

    const std::string normalized_path = normalize_maps_path(path);
    const std::string name = basename_of(path);
    if (!trusted.native_library_dir.empty()
        && normalized_path == trusted.native_library_dir + "/" + name) {
        return true;
    }

    // Some Android builds map native libraries directly from the APK. The APK
    // path itself comes from ApplicationInfo.sourceDir, so only that exact APK
    // is trusted here.
    auto is_trusted_apk_mapping = [&](const std::string& apk_path) {
        const std::string apk_lib_prefix = apk_path + "!/lib/";
        return !apk_path.empty()
            && starts_with(normalized_path, apk_lib_prefix)
            && ends_with(normalized_path, "/" + name);
    };
    if (is_trusted_apk_mapping(trusted.source_dir)) {
        return true;
    }
    for (const auto& split_source_dir : trusted.split_source_dirs) {
        if (is_trusted_apk_mapping(split_source_dir)) {
            return true;
        }
    }
    return false;
}

bool is_trusted_app_code_mapping(const std::string& path, const TrustedRuntimePaths& trusted) {
    const std::string normalized_path = normalize_maps_path(path);
    if (!trusted.native_library_dir.empty()
        && starts_with(normalized_path, trusted.native_library_dir + "/")) {
        return true;
    }

    auto is_trusted_apk_mapping = [&](const std::string& apk_path) {
        return !apk_path.empty() && starts_with(normalized_path, apk_path + "!/lib/");
    };
    if (is_trusted_apk_mapping(trusted.source_dir)) {
        return true;
    }
    for (const auto& split_source_dir : trusted.split_source_dirs) {
        if (is_trusted_apk_mapping(split_source_dir)) {
            return true;
        }
    }
    return false;
}

bool is_memfd_path(const std::string& path) {
    const std::string normalized = normalize_maps_path(path);
    return starts_with(normalized, "/memfd:") || starts_with(normalized, "memfd:");
}

bool is_art_or_jit_runtime_mapping(const std::string& path) {
    const std::string p = lower_ascii(normalize_maps_path(path));
    return contains_any(p, {
        "jit-cache",
        "jit-zygote-cache",
        "dalvik-jit-code-cache",
        "dalvik-classes",
        "dalvik-main space",
        "dalvik-free list large object space",
        "dalvik-large object space",
        "boot-image",
        "/apex/com.android.art/",
        "/apex/com.android.runtime/",
        "/system/framework/",
        "/system/product/framework/",
        "/data/misc/apexdata/com.android.art/",
    });
}

bool is_android_system_path(const std::string& path) {
    const std::string normalized = normalize_maps_path(path);
    return starts_with(normalized, "/system/")
        || starts_with(normalized, "/system_ext/")
        || starts_with(normalized, "/apex/")
        || starts_with(normalized, "/vendor/")
        || starts_with(normalized, "/odm/")
        || starts_with(normalized, "/product/")
        || starts_with(normalized, "/linkerconfig/")
        || starts_with(normalized, "/dev/ashmem/")
        || starts_with(normalized, "/memfd:");
}

bool is_known_app_install_path(const std::string& path) {
    const std::string normalized = normalize_maps_path(path);
    return starts_with(normalized, "/data/app/")
        || starts_with(normalized, "/data/app-private/");
}

bool is_writable_or_temporary_path(const std::string& path) {
    const std::string normalized = normalize_maps_path(path);
    return starts_with(normalized, "/data/local/tmp/")
        || starts_with(normalized, "/data/user/")
        || starts_with(normalized, "/data/data/")
        || starts_with(normalized, "/sdcard/")
        || starts_with(normalized, "/storage/")
        || starts_with(normalized, "/mnt/sdcard/");
}

bool is_probably_shared_object_or_executable_path(const std::string& path) {
    const std::string normalized = lower_ascii(normalize_maps_path(path));
    return normalized.find(".so") != std::string::npos
        || starts_with(normalized, "/data/local/tmp/")
        || starts_with(normalized, "/data/user/")
        || starts_with(normalized, "/data/data/");
}

bool should_skip(const MapRegion& r, const TrustedRuntimePaths& trusted) {
    if (!r.executable() || !r.readable()) return true;
    // Anon executable pages are exactly where we DO want to scan (Frida's
    // Gadget allocates these for trampolines).
    if (r.is_anon()) return false;
    // Our own public/private runtime libraries contain detector code and
    // byte patterns that can resemble hook trampolines. They are trusted
    // collection components, not evidence of third-party injection.
    if (is_trusted_leona_runtime_library(r.path, trusted)) return true;
    for (auto needle : injection_scan_exclusions()) {
        if (r.path.find(needle) != std::string::npos) return true;
    }
    return false;
}

void check_tracer_pid(EventList& out) {
    long tracer = read_status_field("TracerPid");
    if (tracer > 0) {
        EvidenceBuilder ev;
        ev.add("tracer_pid", static_cast<uint64_t>(tracer));
        out.push_back({
            "injection.ptrace.tracer_pid",
            Severity::HIGH,
            "Process is being traced (ptrace attached)",
            ev.build(),
        });
    }
}

void check_frida_gadget_library(const std::vector<MapRegion>& maps, EventList& out) {
    // Weak signal — easily renamed — so severity MEDIUM and we note it as
    // supporting evidence. If paired with a trampoline hit, policy can
    // escalate.
    const auto needles = injection_library_needles();
    for (const auto& m : maps) {
        for (auto needle : needles) {
            if (m.path.find(needle) != std::string::npos) {
                EvidenceBuilder ev;
                ev.add("path", m.path);
                out.push_back({
                    "injection.frida.known_library",
                    Severity::MEDIUM,
                    "Frida-related library mapped into process",
                    ev.build(),
                });
                return;  // one finding is enough
            }
        }
    }
}

void check_leona_runtime_impersonation(const std::vector<MapRegion>& maps, EventList& out) {
    TrustedRuntimePaths trusted = trusted_runtime_paths();
    for (const auto& m : maps) {
        if (!m.executable() || m.is_anon()) continue;
        if (!is_leona_runtime_library_name(m.path)) continue;
        if (is_trusted_leona_runtime_library(m.path, trusted)) continue;

        EvidenceBuilder ev;
        ev.add("path", m.path);
        ev.add("native_library_dir", trusted.native_library_dir);
        ev.add("source_dir", trusted.source_dir);
        ev.add("deleted_mapping", has_deleted_suffix(m.path) ? "true" : "false");
        out.push_back({
            has_deleted_suffix(m.path)
                ? "injection.leona_runtime.deleted_mapping"
                : "injection.leona_runtime.impersonation",
            Severity::HIGH,
            has_deleted_suffix(m.path)
                ? "A Leona runtime library mapping was deleted after load"
                : "A mapped library is using a Leona runtime name from an untrusted path",
            ev.build(),
        });
        return;
    }
}

void check_executable_memfd_baseline(const std::vector<MapRegion>& maps, EventList& out) {
    std::unordered_set<std::string> seen_paths;
    for (const auto& m : maps) {
        if (!m.executable() || !is_memfd_path(m.path)) continue;
        if (is_art_or_jit_runtime_mapping(m.path)) continue;

        const std::string normalized = normalize_maps_path(m.path);
        if (!seen_paths.insert(normalized).second) continue;

        EvidenceBuilder ev;
        ev.add("path", m.path);
        ev.add("region_size", static_cast<uint64_t>(m.size()));
        ev.add("deleted_mapping", has_deleted_suffix(m.path) ? "true" : "false");
        out.push_back({
            "runtime.mapping.memfd_executable",
            Severity::MEDIUM,
            "Executable memfd mapping is present",
            ev.build(),
        });
    }
}

void check_deleted_executable_mapping_baseline(
    const std::vector<MapRegion>& maps,
    EventList& out) {
    std::unordered_set<std::string> seen_paths;
    for (const auto& m : maps) {
        if (!m.executable() || !has_deleted_suffix(m.path)) continue;
        if (is_memfd_path(m.path) || is_art_or_jit_runtime_mapping(m.path)) continue;
        if (is_leona_runtime_library_name(m.path)) continue;

        const std::string normalized = normalize_maps_path(m.path);
        if (!seen_paths.insert(normalized).second) continue;

        EvidenceBuilder ev;
        ev.add("path", m.path);
        ev.add("normalized_path", normalized);
        ev.add("region_size", static_cast<uint64_t>(m.size()));
        out.push_back({
            "runtime.mapping.deleted_executable",
            Severity::LOW,
            "Executable mapping points to a file deleted after load",
            ev.build(),
        });
    }
}

void check_anonymous_executable_mapping_baseline(
    const std::vector<MapRegion>& maps,
    EventList& out) {
    size_t count = 0;
    uint64_t total_bytes = 0;
    const MapRegion* first = nullptr;
    for (const auto& m : maps) {
        if (!m.executable()) continue;
        if (!(m.path.empty() || starts_with(m.path, "[anon"))) continue;
        if (is_art_or_jit_runtime_mapping(m.path)) continue;

        ++count;
        total_bytes += static_cast<uint64_t>(m.size());
        if (!first) first = &m;
    }
    if (count == 0 || !first) return;

    EvidenceBuilder ev;
    ev.add("region_count", static_cast<uint64_t>(count));
    ev.add("total_bytes", total_bytes);
    ev.add("first_region_start", static_cast<uint64_t>(first->start));
    ev.add("first_region_size", static_cast<uint64_t>(first->size()));
    ev.add("first_path", first->path.empty() ? "[anon]" : first->path);
    out.push_back({
        "runtime.mapping.anonymous_executable_summary",
        Severity::LOW,
        "Anonymous executable mappings are present",
        ev.build(),
    });
}

void check_non_system_executable_mapping_baseline(
    const std::vector<MapRegion>& maps,
    const TrustedRuntimePaths& trusted,
    EventList& out) {
    std::unordered_set<std::string> seen_paths;
    for (const auto& m : maps) {
        if (!m.executable() || m.is_anon() || is_memfd_path(m.path)) continue;
        if (is_art_or_jit_runtime_mapping(m.path)) continue;
        if (is_android_system_path(m.path)) continue;
        if (is_known_app_install_path(m.path)) continue;
        if (is_trusted_app_code_mapping(m.path, trusted)) continue;
        if (!is_writable_or_temporary_path(m.path)
            && !is_probably_shared_object_or_executable_path(m.path)) {
            continue;
        }

        const std::string normalized = normalize_maps_path(m.path);
        if (!seen_paths.insert(normalized).second) continue;

        EvidenceBuilder ev;
        ev.add("path", m.path);
        ev.add("region_size", static_cast<uint64_t>(m.size()));
        ev.add("writable_or_temporary_path",
               is_writable_or_temporary_path(m.path) ? "true" : "false");
        out.push_back({
            "runtime.mapping.non_system_executable_path",
            Severity::MEDIUM,
            "Executable mapping comes from a non-system writable or non-install path",
            ev.build(),
        });
    }
}

void check_frida_trampolines(const std::vector<MapRegion>& maps, EventList& out) {
    auto sigs = frida::signatures_for_current_arch();
    if (sigs.empty()) return;

    size_t total_scanned = 0;
    std::unordered_set<std::string> seen_ids;
    TrustedRuntimePaths trusted = trusted_runtime_paths();

    for (const auto& region : maps) {
        if (should_skip(region, trusted)) continue;
        if (region.size() == 0 || region.size() > (64u * 1024u * 1024u)) continue;

        const uint8_t* base = reinterpret_cast<const uint8_t*>(region.start);
        total_scanned += region.size();

        for (const auto& sig : sigs) {
            auto hits = frida::find_signatures(base, region.size(), sig);
            if (hits.empty()) continue;

            // De-dupe by signature id so one flood of matches doesn't produce
            // thousands of events.
            std::string sig_id{sig.id};
            if (!seen_ids.insert(sig_id).second) continue;

            EvidenceBuilder ev;
            ev.add("region_start", static_cast<uint64_t>(region.start));
            ev.add("region_size", static_cast<uint64_t>(region.size()));
            ev.add("match_count", static_cast<uint64_t>(hits.size()));
            ev.add("first_offset", static_cast<uint64_t>(hits[0]));
            ev.add("path", region.path.empty() ? "[anon]" : region.path);

            // Anonymous executable regions are the most damning — legitimate
            // code rarely lives there.
            Severity sev = region.is_anon() ? Severity::CRITICAL : Severity::HIGH;

            out.push_back({
                sig_id,
                sev,
                "Machine-code pattern matching a known Frida trampoline",
                ev.build(),
            });
        }
    }

    if (globals().verbose) {
        // TODO v0.1.0: emit INFO event with bytes_scanned so integrators can
        // verify the scan ran and how much memory it touched.
        (void)total_scanned;
    }
}

}  // namespace

EventList scan_injection_mapping_baseline(
    const std::vector<MapRegion>& maps,
    const std::string& integrity_blob) {
    EventList events;
    TrustedRuntimePaths trusted = trusted_runtime_paths_from_blob(integrity_blob);
    check_executable_memfd_baseline(maps, events);
    check_deleted_executable_mapping_baseline(maps, events);
    check_anonymous_executable_mapping_baseline(maps, events);
    check_non_system_executable_mapping_baseline(maps, trusted, events);
    return events;
}

EventList scan_injection() {
    EventList events;

    check_tracer_pid(events);

    auto maps = read_self_maps();
    if (maps.empty()) return events;

    check_frida_gadget_library(maps, events);
    check_leona_runtime_impersonation(maps, events);
    auto baseline = scan_injection_mapping_baseline(maps, globals().integrity_blob);
    events.insert(events.end(), baseline.begin(), baseline.end());
    check_frida_trampolines(maps, events);

    return events;
}

}  // namespace leona::detection
