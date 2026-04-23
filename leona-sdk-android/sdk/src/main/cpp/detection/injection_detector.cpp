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

#include <cstring>
#include <unordered_set>

#include "process_maps.h"
#include "frida_signatures.h"
#include "../util/evidence_builder.h"

namespace leona::detection {

namespace {

bool should_skip(const MapRegion& r) {
    if (!r.executable() || !r.readable()) return true;
    // Anon executable pages are exactly where we DO want to scan (Frida's
    // Gadget allocates these for trampolines).
    if (r.is_anon()) return false;
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

void check_frida_trampolines(const std::vector<MapRegion>& maps, EventList& out) {
    auto sigs = frida::signatures_for_current_arch();
    if (sigs.empty()) return;

    size_t total_scanned = 0;
    std::unordered_set<std::string> seen_ids;

    for (const auto& region : maps) {
        if (should_skip(region)) continue;
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

EventList scan_injection() {
    EventList events;

    check_tracer_pid(events);

    auto maps = read_self_maps();
    if (maps.empty()) return events;

    check_frida_gadget_library(maps, events);
    check_frida_trampolines(maps, events);

    return events;
}

}  // namespace leona::detection
