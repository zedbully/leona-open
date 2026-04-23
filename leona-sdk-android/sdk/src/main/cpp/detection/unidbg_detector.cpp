/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 *
 * Unidbg detector.
 *
 * Unidbg (https://github.com/zhkl0228/unidbg) is the reverse engineer's
 * favourite way to execute an Android native library *without* running on a
 * device — they host the .so inside a JVM + Unicorn emulator. Almost every
 * mature mobile crack against a non-trivially protected SO passes through
 * Unidbg at some point.
 *
 * Our job is to make that exercise painful. Not impossible: Unidbg is
 * Turing-complete and an attacker can in principle patch our binary to lie
 * about every single signal. Our job is to make the cost of faking every
 * signal higher than the reward.
 *
 * Signals in this first cut (v0.1.0-alpha.1):
 *   1. CNTVCT_EL0 / CNTFRQ_EL0 timing coherence.
 *      Real hardware: a 4K xorshift loop takes ~single-digit microseconds
 *      and the virtual timer advances consistently with the declared
 *      frequency.
 *      Unidbg: CNTVCT often returns 0 or increments by 1 each read; wall
 *      time for the same loop is orders of magnitude slower.
 *
 *   2. CNTFRQ_EL0 availability.
 *      Android real devices expose a nonzero frequency. Unidbg default
 *      config returns 0.
 *
 *   3. Parent process cmdline.
 *      Real Android apps have `zygote` / `zygote64` as the ancestor. Unidbg
 *      typically has `java` / `mvn` / IDE launcher. We check /proc/<ppid>/comm.
 *
 *   4. /proc/cpuinfo content.
 *      Real devices list ARM cores with Features/processor lines. Unidbg
 *      often returns an empty/minimal file because its proc emulation is
 *      partial.
 *
 * Future signals (v0.2+):
 *   - JNI context coherence (ActivityThread, Looper should be present)
 *   - Hardware crypto extension presence via AT_HWCAP
 *   - Syscall coverage probe (obscure syscalls Unidbg stubs)
 *   - Self-reference checks (/proc/self/exe, dlopen on self)
 */
#include "unidbg_detector.h"
#if __has_include("private_unidbg_heuristics.h")
#include "private_unidbg_heuristics.h"
#else
#include "unidbg_heuristics.h"
#endif

#include <unistd.h>
#include <sys/types.h>
#include <cstdio>
#include <cstring>
#include <string>

#include "timing_probe.h"
#include "../util/evidence_builder.h"

namespace leona::detection {

namespace {

// Read a full file into a string, capped at max_bytes.
std::string read_proc_file(const char* path, size_t max_bytes = 4096) {
    FILE* f = std::fopen(path, "r");
    if (!f) return {};
    std::string out;
    out.resize(max_bytes);
    size_t n = std::fread(out.data(), 1, max_bytes, f);
    out.resize(n);
    std::fclose(f);
    return out;
}

// Check timing signal. Returns true if suspicious (emulated timer or implausible wall/tick ratio).
bool timing_looks_emulated(EventList& out) {
    const auto heuristics = unidbg_timing_heuristics();
    if (!heuristics.detect_cntfrq_zero &&
        !heuristics.detect_stuck_cntvct &&
        !heuristics.detect_wall_timer_skew) {
        return false;
    }

    TimingSample s;
    if (!sample_known_workload(&s)) {
        // Non-ARM64: skip. Most Android 64-bit devices are ARM64; the SDK
        // handles 32-bit Android in v0.1.0 with a different probe.
        return false;
    }

    if (heuristics.detect_cntfrq_zero && s.cntfrq == 0) {
        EvidenceBuilder ev;
        ev.add("reason", "cntfrq_el0_zero");
        out.push_back({
            "unidbg.timer.cntfrq_zero",
            Severity::HIGH,
            "ARM64 counter frequency register returned zero — virtualized timer suspected",
            ev.build(),
        });
        return true;
    }

    if (heuristics.detect_stuck_cntvct &&
        s.elapsed_ns < heuristics.min_realistic_elapsed_ns) {
        EvidenceBuilder ev;
        ev.add("elapsed_ns", static_cast<uint64_t>(s.elapsed_ns));
        ev.add("wall_ns", s.wall_ns);
        out.push_back({
            "unidbg.timer.stuck_cntvct",
            Severity::HIGH,
            "CNTVCT_EL0 advanced implausibly little during workload",
            ev.build(),
        });
        return true;
    }

    // Wall time vs CNTVCT time should agree within an order of magnitude on
    // real hardware. In Unidbg, the workload often runs *much* slower in
    // wall time than CNTVCT reports.
    if (s.wall_ns > 0 && s.elapsed_ns > 0) {
        const double ratio = static_cast<double>(s.wall_ns) / s.elapsed_ns;
        if (heuristics.detect_wall_timer_skew &&
            ratio > heuristics.wall_timer_skew_ratio_threshold) {
            EvidenceBuilder ev;
            ev.add("wall_ns", s.wall_ns);
            ev.add("timer_ns", static_cast<uint64_t>(s.elapsed_ns));
            ev.add("ratio_x100", static_cast<uint64_t>(ratio * 100.0));
            out.push_back({
                "unidbg.timer.wall_timer_skew",
                Severity::MEDIUM,
                "Wall clock and virtual timer disagree by >50x — emulation suspected",
                ev.build(),
            });
            return true;
        }
    }

    return false;
}

bool parent_looks_wrong(EventList& out) {
    const auto legitimate = unidbg_legitimate_parents();
    if (legitimate.empty()) {
        return false;
    }

    pid_t ppid = getppid();
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/comm", ppid);
    std::string parent = read_proc_file(path, 256);
    // Trim newline.
    while (!parent.empty() && (parent.back() == '\n' || parent.back() == '\r')) {
        parent.pop_back();
    }
    if (parent.empty()) return false;

    // Zygote and its descendants are the only legitimate parents on Android.
    // Everything else — java, mvn, idea, gradle, whatever — is suspect.
    for (auto ok : legitimate) {
        if (parent == ok) return false;
    }

    EvidenceBuilder ev;
    ev.add("ppid", static_cast<uint64_t>(ppid));
    ev.add("parent_comm", parent);
    out.push_back({
        "unidbg.parent.non_zygote",
        Severity::HIGH,
        "Parent process is not derived from zygote — not running under Android runtime",
        ev.build(),
    });
    return true;
}

bool cpuinfo_looks_wrong(EventList& out) {
    const auto primary_needles = unidbg_cpuinfo_primary_needles();
    const auto secondary_needles = unidbg_cpuinfo_secondary_needles();
    if (primary_needles.empty() || secondary_needles.empty()) {
        return false;
    }

    const std::string content = read_proc_file("/proc/cpuinfo", 16384);
    if (content.empty()) {
        out.push_back({
            "unidbg.proc.cpuinfo_empty",
            Severity::MEDIUM,
            "/proc/cpuinfo is empty — partial proc emulation suspected",
            {},
        });
        return true;
    }

    // Real ARM cpuinfo contains "processor" lines and a "Features" field.
    // Unidbg's stub often has neither.
    bool has_processor = false;
    for (auto needle : primary_needles) {
        if (content.find(needle) != std::string::npos) {
            has_processor = true;
            break;
        }
    }
    bool has_features = false;
    for (auto needle : secondary_needles) {
        if (content.find(needle) != std::string::npos) {
            has_features = true;
            break;
        }
    }
    if (!has_processor || !has_features) {
        EvidenceBuilder ev;
        ev.add("has_processor", static_cast<uint64_t>(has_processor ? 1 : 0));
        ev.add("has_features", static_cast<uint64_t>(has_features ? 1 : 0));
        ev.add("size", static_cast<uint64_t>(content.size()));
        out.push_back({
            "unidbg.proc.cpuinfo_malformed",
            Severity::MEDIUM,
            "/proc/cpuinfo is missing expected fields",
            ev.build(),
        });
        return true;
    }

    return false;
}

}  // namespace

EventList scan_unidbg() {
    EventList events;

    // We run every signal even if an earlier one fires. Reasoning: a
    // reverse engineer might patch a single probe to return clean, so we
    // want to emit all findings independently. The deduplication happens
    // server-side based on BoxId.
    (void)timing_looks_emulated(events);
    (void)parent_looks_wrong(events);
    (void)cpuinfo_looks_wrong(events);

    return events;
}

}  // namespace leona::detection
