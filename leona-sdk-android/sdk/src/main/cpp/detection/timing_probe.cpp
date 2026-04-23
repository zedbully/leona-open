/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
#include "timing_probe.h"

#include <time.h>

namespace leona::detection {

static inline uint64_t read_cntvct() {
#if defined(__aarch64__)
    uint64_t v;
    asm volatile("mrs %0, cntvct_el0" : "=r"(v));
    return v;
#else
    return 0;
#endif
}

static inline uint64_t read_cntfrq() {
#if defined(__aarch64__)
    uint64_t v;
    asm volatile("mrs %0, cntfrq_el0" : "=r"(v));
    return v;
#else
    return 0;
#endif
}

static inline uint64_t now_ns() {
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1'000'000'000ULL +
           static_cast<uint64_t>(ts.tv_nsec);
}

bool sample_known_workload(TimingSample* out) {
#if !defined(__aarch64__)
    (void)out;
    return false;
#else
    if (!out) return false;

    out->cntfrq = read_cntfrq();
    if (out->cntfrq == 0) return false;

    uint64_t wall_start = now_ns();
    out->cntvct_before = read_cntvct();

    // A known workload. Not a tight loop — we want real pipeline activity
    // that real hardware handles in microseconds but Unidbg (running on top
    // of a JVM running a CPU emulator) takes orders of magnitude longer.
    volatile uint64_t acc = 0xA5A5A5A5A5A5A5A5ULL;
    for (int i = 0; i < 4096; ++i) {
        acc ^= acc << 13;
        acc ^= acc >> 7;
        acc ^= acc << 17;
    }

    out->cntvct_after = read_cntvct();
    out->wall_ns = now_ns() - wall_start;

    const uint64_t delta_ticks = out->cntvct_after - out->cntvct_before;
    out->elapsed_ns =
        static_cast<double>(delta_ticks) * 1e9 / static_cast<double>(out->cntfrq);

    // Prevent the compiler from optimizing the workload away.
    if (acc == 0) out->wall_ns ^= 1;

    return true;
#endif
}

}  // namespace leona::detection
