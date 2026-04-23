/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
#pragma once

#include <cstdint>

namespace leona::detection {

// Sample the ARM64 virtual timer counter (CNTVCT_EL0) and its declared
// frequency (CNTFRQ_EL0). On real hardware these are implemented by the
// system and tick at the advertised rate (commonly 19.2 MHz or 24 MHz).
//
// Unidbg's default timer implementation returns 0 or a monotonic counter
// that increments by a fixed step unrelated to wall-clock time — the timing
// probe below exploits this difference.
//
// Returns false if the counter is unavailable on the current architecture.
struct TimingSample {
    uint64_t cntvct_before = 0;
    uint64_t cntvct_after = 0;
    uint64_t cntfrq = 0;
    double elapsed_ns = 0.0;
    uint64_t wall_ns = 0;
};

bool sample_known_workload(TimingSample* out);

}  // namespace leona::detection
