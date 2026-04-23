/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
#pragma once

#include <vector>

namespace leona::detection {

struct UnidbgTimingHeuristics {
    bool detect_cntfrq_zero = false;
    bool detect_stuck_cntvct = false;
    bool detect_wall_timer_skew = false;
    double min_realistic_elapsed_ns = 0.0;
    double wall_timer_skew_ratio_threshold = 0.0;
};

// Public fallback heuristics.
//
// The stronger Unidbg execution heuristics can live in the private module via
// `private_unidbg_heuristics.h`. The OSS build intentionally keeps these
// heuristics disabled.
inline UnidbgTimingHeuristics unidbg_timing_heuristics() {
    return {};
}

inline std::vector<const char*> unidbg_legitimate_parents() {
    return {};
}

inline std::vector<const char*> unidbg_cpuinfo_primary_needles() {
    return {};
}

inline std::vector<const char*> unidbg_cpuinfo_secondary_needles() {
    return {};
}

}  // namespace leona::detection
