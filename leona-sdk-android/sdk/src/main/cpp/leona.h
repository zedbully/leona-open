/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 *
 * Common types used across the native detection core.
 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace leona {

// Bit flags matching LeonaConfig.toNativeHandle() on the Kotlin side.
enum ConfigFlags : uint64_t {
    kFlagInjection   = 1ULL << 0,
    kFlagEnvironment = 1ULL << 1,
    kFlagVerboseLog  = 1ULL << 2,
};

// Severity ordinal — must match DetectionSeverity enum in Kotlin.
enum class Severity : int {
    INFO     = 0,
    LOW      = 1,
    MEDIUM   = 2,
    HIGH     = 3,
    CRITICAL = 4,
};

struct Event {
    std::string id;
    Severity severity;
    std::string message;
    // Evidence is a semicolon-separated k=v string, built via EvidenceBuilder
    // to keep the JNI payload compact.
    std::string evidence;
};

using EventList = std::vector<Event>;

// Global SDK state set once by JNI init(). Accessed read-only afterward,
// so no locking needed on the hot path.
struct GlobalState {
    uint64_t config_flags = 0;
    bool verbose = false;
    std::string integrity_blob;
    std::string tamper_policy_blob;
};

GlobalState& globals();

}  // namespace leona
