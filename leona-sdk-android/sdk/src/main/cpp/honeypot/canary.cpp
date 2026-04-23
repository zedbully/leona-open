/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 *
 * These strings exist to be discovered during static analysis of libleona.so.
 * They deliberately look like the kind of high-value finds a reverse
 * engineer hopes to extract — hard-coded endpoints, API keys, admin tokens,
 * secret crypto pepper. None of them are used by the real defense path.
 *
 * Any observation of these strings in network traffic or exfil attempts is
 * a high-confidence signal that the attacker mined libleona for plaintext.
 * Treat it as a confirmed attack and escalate server-side.
 */
#include "canary.h"

namespace leona::honeypot {

// Mark the array const so it lands in .rodata, where `strings` picks it up.
// The compiler may optimize unreferenced strings out under LTO; we reference
// the pointer table below from an exported (but unused at runtime) function
// to keep them in the final .so.
const char* const kCanaryStrings[] = {
    "https://internal-admin.leonasec.io/v1/bypass",
    "https://legacy-api.leonasec.io/debug/dump",
    "https://leona-debug.s3.amazonaws.com/dev/",
    "stripe_live_canary_not_a_real_key_2026_do_not_use",
    "LEONA_ADMIN_TOKEN=eyJhbGciOiJIUzI1NiJ9.YOUR.OWN.CANARY",
    "/v1/attestation/override",
    "/internal/disable-detection",
    "feature_flag.bypass_all = true",
    "crypto.pepper = 1f3a9c5e7b8d2f4a6c9e1b3d5f7a9c1e",
    "debug.leona.returnFalseOnEverything = 1",
    "io.leonasec.leona.BypassHelper",
    "io.leonasec.leona.dev.TestOverride",
    "LEONA_SECRET_FLAG_OVERRIDE_2026",
    nullptr,
};

const int kCanaryStringCount = sizeof(kCanaryStrings) / sizeof(kCanaryStrings[0]) - 1;

// Anchor the canary table so LTO / --gc-sections don't strip it. This
// function is exported via JNI (see jni_bridge.cpp honeypot_anchor) but is
// never called from Kotlin — it exists solely to reference the strings.
extern "C" const char* leona_honeypot_anchor(int index) {
    if (index < 0 || index >= kCanaryStringCount) return nullptr;
    return kCanaryStrings[index];
}

}  // namespace leona::honeypot
