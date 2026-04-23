/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
#pragma once

namespace leona::honeypot {

// Static canary strings baked into libleona.so's .rodata. A reverse engineer
// running `strings libleona.so` will see these and draw conclusions about
// what the SDK does. Almost all conclusions they draw will be wrong.
//
// At runtime, none of these strings are dereferenced on the real defense
// path. They exist to be FOUND.
//
// The names below read like the kind of hard-coded URLs / keys / class names
// a cracker hopes to find. Any of them appearing in telemetry means an
// attacker tried to use a baited string — a strong signal for the adaptive
// defense pipeline.
extern const char* const kCanaryStrings[];
extern const int kCanaryStringCount;

}  // namespace leona::honeypot
