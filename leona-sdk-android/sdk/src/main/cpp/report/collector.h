/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
#pragma once

#include <cstdint>
#include <vector>

#include "../leona.h"

namespace leona::report {

// Run every enabled detector, aggregate events, and return an opaque byte
// payload ready for [SecureChannel.upload] on the JVM side.
//
// The payload format is deliberately NOT documented publicly. It's the first
// layer of the onion — reverse engineers should not be able to reconstruct
// the event list by inspecting the byte array they see via JNI.
std::vector<uint8_t> collect_payload();

}  // namespace leona::report
