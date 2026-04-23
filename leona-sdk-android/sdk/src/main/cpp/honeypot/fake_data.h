/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace leona::honeypot {

// Generate `length_bytes` of deterministic-looking pseudo-random data.
// Not cryptographically secure; the internal seed is derived from a
// compile-time constant XOR'd with a per-session perturbation so the
// output varies between installs but is stable within a session.
std::vector<uint8_t> fake_key_bytes(size_t length_bytes);

// Derive `token_length_bytes` of token material from the provided `salt`
// via a stable but non-secure mixing function. Identical `salt` values
// produce identical output so a retrying attacker sees a stable decoy.
std::vector<uint8_t> fake_token_bytes(const std::vector<uint8_t>& salt,
                                       size_t token_length_bytes);

}  // namespace leona::honeypot
