/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 *
 * Fake data generators.
 *
 * Design criteria:
 *   1. **Deterministic**: the same salt must produce the same output, so
 *      a retrying attacker sees consistency (not obviously random
 *      responses).
 *   2. **Server-verifiable**: Leona's backend, given the public salt plus
 *      its own backend-only seed, can derive the same output and
 *      recognize exfiltrated honeypot data.
 *   3. **Cheap**: this is invoked on hot paths.
 *
 * This implementation uses a fixed xorshift64* mixer. v0.2 replaces the
 * constants below with server-provisioned values rotated per-tenant, so
 * Leona Cloud subscribers get keys that only their dashboard can
 * recognize.
 */
#include "fake_data.h"

#include <cstring>

namespace leona::honeypot {

namespace {

// Compile-time constants. v0.2 will make these runtime-configured.
constexpr uint64_t kKeyMixer     = 0x8EB53B1E4C3D9A7FULL;
constexpr uint64_t kTokenMixer   = 0xC9A4F60E8B1D2753ULL;
constexpr uint64_t kInstallSeed  = 0xF1B27D94E3AC5860ULL;

inline uint64_t mix(uint64_t state, uint64_t constant) {
    state ^= constant;
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
}

inline void emit_bytes_from(uint64_t& state, uint64_t constant,
                             uint8_t* out, size_t n) {
    size_t i = 0;
    while (i < n) {
        state = mix(state, constant);
        const size_t take = (n - i >= 8) ? 8 : (n - i);
        std::memcpy(out + i, &state, take);
        i += take;
    }
}

}  // namespace

std::vector<uint8_t> fake_key_bytes(size_t length_bytes) {
    std::vector<uint8_t> out(length_bytes);
    if (length_bytes == 0) return out;
    uint64_t state = kInstallSeed;
    emit_bytes_from(state, kKeyMixer, out.data(), length_bytes);
    return out;
}

std::vector<uint8_t> fake_token_bytes(const std::vector<uint8_t>& salt,
                                      size_t token_length_bytes) {
    std::vector<uint8_t> out(token_length_bytes);
    if (token_length_bytes == 0) return out;

    // Fold the salt into the state so two different salts give two different
    // outputs, but equal salts produce equal outputs.
    uint64_t state = kInstallSeed;
    for (size_t i = 0; i < salt.size(); ++i) {
        state = mix(state ^ (static_cast<uint64_t>(salt[i]) << ((i & 7) * 8)),
                    kTokenMixer);
    }
    emit_bytes_from(state, kTokenMixer, out.data(), token_length_bytes);
    return out;
}

}  // namespace leona::honeypot
