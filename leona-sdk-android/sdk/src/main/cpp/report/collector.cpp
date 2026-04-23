/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 *
 * Payload collector.
 *
 * This is the "inner layer" of the onion. A reverse engineer who hooks
 * collect_payload() from the JVM side gets a byte array; decoding that byte
 * array requires understanding:
 *   - the tag stream layout (below)
 *   - the per-event encoding
 *   - the outer encryption (v0.2, placeholder XOR-scrambler in alpha)
 *
 * v0.1.0-alpha.1 does NOT yet include real encryption; the XOR scrambler
 * exists to keep the payload unreadable to casual inspection and to fix the
 * wire format so v0.2 can drop in real AES-GCM without moving the bytes
 * around.
 */
#include "collector.h"

#include <cstring>
#include <string>

#include "../detection/injection_detector.h"
#include "../detection/environment_detector.h"
#include "../detection/unidbg_detector.h"
#include "../detection/root_detector.h"
#include "../detection/xposed_detector.h"
#include "../detection/tamper_detector.h"

namespace leona::report {

namespace {

// Binary TLV-ish format:
//   magic (4 bytes)  = "LNA1"
//   version (1 byte) = 0x01
//   flags (1 byte)   = reserved
//   event_count (2 bytes, LE)
//   events[event_count]:
//     id_len (2, LE)  | id bytes
//     severity (1)    | category (1)
//     msg_len (2, LE) | msg bytes
//     evidence_len (2, LE) | evidence bytes
//
// Then the whole buffer is XOR-scrambled with a rolling per-byte key so
// hex-dump inspection reveals nothing. v0.2 replaces this with AES-GCM.
void write_u8(std::vector<uint8_t>& buf, uint8_t v)  { buf.push_back(v); }
void write_u16(std::vector<uint8_t>& buf, uint16_t v) {
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
}
void write_bytes(std::vector<uint8_t>& buf, const void* p, size_t n) {
    const uint8_t* b = static_cast<const uint8_t*>(p);
    buf.insert(buf.end(), b, b + n);
}
void write_str(std::vector<uint8_t>& buf, const std::string& s) {
    write_u16(buf, static_cast<uint16_t>(s.size()));
    write_bytes(buf, s.data(), s.size());
}

uint8_t category_of(const std::string& id) {
    if (id.rfind("injection.", 0) == 0) return 1;
    if (id.rfind("frida.", 0) == 0) return 1;
    if (id.rfind("environment.", 0) == 0) return 2;
    if (id.rfind("env.", 0) == 0) return 2;
    if (id.rfind("unidbg.", 0) == 0) return 3;
    if (id.rfind("tamper.", 0) == 0) return 4;
    if (id.rfind("honeypot.", 0) == 0) return 5;
    if (id.rfind("network.", 0) == 0) return 6;
    return 0;
}

// Placeholder scramble. NOT a security mechanism — just fixes the format.
// The real encryption in v0.2 uses a server-provisioned session key.
void scramble(std::vector<uint8_t>& buf) {
    uint8_t k = 0x5C;
    for (auto& b : buf) {
        b ^= k;
        k = static_cast<uint8_t>((k * 31u + 17u) & 0xFF);
    }
}

}  // namespace

std::vector<uint8_t> collect_payload() {
    EventList all;

    if (globals().config_flags & kFlagInjection) {
        auto e = detection::scan_injection();
        all.insert(all.end(), e.begin(), e.end());
    }
    if (globals().config_flags & kFlagEnvironment) {
        auto e = detection::scan_environment();
        all.insert(all.end(), e.begin(), e.end());

        auto r = detection::scan_root();
        all.insert(all.end(), r.begin(), r.end());

        auto x = detection::scan_xposed();
        all.insert(all.end(), x.begin(), x.end());

        auto u = detection::scan_unidbg();
        all.insert(all.end(), u.begin(), u.end());

        auto t = detection::scan_tamper();
        all.insert(all.end(), t.begin(), t.end());
    }

    std::vector<uint8_t> buf;
    buf.reserve(256 + all.size() * 128);

    // Header
    static constexpr char kMagic[4] = {'L', 'N', 'A', '1'};
    write_bytes(buf, kMagic, sizeof(kMagic));
    write_u8(buf, 0x01);  // version
    write_u8(buf, 0x00);  // flags reserved
    write_u16(buf, static_cast<uint16_t>(all.size()));

    for (const auto& ev : all) {
        write_str(buf, ev.id);
        write_u8(buf, static_cast<uint8_t>(ev.severity));
        write_u8(buf, category_of(ev.id));
        write_str(buf, ev.message);
        write_str(buf, ev.evidence);
    }

    scramble(buf);
    return buf;
}

}  // namespace leona::report
