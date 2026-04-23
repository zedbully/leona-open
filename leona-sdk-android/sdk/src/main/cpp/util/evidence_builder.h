/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
#pragma once

#include <cstdint>
#include <string>

namespace leona {

// Small helper used by detectors to build the semicolon-separated evidence
// string attached to each Event. Kept deliberately simple — no JSON on the
// hot path, no allocation beyond std::string growth.
class EvidenceBuilder {
public:
    EvidenceBuilder& add(const char* key, const std::string& value);
    EvidenceBuilder& add(const char* key, uint64_t value);
    std::string build() const { return buf_; }

private:
    std::string buf_;
};

}  // namespace leona
