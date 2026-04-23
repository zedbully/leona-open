/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
#include "evidence_builder.h"

#include <cstdio>

namespace leona {

EvidenceBuilder& EvidenceBuilder::add(const char* key, const std::string& value) {
    if (!buf_.empty()) buf_ += ';';
    buf_ += key;
    buf_ += '=';
    buf_ += value;
    return *this;
}

EvidenceBuilder& EvidenceBuilder::add(const char* key, uint64_t value) {
    char num[32];
    std::snprintf(num, sizeof(num), "%llu", static_cast<unsigned long long>(value));
    return add(key, std::string(num));
}

}  // namespace leona
