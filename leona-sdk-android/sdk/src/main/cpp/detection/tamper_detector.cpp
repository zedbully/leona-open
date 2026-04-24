/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
#include "tamper_detector.h"
#include "tamper_catalog.h"
#if __has_include("private_tamper_catalog.h")
#include "private_tamper_catalog.h"
#endif

#include <algorithm>
#include <cctype>
#include <string>
#include <unordered_set>
#include <unordered_map>

#include "../util/evidence_builder.h"

namespace leona::detection {

namespace {

using Snapshot = std::unordered_map<std::string, std::string>;

Snapshot parse_snapshot(const std::string& blob) {
    Snapshot out;
    size_t start = 0;
    while (start < blob.size()) {
        size_t end = blob.find('\n', start);
        if (end == std::string::npos) end = blob.size();

        const std::string line = blob.substr(start, end - start);
        const size_t sep = line.find('=');
        if (sep != std::string::npos && sep > 0) {
            out.emplace(line.substr(0, sep), line.substr(sep + 1));
        }

        start = end + 1;
    }
    return out;
}

std::string get_or(const Snapshot& snapshot, const char* key) {
    const auto it = snapshot.find(key);
    return it == snapshot.end() ? std::string() : it->second;
}

std::string trim(std::string value) {
    auto not_space = [](unsigned char c) { return !std::isspace(c); };
    value.erase(value.begin(),
                std::find_if(value.begin(), value.end(), not_space));
    value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(),
                value.end());
    return value;
}

std::unordered_set<std::string> parse_csv_set(const std::string& raw) {
    std::unordered_set<std::string> out;
    size_t start = 0;
    while (start <= raw.size()) {
        size_t end = raw.find(',', start);
        if (end == std::string::npos) end = raw.size();
        std::string token = trim(raw.substr(start, end - start));
        if (!token.empty()) out.insert(token);
        start = end + 1;
        if (end == raw.size()) break;
    }
    return out;
}

bool has_any_intersection(const std::unordered_set<std::string>& a,
                          const std::unordered_set<std::string>& b) {
    if (a.empty() || b.empty()) return false;
    const auto& small = a.size() < b.size() ? a : b;
    const auto& large = a.size() < b.size() ? b : a;
    for (const auto& item : small) {
        if (large.find(item) != large.end()) return true;
    }
    return false;
}

void check_optional_hash(
    const Snapshot& snapshot,
    const Snapshot& policy,
    const char* expected_key,
    const char* actual_key,
    const char* missing_id,
    const char* mismatch_id,
    const char* missing_message,
    const char* mismatch_message,
    EventList& out) {
    const std::string expected = get_or(policy, expected_key);
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, actual_key);
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty() ? missing_id : mismatch_id,
        Severity::HIGH,
        actual.empty() ? missing_message : mismatch_message,
        ev.build(),
    });
}

void check_debuggable(const Snapshot& snapshot, EventList& out) {
    if (get_or(snapshot, "debuggable") != "1") return;

    EvidenceBuilder ev;
    ev.add("debuggable", "1");
    ev.add("package", get_or(snapshot, "package"));
    out.push_back({
        "tamper.debuggable.app_flag",
        Severity::HIGH,
        "Application is running with FLAG_DEBUGGABLE enabled",
        ev.build(),
    });
}

void check_installer(const Snapshot& snapshot, EventList& out) {
    const std::string installer = get_or(snapshot, "installer");
    if (!installer.empty()) return;

    EvidenceBuilder ev;
    ev.add("package", get_or(snapshot, "package"));
    out.push_back({
        "tamper.installer.missing",
        Severity::MEDIUM,
        "Installer package is missing — sideload or repackaging path suspected",
        ev.build(),
    });
}

void check_expected_package(const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedPackage");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "package");
    if (actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        "tamper.package_name.mismatch",
        Severity::CRITICAL,
        "Package name does not match configured baseline",
        ev.build(),
    });
}

void check_allowed_installers(const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const auto allowed = parse_csv_set(get_or(policy, "allowedInstaller"));
    if (allowed.empty()) return;

    const std::string installer = get_or(snapshot, "installer");
    if (!installer.empty() && allowed.find(installer) != allowed.end()) return;

    EvidenceBuilder ev;
    ev.add("installer", installer);
    ev.add("allowed_count", static_cast<uint64_t>(allowed.size()));
    out.push_back({
        "tamper.installer.untrusted",
        Severity::HIGH,
        "Installer package does not match configured allowlist",
        ev.build(),
    });
}

void check_allowed_signing_certs(const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const auto allowed = parse_csv_set(get_or(policy, "allowedCertSha256"));
    if (allowed.empty()) return;

    const auto actual = parse_csv_set(get_or(snapshot, "certSha256"));
    if (has_any_intersection(actual, allowed)) return;

    EvidenceBuilder ev;
    ev.add("actual_count", static_cast<uint64_t>(actual.size()));
    ev.add("allowed_count", static_cast<uint64_t>(allowed.size()));
    out.push_back({
        "tamper.signature.untrusted",
        Severity::CRITICAL,
        "Signing certificate digest does not match configured allowlist",
        ev.build(),
    });
}

void check_expected_apk_hash(const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedApkSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "apkSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty() ? "tamper.apk_hash.missing" : "tamper.apk_hash.mismatch",
        Severity::CRITICAL,
        actual.empty()
            ? "APK SHA-256 could not be collected"
            : "APK SHA-256 does not match configured baseline",
        ev.build(),
    });
}

void check_expected_manifest_hash(const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedManifestEntrySha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "manifestEntrySha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty() ? "tamper.manifest_hash.missing" : "tamper.manifest_hash.mismatch",
        Severity::CRITICAL,
        actual.empty()
            ? "AndroidManifest.xml hash could not be collected"
            : "AndroidManifest.xml hash does not match configured baseline",
        ev.build(),
    });
}

void check_expected_lib_hashes(const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    static constexpr char kPrefix[] = "expectedLibSha256.";
    for (const auto& [key, expected] : policy) {
        if (key.rfind(kPrefix, 0) != 0) continue;

        const std::string lib_name = key.substr(sizeof(kPrefix) - 1);
        const std::string actual = get_or(snapshot, ("libSha256." + lib_name).c_str());
        if (!actual.empty() && actual == expected) continue;

        EvidenceBuilder ev;
        ev.add("library", lib_name);
        ev.add("expected", expected);
        ev.add("actual", actual);
        out.push_back({
            actual.empty() ? "tamper.native_lib_hash.missing" : "tamper.native_lib_hash.mismatch",
            Severity::HIGH,
            actual.empty()
                ? "Native library SHA-256 could not be collected"
                : "Native library SHA-256 does not match configured baseline",
            ev.build(),
        });
    }
}

void check_expected_dex_hashes(const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    static constexpr char kPrefix[] = "expectedDexSha256.";
    for (const auto& [key, expected] : policy) {
        if (key.rfind(kPrefix, 0) != 0) continue;

        const std::string dex_name = key.substr(sizeof(kPrefix) - 1);
        const std::string actual = get_or(snapshot, ("dexSha256." + dex_name).c_str());
        if (!actual.empty() && actual == expected) continue;

        EvidenceBuilder ev;
        ev.add("entry", dex_name);
        ev.add("expected", expected);
        ev.add("actual", actual);
        out.push_back({
            actual.empty() ? "tamper.dex_hash.missing" : "tamper.dex_hash.mismatch",
            Severity::CRITICAL,
            actual.empty()
                ? "DEX entry SHA-256 could not be collected"
                : "DEX entry SHA-256 does not match configured baseline",
            ev.build(),
        });
    }
}

void check_expected_dex_section_hashes(const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    static constexpr char kPrefix[] = "expectedDexSectionSha256.";
    for (const auto& [key, expected] : policy) {
        if (key.rfind(kPrefix, 0) != 0) continue;

        const std::string entry_and_section = key.substr(sizeof(kPrefix) - 1);
        const std::string actual = get_or(snapshot, ("dexSectionSha256." + entry_and_section).c_str());
        if (!actual.empty() && actual == expected) continue;

        EvidenceBuilder ev;
        ev.add("entry_section", entry_and_section);
        ev.add("expected", expected);
        ev.add("actual", actual);
        out.push_back({
            actual.empty() ? "tamper.dex_section_hash.missing" : "tamper.dex_section_hash.mismatch",
            Severity::CRITICAL,
            actual.empty()
                ? "DEX section SHA-256 could not be collected"
                : "DEX section SHA-256 does not match configured baseline",
            ev.build(),
        });
    }
}

void check_expected_dex_method_hashes(const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    static constexpr char kPrefix[] = "expectedDexMethodSha256.";
    for (const auto& [key, expected] : policy) {
        if (key.rfind(kPrefix, 0) != 0) continue;

        const std::string entry_and_method = key.substr(sizeof(kPrefix) - 1);
        const std::string actual = get_or(snapshot, ("dexMethodSha256." + entry_and_method).c_str());
        if (!actual.empty() && actual == expected) continue;

        EvidenceBuilder ev;
        ev.add("entry_method", entry_and_method);
        ev.add("expected", expected);
        ev.add("actual", actual);
        out.push_back({
            actual.empty() ? "tamper.dex_method_hash.missing" : "tamper.dex_method_hash.mismatch",
            Severity::CRITICAL,
            actual.empty()
                ? "DEX method code hash could not be collected"
                : "DEX method code hash does not match configured baseline",
            ev.build(),
        });
    }
}

void check_expected_split_hashes(const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    static constexpr char kPrefix[] = "expectedSplitSha256.";
    for (const auto& [key, expected] : policy) {
        if (key.rfind(kPrefix, 0) != 0) continue;

        const std::string split_name = key.substr(sizeof(kPrefix) - 1);
        const std::string actual = get_or(snapshot, ("splitSha256." + split_name).c_str());
        if (!actual.empty() && actual == expected) continue;

        EvidenceBuilder ev;
        ev.add("split", split_name);
        ev.add("expected", expected);
        ev.add("actual", actual);
        out.push_back({
            actual.empty() ? "tamper.split_hash.missing" : "tamper.split_hash.mismatch",
            Severity::HIGH,
            actual.empty()
                ? "Split APK SHA-256 could not be collected"
                : "Split APK SHA-256 does not match configured baseline",
            ev.build(),
        });
    }
}

void check_expected_split_inventory(const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedSplitInventorySha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "splitInventorySha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.split_inventory_hash.missing"
            : "tamper.split_inventory_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Split APK inventory fingerprint could not be collected"
            : "Split APK inventory fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_dynamic_feature_splits(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedDynamicFeatureSplitSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "dynamicFeatureSplitSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.dynamic_feature_split_hash.missing"
            : "tamper.dynamic_feature_split_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Dynamic-feature split fingerprint could not be collected"
            : "Dynamic-feature split fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_dynamic_feature_split_names(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedDynamicFeatureSplitNameSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "dynamicFeatureSplitNameSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.dynamic_feature_split_name_hash.missing"
            : "tamper.dynamic_feature_split_name_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Dynamic-feature split filename fingerprint could not be collected"
            : "Dynamic-feature split filename fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_config_split_axes(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedConfigSplitAxisSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "configSplitAxisSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.config_split_axis_hash.missing"
            : "tamper.config_split_axis_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Config split axis fingerprint could not be collected"
            : "Config split axis fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_config_split_names(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedConfigSplitNameSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "configSplitNameSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.config_split_name_hash.missing"
            : "tamper.config_split_name_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Config split filename fingerprint could not be collected"
            : "Config split filename fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_config_split_abis(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedConfigSplitAbiSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "configSplitAbiSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.config_split_abi_hash.missing"
            : "tamper.config_split_abi_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Config split ABI fingerprint could not be collected"
            : "Config split ABI fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_config_split_locales(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedConfigSplitLocaleSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "configSplitLocaleSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.config_split_locale_hash.missing"
            : "tamper.config_split_locale_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Config split locale fingerprint could not be collected"
            : "Config split locale fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_config_split_densities(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedConfigSplitDensitySha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "configSplitDensitySha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.config_split_density_hash.missing"
            : "tamper.config_split_density_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Config split density fingerprint could not be collected"
            : "Config split density fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_elf_section_hashes(const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    static constexpr char kPrefix[] = "expectedElfSectionSha256.";
    for (const auto& [key, expected] : policy) {
        if (key.rfind(kPrefix, 0) != 0) continue;

        const std::string lib_and_section = key.substr(sizeof(kPrefix) - 1);
        const std::string actual = get_or(snapshot, ("elfSectionSha256." + lib_and_section).c_str());
        if (!actual.empty() && actual == expected) continue;

        EvidenceBuilder ev;
        ev.add("lib_section", lib_and_section);
        ev.add("expected", expected);
        ev.add("actual", actual);
        out.push_back({
            actual.empty() ? "tamper.elf_section_hash.missing" : "tamper.elf_section_hash.mismatch",
            Severity::HIGH,
            actual.empty()
                ? "ELF section SHA-256 could not be collected"
                : "ELF section SHA-256 does not match configured baseline",
            ev.build(),
        });
    }
}

void check_expected_elf_export_symbol_hashes(const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    static constexpr char kPrefix[] = "expectedElfExportSymbolSha256.";
    for (const auto& [key, expected] : policy) {
        if (key.rfind(kPrefix, 0) != 0) continue;

        const std::string lib_and_symbol = key.substr(sizeof(kPrefix) - 1);
        const std::string actual = get_or(snapshot, ("elfExportSymbolSha256." + lib_and_symbol).c_str());
        if (!actual.empty() && actual == expected) continue;

        EvidenceBuilder ev;
        ev.add("lib_symbol", lib_and_symbol);
        ev.add("expected", expected);
        ev.add("actual", actual);
        out.push_back({
            actual.empty() ? "tamper.elf_export_symbol_hash.missing" : "tamper.elf_export_symbol_hash.mismatch",
            Severity::HIGH,
            actual.empty()
                ? "ELF export symbol fingerprint could not be collected"
                : "ELF export symbol fingerprint does not match configured baseline",
            ev.build(),
        });
    }
}

void check_expected_elf_export_graph_hashes(const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    static constexpr char kPrefix[] = "expectedElfExportGraphSha256.";
    for (const auto& [key, expected] : policy) {
        if (key.rfind(kPrefix, 0) != 0) continue;

        const std::string lib_name = key.substr(sizeof(kPrefix) - 1);
        const std::string actual = get_or(snapshot, ("elfExportGraphSha256." + lib_name).c_str());
        if (!actual.empty() && actual == expected) continue;

        EvidenceBuilder ev;
        ev.add("library", lib_name);
        ev.add("expected", expected);
        ev.add("actual", actual);
        out.push_back({
            actual.empty() ? "tamper.elf_export_graph_hash.missing" : "tamper.elf_export_graph_hash.mismatch",
            Severity::HIGH,
            actual.empty()
                ? "ELF export graph fingerprint could not be collected"
                : "ELF export graph fingerprint does not match configured baseline",
            ev.build(),
        });
    }
}

void check_expected_requested_permissions(const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedRequestedPermissionsSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "requestedPermissionsSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.permissions_hash.missing"
            : "tamper.permissions_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Requested permissions fingerprint could not be collected"
            : "Requested permissions fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_requested_permission_semantics(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedRequestedPermissionSemanticsSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "requestedPermissionSemanticsSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.permission_semantics_hash.missing"
            : "tamper.permission_semantics_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Requested permission semantics fingerprint could not be collected"
            : "Requested permission semantics fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_declared_permission_semantics(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedDeclaredPermissionSemanticsSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "declaredPermissionSemanticsSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.declared_permission_semantics_hash.missing"
            : "tamper.declared_permission_semantics_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Declared permission semantics fingerprint could not be collected"
            : "Declared permission semantics fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_declared_permission_fields(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    static constexpr char kPrefix[] = "expectedDeclaredPermissionField.";
    for (const auto& [key, expected] : policy) {
        if (key.rfind(kPrefix, 0) != 0) continue;

        const std::string permission_field = key.substr(sizeof(kPrefix) - 1);
        const std::string actual = get_or(snapshot, ("declaredPermissionField." + permission_field).c_str());
        if (actual == expected) continue;

        EvidenceBuilder ev;
        ev.add("permission_field", permission_field);
        ev.add("expected", expected);
        ev.add("actual", actual);
        out.push_back({
            actual.empty()
                ? "tamper.declared_permission_field.missing"
                : "tamper.declared_permission_field.mismatch",
            Severity::HIGH,
            actual.empty()
                ? "Declared permission field could not be collected"
                : "Declared permission field does not match configured baseline",
            ev.build(),
        });
    }
}

void check_expected_component_signatures(const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    static constexpr char kPrefix[] = "expectedComponentSignatureSha256.";
    for (const auto& [key, expected] : policy) {
        if (key.rfind(kPrefix, 0) != 0) continue;

        const std::string component_key = key.substr(sizeof(kPrefix) - 1);
        const std::string actual = get_or(snapshot, ("componentSignatureSha256." + component_key).c_str());
        if (!actual.empty() && actual == expected) continue;

        EvidenceBuilder ev;
        ev.add("component", component_key);
        ev.add("expected", expected);
        ev.add("actual", actual);
        out.push_back({
            actual.empty()
                ? "tamper.component_signature.missing"
                : "tamper.component_signature.mismatch",
            Severity::HIGH,
            actual.empty()
                ? "Manifest component fingerprint could not be collected"
                : "Manifest component fingerprint does not match configured baseline",
            ev.build(),
        });
    }
}

void check_expected_component_fields(const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    static constexpr char kPrefix[] = "expectedComponentField.";
    for (const auto& [key, expected] : policy) {
        if (key.rfind(kPrefix, 0) != 0) continue;

        const std::string component_field = key.substr(sizeof(kPrefix) - 1);
        const std::string actual = get_or(snapshot, ("componentField." + component_field).c_str());
        if (actual == expected) continue;

        EvidenceBuilder ev;
        ev.add("component_field", component_field);
        ev.add("expected", expected);
        ev.add("actual", actual);
        out.push_back({
            actual.empty()
                ? "tamper.component_field.missing"
                : "tamper.component_field.mismatch",
            Severity::HIGH,
            actual.empty()
                ? "Manifest component field could not be collected"
                : "Manifest component field does not match configured baseline",
            ev.build(),
        });
    }
}

void check_expected_provider_uri_permission_patterns(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    static constexpr char kPrefix[] = "expectedProviderUriPermissionPatternsSha256.";
    for (const auto& [key, expected] : policy) {
        if (key.rfind(kPrefix, 0) != 0) continue;

        const std::string provider_key = key.substr(sizeof(kPrefix) - 1);
        const std::string actual = get_or(snapshot, ("providerUriPermissionPatternsSha256." + provider_key).c_str());
        if (!actual.empty() && actual == expected) continue;

        EvidenceBuilder ev;
        ev.add("provider", provider_key);
        ev.add("expected", expected);
        ev.add("actual", actual);
        out.push_back({
            actual.empty()
                ? "tamper.provider_uri_permission_patterns_hash.missing"
                : "tamper.provider_uri_permission_patterns_hash.mismatch",
            Severity::HIGH,
            actual.empty()
                ? "Provider uriPermissionPatterns fingerprint could not be collected"
                : "Provider uriPermissionPatterns fingerprint does not match configured baseline",
            ev.build(),
        });
    }
}

void check_expected_provider_path_permissions(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    static constexpr char kPrefix[] = "expectedProviderPathPermissionsSha256.";
    for (const auto& [key, expected] : policy) {
        if (key.rfind(kPrefix, 0) != 0) continue;

        const std::string provider_key = key.substr(sizeof(kPrefix) - 1);
        const std::string actual = get_or(snapshot, ("providerPathPermissionsSha256." + provider_key).c_str());
        if (!actual.empty() && actual == expected) continue;

        EvidenceBuilder ev;
        ev.add("provider", provider_key);
        ev.add("expected", expected);
        ev.add("actual", actual);
        out.push_back({
            actual.empty()
                ? "tamper.provider_path_permissions_hash.missing"
                : "tamper.provider_path_permissions_hash.mismatch",
            Severity::HIGH,
            actual.empty()
                ? "Provider pathPermissions fingerprint could not be collected"
                : "Provider pathPermissions fingerprint does not match configured baseline",
            ev.build(),
        });
    }
}

void check_expected_provider_authority_sets(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    static constexpr char kPrefix[] = "expectedProviderAuthoritySetSha256.";
    for (const auto& [key, expected] : policy) {
        if (key.rfind(kPrefix, 0) != 0) continue;

        const std::string provider_key = key.substr(sizeof(kPrefix) - 1);
        const std::string actual = get_or(snapshot, ("providerAuthoritySetSha256." + provider_key).c_str());
        if (!actual.empty() && actual == expected) continue;

        EvidenceBuilder ev;
        ev.add("provider", provider_key);
        ev.add("expected", expected);
        ev.add("actual", actual);
        out.push_back({
            actual.empty()
                ? "tamper.provider_authority_set_hash.missing"
                : "tamper.provider_authority_set_hash.mismatch",
            Severity::HIGH,
            actual.empty()
                ? "Provider authority-set fingerprint could not be collected"
                : "Provider authority-set fingerprint does not match configured baseline",
            ev.build(),
        });
    }
}

void check_expected_provider_semantics(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    static constexpr char kPrefix[] = "expectedProviderSemanticsSha256.";
    for (const auto& [key, expected] : policy) {
        if (key.rfind(kPrefix, 0) != 0) continue;

        const std::string provider_key = key.substr(sizeof(kPrefix) - 1);
        const std::string actual = get_or(snapshot, ("providerSemanticsSha256." + provider_key).c_str());
        if (!actual.empty() && actual == expected) continue;

        EvidenceBuilder ev;
        ev.add("provider", provider_key);
        ev.add("expected", expected);
        ev.add("actual", actual);
        out.push_back({
            actual.empty()
                ? "tamper.provider_semantics_hash.missing"
                : "tamper.provider_semantics_hash.mismatch",
            Severity::HIGH,
            actual.empty()
                ? "Provider semantics fingerprint could not be collected"
                : "Provider semantics fingerprint does not match configured baseline",
            ev.build(),
        });
    }
}

void check_expected_intent_filter_hashes(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    static constexpr char kPrefix[] = "expectedIntentFilterSha256.";
    for (const auto& [key, expected] : policy) {
        if (key.rfind(kPrefix, 0) != 0) continue;

        const std::string component_key = key.substr(sizeof(kPrefix) - 1);
        const std::string actual = get_or(snapshot, ("intentFilterSha256." + component_key).c_str());
        if (!actual.empty() && actual == expected) continue;

        EvidenceBuilder ev;
        ev.add("component", component_key);
        ev.add("expected", expected);
        ev.add("actual", actual);
        out.push_back({
            actual.empty()
                ? "tamper.intent_filter_hash.missing"
                : "tamper.intent_filter_hash.mismatch",
            Severity::HIGH,
            actual.empty()
                ? "Manifest intent-filter fingerprint could not be collected"
                : "Manifest intent-filter fingerprint does not match configured baseline",
            ev.build(),
        });
    }
}

void check_expected_intent_filter_action_hashes(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    static constexpr char kPrefix[] = "expectedIntentFilterActionSha256.";
    for (const auto& [key, expected] : policy) {
        if (key.rfind(kPrefix, 0) != 0) continue;

        const std::string component_key = key.substr(sizeof(kPrefix) - 1);
        const std::string actual = get_or(snapshot, ("intentFilterActionSha256." + component_key).c_str());
        if (!actual.empty() && actual == expected) continue;

        EvidenceBuilder ev;
        ev.add("component", component_key);
        ev.add("expected", expected);
        ev.add("actual", actual);
        out.push_back({
            actual.empty()
                ? "tamper.intent_filter_action_hash.missing"
                : "tamper.intent_filter_action_hash.mismatch",
            Severity::HIGH,
            actual.empty()
                ? "Manifest intent-filter action fingerprint could not be collected"
                : "Manifest intent-filter action fingerprint does not match configured baseline",
            ev.build(),
        });
    }
}

void check_expected_intent_filter_category_hashes(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    static constexpr char kPrefix[] = "expectedIntentFilterCategorySha256.";
    for (const auto& [key, expected] : policy) {
        if (key.rfind(kPrefix, 0) != 0) continue;

        const std::string component_key = key.substr(sizeof(kPrefix) - 1);
        const std::string actual = get_or(snapshot, ("intentFilterCategorySha256." + component_key).c_str());
        if (!actual.empty() && actual == expected) continue;

        EvidenceBuilder ev;
        ev.add("component", component_key);
        ev.add("expected", expected);
        ev.add("actual", actual);
        out.push_back({
            actual.empty()
                ? "tamper.intent_filter_category_hash.missing"
                : "tamper.intent_filter_category_hash.mismatch",
            Severity::HIGH,
            actual.empty()
                ? "Manifest intent-filter category fingerprint could not be collected"
                : "Manifest intent-filter category fingerprint does not match configured baseline",
            ev.build(),
        });
    }
}

void check_expected_intent_filter_data_hashes(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    static constexpr char kPrefix[] = "expectedIntentFilterDataSha256.";
    for (const auto& [key, expected] : policy) {
        if (key.rfind(kPrefix, 0) != 0) continue;

        const std::string component_key = key.substr(sizeof(kPrefix) - 1);
        const std::string actual = get_or(snapshot, ("intentFilterDataSha256." + component_key).c_str());
        if (!actual.empty() && actual == expected) continue;

        EvidenceBuilder ev;
        ev.add("component", component_key);
        ev.add("expected", expected);
        ev.add("actual", actual);
        out.push_back({
            actual.empty()
                ? "tamper.intent_filter_data_hash.missing"
                : "tamper.intent_filter_data_hash.mismatch",
            Severity::HIGH,
            actual.empty()
                ? "Manifest intent-filter data fingerprint could not be collected"
                : "Manifest intent-filter data fingerprint does not match configured baseline",
            ev.build(),
        });
    }
}

void check_expected_intent_filter_data_scheme_hashes(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    static constexpr char kPrefix[] = "expectedIntentFilterDataSchemeSha256.";
    for (const auto& [key, expected] : policy) {
        if (key.rfind(kPrefix, 0) != 0) continue;

        const std::string component_key = key.substr(sizeof(kPrefix) - 1);
        const std::string actual = get_or(snapshot, ("intentFilterDataSchemeSha256." + component_key).c_str());
        if (!actual.empty() && actual == expected) continue;

        EvidenceBuilder ev;
        ev.add("component", component_key);
        ev.add("expected", expected);
        ev.add("actual", actual);
        out.push_back({
            actual.empty()
                ? "tamper.intent_filter_data_scheme_hash.missing"
                : "tamper.intent_filter_data_scheme_hash.mismatch",
            Severity::HIGH,
            actual.empty()
                ? "Manifest intent-filter data scheme fingerprint could not be collected"
                : "Manifest intent-filter data scheme fingerprint does not match configured baseline",
            ev.build(),
        });
    }
}

void check_expected_intent_filter_data_authority_hashes(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    static constexpr char kPrefix[] = "expectedIntentFilterDataAuthoritySha256.";
    for (const auto& [key, expected] : policy) {
        if (key.rfind(kPrefix, 0) != 0) continue;

        const std::string component_key = key.substr(sizeof(kPrefix) - 1);
        const std::string actual = get_or(snapshot, ("intentFilterDataAuthoritySha256." + component_key).c_str());
        if (!actual.empty() && actual == expected) continue;

        EvidenceBuilder ev;
        ev.add("component", component_key);
        ev.add("expected", expected);
        ev.add("actual", actual);
        out.push_back({
            actual.empty()
                ? "tamper.intent_filter_data_authority_hash.missing"
                : "tamper.intent_filter_data_authority_hash.mismatch",
            Severity::HIGH,
            actual.empty()
                ? "Manifest intent-filter data authority fingerprint could not be collected"
                : "Manifest intent-filter data authority fingerprint does not match configured baseline",
            ev.build(),
        });
    }
}

void check_expected_intent_filter_data_path_hashes(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    static constexpr char kPrefix[] = "expectedIntentFilterDataPathSha256.";
    for (const auto& [key, expected] : policy) {
        if (key.rfind(kPrefix, 0) != 0) continue;

        const std::string component_key = key.substr(sizeof(kPrefix) - 1);
        const std::string actual = get_or(snapshot, ("intentFilterDataPathSha256." + component_key).c_str());
        if (!actual.empty() && actual == expected) continue;

        EvidenceBuilder ev;
        ev.add("component", component_key);
        ev.add("expected", expected);
        ev.add("actual", actual);
        out.push_back({
            actual.empty()
                ? "tamper.intent_filter_data_path_hash.missing"
                : "tamper.intent_filter_data_path_hash.mismatch",
            Severity::HIGH,
            actual.empty()
                ? "Manifest intent-filter data path fingerprint could not be collected"
                : "Manifest intent-filter data path fingerprint does not match configured baseline",
            ev.build(),
        });
    }
}

void check_expected_intent_filter_data_mime_type_hashes(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    static constexpr char kPrefix[] = "expectedIntentFilterDataMimeTypeSha256.";
    for (const auto& [key, expected] : policy) {
        if (key.rfind(kPrefix, 0) != 0) continue;

        const std::string component_key = key.substr(sizeof(kPrefix) - 1);
        const std::string actual = get_or(snapshot, ("intentFilterDataMimeTypeSha256." + component_key).c_str());
        if (!actual.empty() && actual == expected) continue;

        EvidenceBuilder ev;
        ev.add("component", component_key);
        ev.add("expected", expected);
        ev.add("actual", actual);
        out.push_back({
            actual.empty()
                ? "tamper.intent_filter_data_mime_type_hash.missing"
                : "tamper.intent_filter_data_mime_type_hash.mismatch",
            Severity::HIGH,
            actual.empty()
                ? "Manifest intent-filter data mimeType fingerprint could not be collected"
                : "Manifest intent-filter data mimeType fingerprint does not match configured baseline",
            ev.build(),
        });
    }
}

void check_expected_grant_uri_permission_hashes(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    static constexpr char kPrefix[] = "expectedGrantUriPermissionSha256.";
    for (const auto& [key, expected] : policy) {
        if (key.rfind(kPrefix, 0) != 0) continue;

        const std::string provider_key = key.substr(sizeof(kPrefix) - 1);
        const std::string actual = get_or(snapshot, ("grantUriPermissionSha256." + provider_key).c_str());
        if (!actual.empty() && actual == expected) continue;

        EvidenceBuilder ev;
        ev.add("provider", provider_key);
        ev.add("expected", expected);
        ev.add("actual", actual);
        out.push_back({
            actual.empty()
                ? "tamper.grant_uri_permission_hash.missing"
                : "tamper.grant_uri_permission_hash.mismatch",
            Severity::HIGH,
            actual.empty()
                ? "Manifest grant-uri-permission fingerprint could not be collected"
                : "Manifest grant-uri-permission fingerprint does not match configured baseline",
            ev.build(),
        });
    }
}

void check_expected_uses_feature_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedUsesFeatureSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "usesFeatureSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.uses_feature_hash.missing"
            : "tamper.uses_feature_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Manifest uses-feature fingerprint could not be collected"
            : "Manifest uses-feature fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_uses_feature_name_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedUsesFeatureNameSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "usesFeatureNameSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.uses_feature_name_hash.missing"
            : "tamper.uses_feature_name_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Manifest uses-feature name fingerprint could not be collected"
            : "Manifest uses-feature name fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_uses_feature_required_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedUsesFeatureRequiredSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "usesFeatureRequiredSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.uses_feature_required_hash.missing"
            : "tamper.uses_feature_required_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Manifest uses-feature required fingerprint could not be collected"
            : "Manifest uses-feature required fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_uses_feature_gles_version_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedUsesFeatureGlEsVersionSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "usesFeatureGlEsVersionSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.uses_feature_gles_version_hash.missing"
            : "tamper.uses_feature_gles_version_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Manifest uses-feature glEsVersion fingerprint could not be collected"
            : "Manifest uses-feature glEsVersion fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_uses_sdk_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedUsesSdkSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "usesSdkSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.uses_sdk_hash.missing"
            : "tamper.uses_sdk_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Manifest uses-sdk fingerprint could not be collected"
            : "Manifest uses-sdk fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_uses_sdk_min_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedUsesSdkMinSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "usesSdkMinSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.uses_sdk_min_hash.missing"
            : "tamper.uses_sdk_min_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Manifest uses-sdk minSdkVersion fingerprint could not be collected"
            : "Manifest uses-sdk minSdkVersion fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_uses_sdk_target_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedUsesSdkTargetSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "usesSdkTargetSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.uses_sdk_target_hash.missing"
            : "tamper.uses_sdk_target_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Manifest uses-sdk targetSdkVersion fingerprint could not be collected"
            : "Manifest uses-sdk targetSdkVersion fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_uses_sdk_max_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedUsesSdkMaxSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "usesSdkMaxSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.uses_sdk_max_hash.missing"
            : "tamper.uses_sdk_max_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Manifest uses-sdk maxSdkVersion fingerprint could not be collected"
            : "Manifest uses-sdk maxSdkVersion fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_supports_screens_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedSupportsScreensSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "supportsScreensSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.supports_screens_hash.missing"
            : "tamper.supports_screens_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Manifest supports-screens fingerprint could not be collected"
            : "Manifest supports-screens fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_supports_screens_small_screens_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    check_optional_hash(
        snapshot,
        policy,
        "expectedSupportsScreensSmallScreensSha256",
        "supportsScreensSmallScreensSha256",
        "tamper.supports_screens_small_screens_hash.missing",
        "tamper.supports_screens_small_screens_hash.mismatch",
        "Manifest supports-screens smallScreens fingerprint could not be collected",
        "Manifest supports-screens smallScreens fingerprint does not match configured baseline",
        out);
}

void check_expected_supports_screens_normal_screens_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    check_optional_hash(
        snapshot,
        policy,
        "expectedSupportsScreensNormalScreensSha256",
        "supportsScreensNormalScreensSha256",
        "tamper.supports_screens_normal_screens_hash.missing",
        "tamper.supports_screens_normal_screens_hash.mismatch",
        "Manifest supports-screens normalScreens fingerprint could not be collected",
        "Manifest supports-screens normalScreens fingerprint does not match configured baseline",
        out);
}

void check_expected_supports_screens_large_screens_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    check_optional_hash(
        snapshot,
        policy,
        "expectedSupportsScreensLargeScreensSha256",
        "supportsScreensLargeScreensSha256",
        "tamper.supports_screens_large_screens_hash.missing",
        "tamper.supports_screens_large_screens_hash.mismatch",
        "Manifest supports-screens largeScreens fingerprint could not be collected",
        "Manifest supports-screens largeScreens fingerprint does not match configured baseline",
        out);
}

void check_expected_supports_screens_xlarge_screens_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    check_optional_hash(
        snapshot,
        policy,
        "expectedSupportsScreensXlargeScreensSha256",
        "supportsScreensXlargeScreensSha256",
        "tamper.supports_screens_xlarge_screens_hash.missing",
        "tamper.supports_screens_xlarge_screens_hash.mismatch",
        "Manifest supports-screens xlargeScreens fingerprint could not be collected",
        "Manifest supports-screens xlargeScreens fingerprint does not match configured baseline",
        out);
}

void check_expected_supports_screens_resizeable_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    check_optional_hash(
        snapshot,
        policy,
        "expectedSupportsScreensResizeableSha256",
        "supportsScreensResizeableSha256",
        "tamper.supports_screens_resizeable_hash.missing",
        "tamper.supports_screens_resizeable_hash.mismatch",
        "Manifest supports-screens resizeable fingerprint could not be collected",
        "Manifest supports-screens resizeable fingerprint does not match configured baseline",
        out);
}

void check_expected_supports_screens_any_density_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    check_optional_hash(
        snapshot,
        policy,
        "expectedSupportsScreensAnyDensitySha256",
        "supportsScreensAnyDensitySha256",
        "tamper.supports_screens_any_density_hash.missing",
        "tamper.supports_screens_any_density_hash.mismatch",
        "Manifest supports-screens anyDensity fingerprint could not be collected",
        "Manifest supports-screens anyDensity fingerprint does not match configured baseline",
        out);
}

void check_expected_supports_screens_requires_smallest_width_dp_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    check_optional_hash(
        snapshot,
        policy,
        "expectedSupportsScreensRequiresSmallestWidthDpSha256",
        "supportsScreensRequiresSmallestWidthDpSha256",
        "tamper.supports_screens_requires_smallest_width_dp_hash.missing",
        "tamper.supports_screens_requires_smallest_width_dp_hash.mismatch",
        "Manifest supports-screens requiresSmallestWidthDp fingerprint could not be collected",
        "Manifest supports-screens requiresSmallestWidthDp fingerprint does not match configured baseline",
        out);
}

void check_expected_supports_screens_compatible_width_limit_dp_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    check_optional_hash(
        snapshot,
        policy,
        "expectedSupportsScreensCompatibleWidthLimitDpSha256",
        "supportsScreensCompatibleWidthLimitDpSha256",
        "tamper.supports_screens_compatible_width_limit_dp_hash.missing",
        "tamper.supports_screens_compatible_width_limit_dp_hash.mismatch",
        "Manifest supports-screens compatibleWidthLimitDp fingerprint could not be collected",
        "Manifest supports-screens compatibleWidthLimitDp fingerprint does not match configured baseline",
        out);
}

void check_expected_supports_screens_largest_width_limit_dp_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    check_optional_hash(
        snapshot,
        policy,
        "expectedSupportsScreensLargestWidthLimitDpSha256",
        "supportsScreensLargestWidthLimitDpSha256",
        "tamper.supports_screens_largest_width_limit_dp_hash.missing",
        "tamper.supports_screens_largest_width_limit_dp_hash.mismatch",
        "Manifest supports-screens largestWidthLimitDp fingerprint could not be collected",
        "Manifest supports-screens largestWidthLimitDp fingerprint does not match configured baseline",
        out);
}

void check_expected_compatible_screens_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedCompatibleScreensSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "compatibleScreensSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.compatible_screens_hash.missing"
            : "tamper.compatible_screens_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Manifest compatible-screens fingerprint could not be collected"
            : "Manifest compatible-screens fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_compatible_screens_screen_size_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    check_optional_hash(
        snapshot,
        policy,
        "expectedCompatibleScreensScreenSizeSha256",
        "compatibleScreensScreenSizeSha256",
        "tamper.compatible_screens_screen_size_hash.missing",
        "tamper.compatible_screens_screen_size_hash.mismatch",
        "Manifest compatible-screens screenSize fingerprint could not be collected",
        "Manifest compatible-screens screenSize fingerprint does not match configured baseline",
        out);
}

void check_expected_compatible_screens_screen_density_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    check_optional_hash(
        snapshot,
        policy,
        "expectedCompatibleScreensScreenDensitySha256",
        "compatibleScreensScreenDensitySha256",
        "tamper.compatible_screens_screen_density_hash.missing",
        "tamper.compatible_screens_screen_density_hash.mismatch",
        "Manifest compatible-screens screenDensity fingerprint could not be collected",
        "Manifest compatible-screens screenDensity fingerprint does not match configured baseline",
        out);
}

void check_expected_uses_library_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedUsesLibrarySha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "usesLibrarySha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.uses_library_hash.missing"
            : "tamper.uses_library_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Manifest uses-library fingerprint could not be collected"
            : "Manifest uses-library fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_uses_library_name_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    check_optional_hash(
        snapshot,
        policy,
        "expectedUsesLibraryNameSha256",
        "usesLibraryNameSha256",
        "tamper.uses_library_name_hash.missing",
        "tamper.uses_library_name_hash.mismatch",
        "Manifest uses-library name fingerprint could not be collected",
        "Manifest uses-library name fingerprint does not match configured baseline",
        out);
}

void check_expected_uses_library_required_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    check_optional_hash(
        snapshot,
        policy,
        "expectedUsesLibraryRequiredSha256",
        "usesLibraryRequiredSha256",
        "tamper.uses_library_required_hash.missing",
        "tamper.uses_library_required_hash.mismatch",
        "Manifest uses-library required fingerprint could not be collected",
        "Manifest uses-library required fingerprint does not match configured baseline",
        out);
}

void check_expected_uses_library_only_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedUsesLibraryOnlySha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "usesLibraryOnlySha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.uses_library_only_hash.missing"
            : "tamper.uses_library_only_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Manifest uses-library-only fingerprint could not be collected"
            : "Manifest uses-library-only fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_uses_library_only_name_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    check_optional_hash(
        snapshot,
        policy,
        "expectedUsesLibraryOnlyNameSha256",
        "usesLibraryOnlyNameSha256",
        "tamper.uses_library_only_name_hash.missing",
        "tamper.uses_library_only_name_hash.mismatch",
        "Manifest uses-library-only name fingerprint could not be collected",
        "Manifest uses-library-only name fingerprint does not match configured baseline",
        out);
}

void check_expected_uses_library_only_required_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    check_optional_hash(
        snapshot,
        policy,
        "expectedUsesLibraryOnlyRequiredSha256",
        "usesLibraryOnlyRequiredSha256",
        "tamper.uses_library_only_required_hash.missing",
        "tamper.uses_library_only_required_hash.mismatch",
        "Manifest uses-library-only required fingerprint could not be collected",
        "Manifest uses-library-only required fingerprint does not match configured baseline",
        out);
}

void check_expected_uses_native_library_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedUsesNativeLibrarySha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "usesNativeLibrarySha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.uses_native_library_hash.missing"
            : "tamper.uses_native_library_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Manifest uses-native-library fingerprint could not be collected"
            : "Manifest uses-native-library fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_uses_native_library_name_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    check_optional_hash(
        snapshot,
        policy,
        "expectedUsesNativeLibraryNameSha256",
        "usesNativeLibraryNameSha256",
        "tamper.uses_native_library_name_hash.missing",
        "tamper.uses_native_library_name_hash.mismatch",
        "Manifest uses-native-library name fingerprint could not be collected",
        "Manifest uses-native-library name fingerprint does not match configured baseline",
        out);
}

void check_expected_uses_native_library_required_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    check_optional_hash(
        snapshot,
        policy,
        "expectedUsesNativeLibraryRequiredSha256",
        "usesNativeLibraryRequiredSha256",
        "tamper.uses_native_library_required_hash.missing",
        "tamper.uses_native_library_required_hash.mismatch",
        "Manifest uses-native-library required fingerprint could not be collected",
        "Manifest uses-native-library required fingerprint does not match configured baseline",
        out);
}

void check_expected_queries_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedQueriesSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "queriesSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.queries_hash.missing"
            : "tamper.queries_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Manifest queries fingerprint could not be collected"
            : "Manifest queries fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_queries_package_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedQueriesPackageSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "queriesPackageSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.queries_package_hash.missing"
            : "tamper.queries_package_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Manifest queries package fingerprint could not be collected"
            : "Manifest queries package fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_queries_package_name_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedQueriesPackageNameSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "queriesPackageNameSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.queries_package_name_hash.missing"
            : "tamper.queries_package_name_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Manifest queries package-name fingerprint could not be collected"
            : "Manifest queries package-name fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_queries_provider_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedQueriesProviderSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "queriesProviderSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.queries_provider_hash.missing"
            : "tamper.queries_provider_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Manifest queries provider fingerprint could not be collected"
            : "Manifest queries provider fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_queries_provider_authority_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedQueriesProviderAuthoritySha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "queriesProviderAuthoritySha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.queries_provider_authority_hash.missing"
            : "tamper.queries_provider_authority_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Manifest queries provider-authority fingerprint could not be collected"
            : "Manifest queries provider-authority fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_queries_intent_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedQueriesIntentSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "queriesIntentSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.queries_intent_hash.missing"
            : "tamper.queries_intent_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Manifest queries intent fingerprint could not be collected"
            : "Manifest queries intent fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_queries_intent_action_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedQueriesIntentActionSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "queriesIntentActionSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.queries_intent_action_hash.missing"
            : "tamper.queries_intent_action_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Manifest queries intent action fingerprint could not be collected"
            : "Manifest queries intent action fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_queries_intent_category_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedQueriesIntentCategorySha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "queriesIntentCategorySha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.queries_intent_category_hash.missing"
            : "tamper.queries_intent_category_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Manifest queries intent category fingerprint could not be collected"
            : "Manifest queries intent category fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_queries_intent_data_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedQueriesIntentDataSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "queriesIntentDataSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.queries_intent_data_hash.missing"
            : "tamper.queries_intent_data_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Manifest queries intent data fingerprint could not be collected"
            : "Manifest queries intent data fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_queries_intent_data_scheme_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedQueriesIntentDataSchemeSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "queriesIntentDataSchemeSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.queries_intent_data_scheme_hash.missing"
            : "tamper.queries_intent_data_scheme_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Manifest queries intent data scheme fingerprint could not be collected"
            : "Manifest queries intent data scheme fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_queries_intent_data_authority_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedQueriesIntentDataAuthoritySha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "queriesIntentDataAuthoritySha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.queries_intent_data_authority_hash.missing"
            : "tamper.queries_intent_data_authority_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Manifest queries intent data authority fingerprint could not be collected"
            : "Manifest queries intent data authority fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_queries_intent_data_path_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedQueriesIntentDataPathSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "queriesIntentDataPathSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.queries_intent_data_path_hash.missing"
            : "tamper.queries_intent_data_path_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Manifest queries intent data path fingerprint could not be collected"
            : "Manifest queries intent data path fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_queries_intent_data_mime_type_hash(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedQueriesIntentDataMimeTypeSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "queriesIntentDataMimeTypeSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.queries_intent_data_mime_type_hash.missing"
            : "tamper.queries_intent_data_mime_type_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Manifest queries intent data mimeType fingerprint could not be collected"
            : "Manifest queries intent data mimeType fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_application_fields(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    static constexpr char kPrefix[] = "expectedApplicationField.";
    for (const auto& [key, expected] : policy) {
        if (key.rfind(kPrefix, 0) != 0) continue;

        const std::string field_key = key.substr(sizeof(kPrefix) - 1);
        const std::string actual = get_or(snapshot, ("applicationField." + field_key).c_str());
        if (actual == expected) continue;

        EvidenceBuilder ev;
        ev.add("application_field", field_key);
        ev.add("expected", expected);
        ev.add("actual", actual);
        out.push_back({
            actual.empty()
                ? "tamper.application_field.missing"
                : "tamper.application_field.mismatch",
            Severity::HIGH,
            actual.empty()
                ? "Manifest application field could not be collected"
                : "Manifest application field does not match configured baseline",
            ev.build(),
        });
    }
}

void check_expected_application_semantics(
    const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    const std::string expected = get_or(policy, "expectedApplicationSemanticsSha256");
    if (expected.empty()) return;

    const std::string actual = get_or(snapshot, "applicationSemanticsSha256");
    if (!actual.empty() && actual == expected) return;

    EvidenceBuilder ev;
    ev.add("expected", expected);
    ev.add("actual", actual);
    out.push_back({
        actual.empty()
            ? "tamper.application_semantics_hash.missing"
            : "tamper.application_semantics_hash.mismatch",
        Severity::HIGH,
        actual.empty()
            ? "Manifest application semantics fingerprint could not be collected"
            : "Manifest application semantics fingerprint does not match configured baseline",
        ev.build(),
    });
}

void check_expected_metadata(const Snapshot& snapshot, const Snapshot& policy, EventList& out) {
    static constexpr char kPrefix[] = "expectedMetaData.";
    for (const auto& [key, expected] : policy) {
        if (key.rfind(kPrefix, 0) != 0) continue;

        const std::string meta_key = key.substr(sizeof(kPrefix) - 1);
        const std::string actual = get_or(snapshot, ("metaData." + meta_key).c_str());
        if (actual == expected) continue;

        EvidenceBuilder ev;
        ev.add("meta_key", meta_key);
        ev.add("expected", expected);
        ev.add("actual", actual);
        out.push_back({
            actual.empty() ? "tamper.metadata.missing" : "tamper.metadata.mismatch",
            Severity::HIGH,
            actual.empty()
                ? "Manifest meta-data value is missing"
                : "Manifest meta-data value does not match configured baseline",
            ev.build(),
        });
    }
}

void check_source_dir(const Snapshot& snapshot, EventList& out) {
    const std::string source_dir = get_or(snapshot, "sourceDir");
    if (source_dir.empty()) {
        EvidenceBuilder ev;
        ev.add("package", get_or(snapshot, "package"));
        out.push_back({
            "tamper.source_dir.missing",
            Severity::HIGH,
            "Application sourceDir is missing from integrity snapshot",
            ev.build(),
        });
        return;
    }

    if (source_dir.size() < 4 || source_dir.rfind(".apk") != source_dir.size() - 4) {
        EvidenceBuilder ev;
        ev.add("sourceDir", source_dir);
        out.push_back({
            "tamper.source_dir.non_apk",
            Severity::MEDIUM,
            "Application sourceDir does not end with .apk",
            ev.build(),
        });
    }
}

void check_signing_digests(const Snapshot& snapshot, EventList& out) {
    const std::string digests = get_or(snapshot, "certSha256");
    if (!digests.empty()) return;

    EvidenceBuilder ev;
    ev.add("package", get_or(snapshot, "package"));
    out.push_back({
        "tamper.signature.missing",
        Severity::HIGH,
        "Signing certificate digest list is empty",
        ev.build(),
    });
}

void check_package_name(const Snapshot& snapshot, EventList& out) {
    const std::string package_name = get_or(snapshot, "package");
    if (!package_name.empty()) return;

    out.push_back({
        "tamper.package_name.missing",
        Severity::HIGH,
        "Package name missing from integrity snapshot",
        {},
    });
}

}  // namespace

EventList scan_tamper() {
    EventList events;

    const auto snapshot = parse_snapshot(globals().integrity_blob);
    const auto policy = parse_snapshot(globals().tamper_policy_blob);
    auto catalog = tamper_check_catalog();
#if __has_include("private_tamper_catalog.h")
    catalog = apply_private_tamper_check_catalog(catalog);
#endif
    if (snapshot.empty()) {
        events.push_back({
            "tamper.snapshot.unavailable",
            Severity::LOW,
            "App integrity snapshot unavailable — tamper baseline not initialized",
            {},
        });
        return events;
    }

    check_package_name(snapshot, events);
    check_debuggable(snapshot, events);
    check_installer(snapshot, events);
    check_source_dir(snapshot, events);
    check_signing_digests(snapshot, events);
    if (catalog.expected_package) check_expected_package(snapshot, policy, events);
    if (catalog.allowed_installers) check_allowed_installers(snapshot, policy, events);
    if (catalog.allowed_signing_certs) check_allowed_signing_certs(snapshot, policy, events);
    if (catalog.expected_apk_hash) check_expected_apk_hash(snapshot, policy, events);
    if (catalog.expected_manifest_hash) check_expected_manifest_hash(snapshot, policy, events);
    if (catalog.expected_lib_hashes) check_expected_lib_hashes(snapshot, policy, events);
    if (catalog.expected_dex_hashes) check_expected_dex_hashes(snapshot, policy, events);
    if (catalog.expected_dex_section_hashes) check_expected_dex_section_hashes(snapshot, policy, events);
    if (catalog.expected_dex_method_hashes) check_expected_dex_method_hashes(snapshot, policy, events);
    if (catalog.expected_split_hashes) check_expected_split_hashes(snapshot, policy, events);
    if (catalog.expected_split_inventory) check_expected_split_inventory(snapshot, policy, events);
    if (catalog.expected_dynamic_feature_splits) {
        check_expected_dynamic_feature_splits(snapshot, policy, events);
    }
    if (catalog.expected_dynamic_feature_split_names) {
        check_expected_dynamic_feature_split_names(snapshot, policy, events);
    }
    if (catalog.expected_config_split_axes) {
        check_expected_config_split_axes(snapshot, policy, events);
    }
    if (catalog.expected_config_split_names) {
        check_expected_config_split_names(snapshot, policy, events);
    }
    if (catalog.expected_config_split_abis) {
        check_expected_config_split_abis(snapshot, policy, events);
    }
    if (catalog.expected_config_split_locales) {
        check_expected_config_split_locales(snapshot, policy, events);
    }
    if (catalog.expected_config_split_densities) {
        check_expected_config_split_densities(snapshot, policy, events);
    }
    if (catalog.expected_elf_section_hashes) check_expected_elf_section_hashes(snapshot, policy, events);
    if (catalog.expected_elf_export_symbol_hashes) check_expected_elf_export_symbol_hashes(snapshot, policy, events);
    if (catalog.expected_elf_export_graph_hashes) check_expected_elf_export_graph_hashes(snapshot, policy, events);
    if (catalog.expected_requested_permissions) check_expected_requested_permissions(snapshot, policy, events);
    if (catalog.expected_requested_permission_semantics) {
        check_expected_requested_permission_semantics(snapshot, policy, events);
    }
    if (catalog.expected_declared_permission_semantics) {
        check_expected_declared_permission_semantics(snapshot, policy, events);
    }
    if (catalog.expected_declared_permission_fields) {
        check_expected_declared_permission_fields(snapshot, policy, events);
    }
    if (catalog.expected_component_signatures) check_expected_component_signatures(snapshot, policy, events);
    if (catalog.expected_component_fields) check_expected_component_fields(snapshot, policy, events);
    if (catalog.expected_provider_uri_permission_patterns) {
        check_expected_provider_uri_permission_patterns(snapshot, policy, events);
    }
    if (catalog.expected_provider_path_permissions) {
        check_expected_provider_path_permissions(snapshot, policy, events);
    }
    if (catalog.expected_provider_authority_sets) {
        check_expected_provider_authority_sets(snapshot, policy, events);
    }
    if (catalog.expected_provider_semantics) {
        check_expected_provider_semantics(snapshot, policy, events);
    }
    if (catalog.expected_intent_filter_hashes) check_expected_intent_filter_hashes(snapshot, policy, events);
    if (catalog.expected_intent_filter_action_hashes) {
        check_expected_intent_filter_action_hashes(snapshot, policy, events);
    }
    if (catalog.expected_intent_filter_category_hashes) {
        check_expected_intent_filter_category_hashes(snapshot, policy, events);
    }
    if (catalog.expected_intent_filter_data_hashes) {
        check_expected_intent_filter_data_hashes(snapshot, policy, events);
    }
    if (catalog.expected_intent_filter_data_scheme_hashes) {
        check_expected_intent_filter_data_scheme_hashes(snapshot, policy, events);
    }
    if (catalog.expected_intent_filter_data_authority_hashes) {
        check_expected_intent_filter_data_authority_hashes(snapshot, policy, events);
    }
    if (catalog.expected_intent_filter_data_path_hashes) {
        check_expected_intent_filter_data_path_hashes(snapshot, policy, events);
    }
    if (catalog.expected_intent_filter_data_mime_type_hashes) {
        check_expected_intent_filter_data_mime_type_hashes(snapshot, policy, events);
    }
    if (catalog.expected_grant_uri_permission_hashes) {
        check_expected_grant_uri_permission_hashes(snapshot, policy, events);
    }
    if (catalog.expected_uses_feature_hash) {
        check_expected_uses_feature_hash(snapshot, policy, events);
    }
    if (catalog.expected_uses_feature_name_hash) {
        check_expected_uses_feature_name_hash(snapshot, policy, events);
    }
    if (catalog.expected_uses_feature_required_hash) {
        check_expected_uses_feature_required_hash(snapshot, policy, events);
    }
    if (catalog.expected_uses_feature_gles_version_hash) {
        check_expected_uses_feature_gles_version_hash(snapshot, policy, events);
    }
    if (catalog.expected_uses_sdk_hash) {
        check_expected_uses_sdk_hash(snapshot, policy, events);
    }
    if (catalog.expected_uses_sdk_min_hash) {
        check_expected_uses_sdk_min_hash(snapshot, policy, events);
    }
    if (catalog.expected_uses_sdk_target_hash) {
        check_expected_uses_sdk_target_hash(snapshot, policy, events);
    }
    if (catalog.expected_uses_sdk_max_hash) {
        check_expected_uses_sdk_max_hash(snapshot, policy, events);
    }
    if (catalog.expected_supports_screens_hash) {
        check_expected_supports_screens_hash(snapshot, policy, events);
    }
    if (catalog.expected_supports_screens_small_screens_hash) {
        check_expected_supports_screens_small_screens_hash(snapshot, policy, events);
    }
    if (catalog.expected_supports_screens_normal_screens_hash) {
        check_expected_supports_screens_normal_screens_hash(snapshot, policy, events);
    }
    if (catalog.expected_supports_screens_large_screens_hash) {
        check_expected_supports_screens_large_screens_hash(snapshot, policy, events);
    }
    if (catalog.expected_supports_screens_xlarge_screens_hash) {
        check_expected_supports_screens_xlarge_screens_hash(snapshot, policy, events);
    }
    if (catalog.expected_supports_screens_resizeable_hash) {
        check_expected_supports_screens_resizeable_hash(snapshot, policy, events);
    }
    if (catalog.expected_supports_screens_any_density_hash) {
        check_expected_supports_screens_any_density_hash(snapshot, policy, events);
    }
    if (catalog.expected_supports_screens_requires_smallest_width_dp_hash) {
        check_expected_supports_screens_requires_smallest_width_dp_hash(snapshot, policy, events);
    }
    if (catalog.expected_supports_screens_compatible_width_limit_dp_hash) {
        check_expected_supports_screens_compatible_width_limit_dp_hash(snapshot, policy, events);
    }
    if (catalog.expected_supports_screens_largest_width_limit_dp_hash) {
        check_expected_supports_screens_largest_width_limit_dp_hash(snapshot, policy, events);
    }
    if (catalog.expected_compatible_screens_hash) {
        check_expected_compatible_screens_hash(snapshot, policy, events);
    }
    if (catalog.expected_compatible_screens_screen_size_hash) {
        check_expected_compatible_screens_screen_size_hash(snapshot, policy, events);
    }
    if (catalog.expected_compatible_screens_screen_density_hash) {
        check_expected_compatible_screens_screen_density_hash(snapshot, policy, events);
    }
    if (catalog.expected_uses_library_hash) {
        check_expected_uses_library_hash(snapshot, policy, events);
    }
    if (catalog.expected_uses_library_name_hash) {
        check_expected_uses_library_name_hash(snapshot, policy, events);
    }
    if (catalog.expected_uses_library_required_hash) {
        check_expected_uses_library_required_hash(snapshot, policy, events);
    }
    if (catalog.expected_uses_library_only_hash) {
        check_expected_uses_library_only_hash(snapshot, policy, events);
    }
    if (catalog.expected_uses_library_only_name_hash) {
        check_expected_uses_library_only_name_hash(snapshot, policy, events);
    }
    if (catalog.expected_uses_library_only_required_hash) {
        check_expected_uses_library_only_required_hash(snapshot, policy, events);
    }
    if (catalog.expected_uses_native_library_hash) {
        check_expected_uses_native_library_hash(snapshot, policy, events);
    }
    if (catalog.expected_uses_native_library_name_hash) {
        check_expected_uses_native_library_name_hash(snapshot, policy, events);
    }
    if (catalog.expected_uses_native_library_required_hash) {
        check_expected_uses_native_library_required_hash(snapshot, policy, events);
    }
    if (catalog.expected_queries_hash) {
        check_expected_queries_hash(snapshot, policy, events);
    }
    if (catalog.expected_queries_package_hash) {
        check_expected_queries_package_hash(snapshot, policy, events);
    }
    if (catalog.expected_queries_package_name_hash) {
        check_expected_queries_package_name_hash(snapshot, policy, events);
    }
    if (catalog.expected_queries_provider_hash) {
        check_expected_queries_provider_hash(snapshot, policy, events);
    }
    if (catalog.expected_queries_provider_authority_hash) {
        check_expected_queries_provider_authority_hash(snapshot, policy, events);
    }
    if (catalog.expected_queries_intent_hash) {
        check_expected_queries_intent_hash(snapshot, policy, events);
    }
    if (catalog.expected_queries_intent_action_hash) {
        check_expected_queries_intent_action_hash(snapshot, policy, events);
    }
    if (catalog.expected_queries_intent_category_hash) {
        check_expected_queries_intent_category_hash(snapshot, policy, events);
    }
    if (catalog.expected_queries_intent_data_hash) {
        check_expected_queries_intent_data_hash(snapshot, policy, events);
    }
    if (catalog.expected_queries_intent_data_scheme_hash) {
        check_expected_queries_intent_data_scheme_hash(snapshot, policy, events);
    }
    if (catalog.expected_queries_intent_data_authority_hash) {
        check_expected_queries_intent_data_authority_hash(snapshot, policy, events);
    }
    if (catalog.expected_queries_intent_data_path_hash) {
        check_expected_queries_intent_data_path_hash(snapshot, policy, events);
    }
    if (catalog.expected_queries_intent_data_mime_type_hash) {
        check_expected_queries_intent_data_mime_type_hash(snapshot, policy, events);
    }
    if (catalog.expected_application_semantics) {
        check_expected_application_semantics(snapshot, policy, events);
    }
    if (catalog.expected_application_fields) {
        check_expected_application_fields(snapshot, policy, events);
    }
    if (catalog.expected_metadata) check_expected_metadata(snapshot, policy, events);

    return events;
}

}  // namespace leona::detection
