/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
#pragma once

namespace leona::detection {

struct TamperCheckCatalog {
    bool expected_package = false;
    bool allowed_installers = false;
    bool allowed_signing_certs = false;
    bool expected_apk_hash = false;
    bool expected_manifest_hash = false;
    bool expected_lib_hashes = false;
    bool expected_dex_hashes = false;
    bool expected_dex_section_hashes = false;
    bool expected_dex_method_hashes = false;
    bool expected_split_hashes = false;
    bool expected_split_inventory = false;
    bool expected_dynamic_feature_splits = false;
    bool expected_dynamic_feature_split_names = false;
    bool expected_config_split_axes = false;
    bool expected_config_split_names = false;
    bool expected_config_split_abis = false;
    bool expected_config_split_locales = false;
    bool expected_config_split_densities = false;
    bool expected_elf_section_hashes = false;
    bool expected_elf_export_symbol_hashes = false;
    bool expected_elf_export_graph_hashes = false;
    bool expected_requested_permissions = false;
    bool expected_requested_permission_semantics = false;
    bool expected_declared_permission_semantics = false;
    bool expected_declared_permission_fields = false;
    bool expected_component_signatures = false;
    bool expected_component_fields = false;
    bool expected_provider_uri_permission_patterns = false;
    bool expected_provider_path_permissions = false;
    bool expected_provider_authority_sets = false;
    bool expected_provider_semantics = false;
    bool expected_intent_filter_hashes = false;
    bool expected_intent_filter_action_hashes = false;
    bool expected_intent_filter_category_hashes = false;
    bool expected_intent_filter_data_hashes = false;
    bool expected_intent_filter_data_scheme_hashes = false;
    bool expected_intent_filter_data_authority_hashes = false;
    bool expected_intent_filter_data_path_hashes = false;
    bool expected_intent_filter_data_mime_type_hashes = false;
    bool expected_grant_uri_permission_hashes = false;
    bool expected_uses_feature_hash = false;
    bool expected_uses_feature_name_hash = false;
    bool expected_uses_feature_required_hash = false;
    bool expected_uses_feature_gles_version_hash = false;
    bool expected_uses_sdk_hash = false;
    bool expected_uses_sdk_min_hash = false;
    bool expected_uses_sdk_target_hash = false;
    bool expected_uses_sdk_max_hash = false;
    bool expected_supports_screens_hash = false;
    bool expected_compatible_screens_hash = false;
    bool expected_uses_library_hash = false;
    bool expected_uses_library_only_hash = false;
    bool expected_uses_native_library_hash = false;
    bool expected_queries_hash = false;
    bool expected_queries_package_hash = false;
    bool expected_queries_package_name_hash = false;
    bool expected_queries_provider_hash = false;
    bool expected_queries_provider_authority_hash = false;
    bool expected_queries_intent_hash = false;
    bool expected_queries_intent_action_hash = false;
    bool expected_queries_intent_category_hash = false;
    bool expected_queries_intent_data_hash = false;
    bool expected_queries_intent_data_scheme_hash = false;
    bool expected_queries_intent_data_authority_hash = false;
    bool expected_queries_intent_data_path_hash = false;
    bool expected_queries_intent_data_mime_type_hash = false;
    bool expected_application_semantics = false;
    bool expected_application_fields = false;
    bool expected_metadata = false;
};

// Public fallback tamper catalog.
//
// The open-source build keeps only the baseline runtime-integrity checks
// (debuggable / installer-missing / sourceDir / signing digests). The deeper
// app-baseline policy comparisons can live in the private module via
// `private_tamper_catalog.h`.
inline TamperCheckCatalog tamper_check_catalog() {
    return {};
}

}  // namespace leona::detection
