/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 *
 * Emulator fingerprint scanner.
 *
 * Covers the mainstream Android emulators used in 2026:
 *   - Android Studio AVD (Goldfish, Ranchu kernels)
 *   - Genymotion (VirtualBox-backed, vbox86 signature)
 *   - LDPlayer   (very popular for game cheating)
 *   - NoxPlayer
 *   - MuMu / MuMu Pro
 *   - BlueStacks
 *   - Cloud phones (YunMi, Redfinger, Cloud-equivalents) — partial
 */
#include "environment_detector.h"
#if __has_include("private_environment_catalog.h")
#include "private_environment_catalog.h"
#else
#include "environment_catalog.h"
#endif

#include <sys/stat.h>
#include <sys/system_properties.h>
#include <dirent.h>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "../util/evidence_builder.h"

namespace leona::detection {

namespace {

std::string read_prop(const char* key) {
    char buf[PROP_VALUE_MAX] = {};
    __system_property_get(key, buf);
    return std::string(buf);
}

std::string read_file_prefix(const char* path, size_t max_bytes = 64 * 1024) {
    FILE* f = std::fopen(path, "r");
    if (!f) return {};

    std::string out;
    out.reserve(std::min<size_t>(max_bytes, 4096));
    char buf[512];
    while (out.size() < max_bytes) {
        const size_t want = std::min(sizeof(buf), max_bytes - out.size());
        const size_t n = std::fread(buf, 1, want, f);
        if (n == 0) break;
        out.append(buf, n);
    }
    std::fclose(f);
    return out;
}

bool file_exists(const char* path) {
    struct stat s;
    return ::stat(path, &s) == 0;
}

bool contains(const std::string& haystack, const char* needle) {
    return haystack.find(needle) != std::string::npos;
}

std::string lower_copy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

bool contains_ci(const std::string& haystack, const char* needle) {
    return lower_copy(haystack).find(lower_copy(std::string(needle))) != std::string::npos;
}

size_t count_occurrences(const std::string& haystack, const char* needle) {
    if (!needle || needle[0] == '\0') return 0;
    size_t count = 0;
    size_t pos = 0;
    while ((pos = haystack.find(needle, pos)) != std::string::npos) {
        ++count;
        pos += std::strlen(needle);
    }
    return count;
}

std::string sanitize_sample(std::string value, size_t max_len = 160) {
    for (char& c : value) {
        if (c == '\t') c = ' ';
        if (c == '\n' || c == '\r' || c == ';') c = ',';
    }
    if (value.size() > max_len) {
        value.resize(max_len);
        value += "...";
    }
    return value;
}

std::string first_matching_line(const std::string& text, const char* needle) {
    const std::string lowered_text = lower_copy(text);
    const std::string lowered_needle = lower_copy(std::string(needle));
    size_t pos = lowered_text.find(lowered_needle);
    if (pos == std::string::npos) return {};

    const size_t start = text.rfind('\n', pos);
    const size_t end = text.find('\n', pos);
    const size_t line_start = start == std::string::npos ? 0 : start + 1;
    const size_t line_end = end == std::string::npos ? text.size() : end;
    return sanitize_sample(text.substr(line_start, line_end - line_start));
}

void add_event(
    EventList& out,
    const char* id,
    Severity severity,
    const char* message,
    const EvidenceBuilder& evidence
) {
    out.push_back({ id, severity, message, evidence.build() });
}

void check_props(EventList& out) {
    for (const auto& p : environment_prop_matches()) {
        const std::string v = read_prop(p.prop);
        if (v.empty()) continue;
        if (contains(v, p.needle)) {
            EvidenceBuilder ev;
            ev.add("prop", p.prop);
            ev.add("value", v);
            out.push_back({ p.id, p.severity, p.message, ev.build() });
        }
    }
}

void check_files(EventList& out) {
    for (const auto& f : environment_file_matches()) {
        if (file_exists(f.path)) {
            EvidenceBuilder ev;
            ev.add("path", f.path);
            out.push_back({
                f.id,
                f.severity,
                f.message,
                ev.build(),
            });
        }
    }
}

void check_virtualization_props(EventList& out) {
    struct PropNeedle {
        const char* prop;
        const char* needle;
        const char* id;
        const char* message;
        Severity severity;
    };

    static const PropNeedle kRuntimeProps[] = {
        {
            "ro.build.hv.platform",
            "qemu",
            "env.emulator.runtime.hypervisor_prop",
            "Android property exposes a QEMU hypervisor backend",
            Severity::HIGH,
        },
        {
            "ro.kernel.qemu",
            "1",
            "env.emulator.runtime.qemu_kernel",
            "Kernel boot properties expose QEMU runtime",
            Severity::HIGH,
        },
        {
            "ro.boot.qemu",
            "1",
            "env.emulator.runtime.qemu_boot",
            "Boot properties expose QEMU runtime",
            Severity::HIGH,
        },
        {
            "ro.build.version.nemux",
            "true",
            "env.emulator.runtime.guest_layer",
            "Guest OS exposes an emulator compatibility layer",
            Severity::HIGH,
        },
        {
            "qemu.hw.mainkeys",
            "1",
            "env.emulator.runtime.qemu_property_namespace",
            "QEMU property namespace is visible inside Android",
            Severity::MEDIUM,
        },
        {
            "deviceinfo.player.setting",
            "1",
            "env.emulator.runtime.player_settings",
            "Guest properties expose player-managed device settings",
            Severity::MEDIUM,
        },
    };

    for (const auto& p : kRuntimeProps) {
        const std::string value = read_prop(p.prop);
        if (value.empty() || !contains_ci(value, p.needle)) continue;
        EvidenceBuilder ev;
        ev.add("prop", p.prop);
        ev.add("value", sanitize_sample(value));
        add_event(out, p.id, p.severity, p.message, ev);
    }

    static const char* kGuestServices[] = {
        "init.svc.nemuinit",
        "init.svc.nemuinput",
        "init.svc.nemu_sys_opt",
        "init.svc.microvirtd",
        "init.svc.vbox86-setup",
    };
    EvidenceBuilder service_ev;
    size_t service_count = 0;
    for (const char* prop : kGuestServices) {
        const std::string value = read_prop(prop);
        if (value.empty()) continue;
        const std::string lowered = lower_copy(value);
        if (lowered == "running" || lowered == "restarting") {
            ++service_count;
            service_ev.add(prop, sanitize_sample(value));
        }
    }
    if (service_count >= 1) {
        service_ev.add("serviceCount", static_cast<uint64_t>(service_count));
        add_event(
            out,
            "env.emulator.runtime.guest_control_services",
            service_count >= 2 ? Severity::HIGH : Severity::MEDIUM,
            "Emulator guest-control services are running inside Android",
            service_ev
        );
    }

    static const char* kGuestMetadataProps[] = {
        "nemud.player_package",
        "nemud.player_engine",
        "nemud.player_version",
        "nemud.player_architecture",
        "nemud.player_uuid",
    };
    EvidenceBuilder metadata_ev;
    size_t metadata_count = 0;
    for (const char* prop : kGuestMetadataProps) {
        const std::string value = read_prop(prop);
        if (value.empty()) continue;
        ++metadata_count;
        metadata_ev.add(prop, sanitize_sample(value));
    }
    if (metadata_count > 0) {
        metadata_ev.add("metadataPropCount", static_cast<uint64_t>(metadata_count));
        add_event(
            out,
            "env.emulator.runtime.guest_metadata_props",
            Severity::HIGH,
            "Guest-visible metadata exposes emulator host integration",
            metadata_ev
        );
    }
}

void check_cpu_virtualization(EventList& out) {
    const std::string cpuinfo = read_file_prefix("/proc/cpuinfo", 32 * 1024);
    if (cpuinfo.empty()) return;

    const std::string lowered = lower_copy(cpuinfo);
    if (contains(lowered, "linux,dummy-virt")) {
        EvidenceBuilder ev;
        ev.add("path", "/proc/cpuinfo");
        ev.add("sample", first_matching_line(cpuinfo, "linux,dummy-virt"));
        add_event(
            out,
            "env.emulator.cpu.dummy_virt_hardware",
            Severity::HIGH,
            "CPU hardware field exposes a virtual machine platform",
            ev
        );
    }

    if (contains(lowered, "hypervisor")) {
        EvidenceBuilder ev;
        ev.add("path", "/proc/cpuinfo");
        ev.add("sample", first_matching_line(cpuinfo, "hypervisor"));
        add_event(
            out,
            "env.emulator.cpu.hypervisor_flag",
            Severity::HIGH,
            "CPU flags expose hypervisor execution",
            ev
        );
    }

    const size_t processor_count = count_occurrences(lowered, "processor");
    const size_t bogomips_48_count = count_occurrences(lowered, "bogomips\t: 48.00") +
        count_occurrences(lowered, "bogomips : 48.00");
    const size_t zero_part_count = count_occurrences(lowered, "cpu part\t: 0x000") +
        count_occurrences(lowered, "cpu part : 0x000");
    const size_t apple_impl_count = count_occurrences(lowered, "cpu implementer\t: 0x61") +
        count_occurrences(lowered, "cpu implementer : 0x61");
    if (processor_count >= 2 &&
        bogomips_48_count >= processor_count &&
        zero_part_count >= processor_count &&
        apple_impl_count >= processor_count) {
        EvidenceBuilder ev;
        ev.add("path", "/proc/cpuinfo");
        ev.add("processorCount", static_cast<uint64_t>(processor_count));
        ev.add("bogomips48Count", static_cast<uint64_t>(bogomips_48_count));
        ev.add("zeroCpuPartCount", static_cast<uint64_t>(zero_part_count));
        ev.add("implementer61Count", static_cast<uint64_t>(apple_impl_count));
        add_event(
            out,
            "env.emulator.cpu.synthetic_arm_profile",
            Severity::MEDIUM,
            "CPU topology looks synthesized by a virtualization layer",
            ev
        );
    }
}

void check_sysfs_virtual_devices(EventList& out) {
    DIR* dir = ::opendir("/sys/bus/virtio/devices");
    if (!dir) return;

    size_t virtio_count = 0;
    std::string sample;
    while (dirent* ent = ::readdir(dir)) {
        if (std::strncmp(ent->d_name, "virtio", 6) != 0) continue;
        ++virtio_count;
        if (sample.empty()) sample = ent->d_name;
    }
    ::closedir(dir);

    if (virtio_count > 0) {
        EvidenceBuilder ev;
        ev.add("path", "/sys/bus/virtio/devices");
        ev.add("deviceCount", static_cast<uint64_t>(virtio_count));
        ev.add("sample", sample);
        add_event(
            out,
            "env.emulator.sysfs.virtio_devices",
            Severity::MEDIUM,
            "Virtio devices are exposed to the Android guest",
            ev
        );
    }
}

void check_virtual_mounts(EventList& out) {
    const std::string mounts = read_file_prefix("/proc/mounts", 96 * 1024);
    if (mounts.empty()) return;

    size_t virtio_9p_count = 0;
    size_t host_shared_count = 0;
    std::string virtio_sample;
    std::string shared_sample;

    size_t line_start = 0;
    const std::string lowered_mounts = lower_copy(mounts);
    while (line_start < mounts.size()) {
        const size_t line_end = mounts.find('\n', line_start);
        const size_t end = line_end == std::string::npos ? mounts.size() : line_end;
        const std::string line = mounts.substr(line_start, end - line_start);
        const std::string lowered_line = lowered_mounts.substr(line_start, end - line_start);
        const bool is_virtio_9p =
            lowered_line.find(" 9p ") != std::string::npos &&
            lowered_line.find("virtio") != std::string::npos;
        const bool is_host_shared =
            lowered_line.find("/mnt/shared") != std::string::npos ||
            lowered_line.find("mumu") != std::string::npos ||
            lowered_line.find("global_shared") != std::string::npos ||
            lowered_line.find("private_shared") != std::string::npos;

        if (is_virtio_9p) {
            ++virtio_9p_count;
            if (virtio_sample.empty()) virtio_sample = sanitize_sample(line);
        }
        if (is_host_shared) {
            ++host_shared_count;
            if (shared_sample.empty()) shared_sample = sanitize_sample(line);
        }
        if (line_end == std::string::npos) break;
        line_start = line_end + 1;
    }

    if (virtio_9p_count > 0) {
        EvidenceBuilder ev;
        ev.add("path", "/proc/mounts");
        ev.add("mountCount", static_cast<uint64_t>(virtio_9p_count));
        ev.add("sample", virtio_sample);
        add_event(
            out,
            "env.emulator.fs.virtio_9p_shared_mount",
            Severity::HIGH,
            "Host shared storage is mounted through virtio 9p",
            ev
        );
    }

    if (host_shared_count > 0) {
        EvidenceBuilder ev;
        ev.add("path", "/proc/mounts");
        ev.add("mountCount", static_cast<uint64_t>(host_shared_count));
        ev.add("sample", shared_sample);
        add_event(
            out,
            "env.emulator.fs.host_shared_storage",
            Severity::MEDIUM,
            "Host-shared storage mount is visible to the guest",
            ev
        );
    }
}

void check_virtual_network(EventList& out) {
    const std::string route = read_file_prefix("/proc/net/route", 16 * 1024);
    if (route.empty()) return;
    const std::string lowered = lower_copy(route);

    if (contains(lowered, "0002000a") || contains(lowered, "0202000a")) {
        EvidenceBuilder ev;
        ev.add("path", "/proc/net/route");
        ev.add("sample", first_matching_line(route, "0002000A"));
        add_event(
            out,
            "env.emulator.net.qemu_nat_subnet",
            Severity::MEDIUM,
            "Network routing table exposes the common QEMU 10.0.2.0 guest subnet",
            ev
        );
    }
}

void check_identity_virtualization_conflict(EventList& out) {
    const std::string hv = lower_copy(read_prop("ro.build.hv.platform"));
    const std::string cpuinfo = read_file_prefix("/proc/cpuinfo", 32 * 1024);
    const std::string cpu_lower = lower_copy(cpuinfo);
    const bool has_virtual_runtime =
        contains(hv, "qemu") ||
        contains(cpu_lower, "linux,dummy-virt") ||
        contains(cpu_lower, "hypervisor");
    if (!has_virtual_runtime) return;

    const std::string manufacturer = read_prop("ro.product.manufacturer");
    const std::string model = read_prop("ro.product.model");
    const std::string fingerprint = read_prop("ro.build.fingerprint");
    const std::string identity = lower_copy(manufacturer + " " + model + " " + fingerprint);
    static const char* kConsumerBrands[] = {
        "huawei",
        "honor",
        "xiaomi",
        "redmi",
        "samsung",
        "oppo",
        "vivo",
        "oneplus",
        "realme",
        "google",
    };

    bool looks_like_consumer_device = false;
    for (const char* brand : kConsumerBrands) {
        if (contains(identity, brand)) {
            looks_like_consumer_device = true;
            break;
        }
    }
    if (!looks_like_consumer_device) return;

    EvidenceBuilder ev;
    ev.add("manufacturer", sanitize_sample(manufacturer));
    ev.add("model", sanitize_sample(model));
    ev.add("fingerprint", sanitize_sample(fingerprint));
    if (!hv.empty()) ev.add("hypervisorProp", hv);
    const std::string cpu_sample = first_matching_line(cpuinfo, "linux,dummy-virt");
    if (!cpu_sample.empty()) ev.add("cpuSample", cpu_sample);
    add_event(
        out,
        "env.emulator.identity.consumer_brand_virtualized",
        Severity::HIGH,
        "Device identity claims a consumer handset while runtime exposes virtualization",
        ev
    );
}

void check_boot_virtualization(EventList& out) {
    const std::string cmdline = read_file_prefix("/proc/cmdline", 16 * 1024);
    if (cmdline.empty()) return;
    const std::string lowered = lower_copy(cmdline);

    const bool has_boot_marker =
        contains(lowered, "androidboot.hardware=ranchu") ||
        contains(lowered, "androidboot.hardware=goldfish") ||
        contains(lowered, "qemu") ||
        contains(lowered, "virtio");
    if (!has_boot_marker) return;

    EvidenceBuilder ev;
    ev.add("path", "/proc/cmdline");
    ev.add("sample", sanitize_sample(cmdline));
    add_event(
        out,
        "env.emulator.kernel.virtual_boot_args",
        Severity::HIGH,
        "Kernel command line exposes virtual Android boot arguments",
        ev
    );
}

}  // namespace

EventList scan_environment() {
    EventList events;
    check_props(events);
    check_files(events);
    check_virtualization_props(events);
    check_boot_virtualization(events);
    check_cpu_virtualization(events);
    check_sysfs_virtual_devices(events);
    check_virtual_mounts(events);
    check_virtual_network(events);
    check_identity_virtualization_conflict(events);
    return events;
}

}  // namespace leona::detection
