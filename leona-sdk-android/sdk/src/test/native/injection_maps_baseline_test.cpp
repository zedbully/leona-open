#include "../../main/cpp/detection/injection_detector.h"

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace leona {

GlobalState& globals() {
    static GlobalState state;
    return state;
}

}  // namespace leona

namespace {

void fail(const std::string& message) {
    std::cerr << "FAIL: " << message << "\n";
    std::exit(1);
}

void expect_true(bool value, const std::string& message) {
    if (!value) fail(message);
}

leona::detection::MapRegion parse_line(const char* line) {
    leona::detection::MapRegion region;
    if (!leona::detection::parse_maps_line(line, &region)) {
        fail(std::string("could not parse maps line: ") + line);
    }
    return region;
}

int count_events(const leona::EventList& events, const std::string& id) {
    int count = 0;
    for (const auto& event : events) {
        if (event.id == id) ++count;
    }
    return count;
}

const leona::Event* first_event(const leona::EventList& events, const std::string& id) {
    for (const auto& event : events) {
        if (event.id == id) return &event;
    }
    return nullptr;
}

}  // namespace

int main() {
    auto memfd = parse_line(
        "70000000-70001000 r-xp 00000000 00:00 0 /memfd:payload (deleted)\n");
    expect_true(memfd.executable(), "memfd fixture should be executable");
    expect_true(memfd.path == "/memfd:payload (deleted)", "memfd path should keep deleted suffix");

    std::vector<leona::detection::MapRegion> maps = {
        memfd,
        parse_line("71000000-71001000 r-xp 00000000 00:00 0 /memfd:jit-cache (deleted)\n"),
        parse_line("72000000-72001000 r-xp 00000000 00:00 0 /data/local/tmp/libshadow.so (deleted)\n"),
        parse_line("73000000-73001000 rwxp 00000000 00:00 0 \n"),
        parse_line("74000000-74001000 r-xp 00000000 00:00 0 [anon:dalvik-jit-code-cache]\n"),
        parse_line("75000000-75001000 r-xp 00000000 00:00 0 /data/user/0/com.example/files/libpayload.so\n"),
        parse_line("76000000-76001000 r-xp 00000000 00:00 0 /system/lib64/libc.so\n"),
        parse_line("77000000-77001000 r-xp 00000000 00:00 0 /data/app/~~abc/com.example/base.apk!/lib/arm64-v8a/libleona.so\n"),
        parse_line("78000000-78001000 r-xp 00000000 00:00 0 /data/app/~~abc/com.example/lib/arm64/libleona.so (deleted)\n"),
    };
    const std::string integrity_blob =
        "nativeLibraryDir=/data/app/~~abc/com.example/lib/arm64\n"
        "sourceDir=/data/app/~~abc/com.example/base.apk\n"
        "splitSourceDirs=/data/app/~~abc/com.example/split_config.arm64_v8a.apk\n";

    auto events = leona::detection::scan_injection_mapping_baseline(maps, integrity_blob);

    expect_true(
        count_events(events, "runtime.mapping.memfd_executable") == 1,
        "non-ART executable memfd should emit exactly one event");
    expect_true(
        count_events(events, "runtime.mapping.deleted_executable") == 1,
        "non-Leona deleted executable mapping should emit exactly one event");
    expect_true(
        count_events(events, "runtime.mapping.anonymous_executable_summary") == 1,
        "anonymous executable mapping should emit one summary event");
    expect_true(
        count_events(events, "runtime.mapping.non_system_executable_path") == 2,
        "writable non-system executable paths should emit per-path facts");

    const auto* anon = first_event(events, "runtime.mapping.anonymous_executable_summary");
    expect_true(anon != nullptr, "anonymous summary event missing");
    expect_true(
        anon->evidence.find("region_count=1") != std::string::npos,
        "ART/dalvik JIT executable mapping should be excluded from anonymous summary");

    for (const auto& event : events) {
        expect_true(
            event.evidence.find("jit-cache") == std::string::npos,
            "ART/JIT memfd should not appear in baseline evidence");
        expect_true(
            event.evidence.find("libleona.so (deleted)") == std::string::npos,
            "Leona deleted runtime mapping is handled by the dedicated detector");
    }

    std::cout << "PASS injection maps baseline events: " << events.size() << "\n";
    return 0;
}
