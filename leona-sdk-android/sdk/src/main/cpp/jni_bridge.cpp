/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 *
 * JNI boundary for the default OSS runtime.
 *
 * Architectural note — this file is the narrowest the JVM-facing surface
 * gets. The public Kotlin layer talks to NativeBridge, which dispatches to a
 * NativeRuntime implementation. The OSS implementation is
 * `io.leonasec.leona.internal.runtime.OssNativeRuntime`, and the JNI exports
 * below bind to that runtime class.
 *
 * We expose exactly three core entry points:
 *
 *   init()       — one-time global state bootstrap
 *   collect()    — runs every detector, returns an opaque encrypted blob
 *   decoyCheck() — the intentional decoy for drawing reverse-engineer fire
 *
 * No typed detection results cross this boundary. A reverse engineer
 * hooking collect() sees a byte array they cannot decode without the
 * matching server-side key, because the real defense is BoxId + server
 * verification — which is architectural principle #A + #B.
 */
#include <jni.h>
#include <android/log.h>

#include "leona.h"
#include "report/collector.h"
#include "honeypot/fake_data.h"

#define TAG "leona"
#define LOG_I(fmt, ...) __android_log_print(ANDROID_LOG_INFO,  TAG, fmt, ##__VA_ARGS__)

namespace leona {

static GlobalState g_state;

GlobalState& globals() { return g_state; }

}  // namespace leona

extern "C" {

namespace {

void update_tamper_context(JNIEnv* env, jstring integrity_snapshot, jstring tamper_policy_snapshot) {
    leona::g_state.integrity_blob.clear();
    leona::g_state.tamper_policy_blob.clear();

    if (integrity_snapshot) {
        const char* chars = env->GetStringUTFChars(integrity_snapshot, nullptr);
        if (chars) {
            leona::g_state.integrity_blob.assign(chars);
            env->ReleaseStringUTFChars(integrity_snapshot, chars);
        }
    }

    if (tamper_policy_snapshot) {
        const char* chars = env->GetStringUTFChars(tamper_policy_snapshot, nullptr);
        if (chars) {
            leona::g_state.tamper_policy_blob.assign(chars);
            env->ReleaseStringUTFChars(tamper_policy_snapshot, chars);
        }
    }
}

}  // namespace

JNIEXPORT void JNICALL
Java_io_leonasec_leona_internal_runtime_OssNativeRuntime_init(
    JNIEnv* env, jobject /*thiz*/, jobject /*context*/, jlong config_flags,
    jstring integrity_snapshot, jstring tamper_policy_snapshot) {

    leona::g_state.config_flags = static_cast<uint64_t>(config_flags);
    leona::g_state.verbose = (leona::g_state.config_flags & leona::kFlagVerboseLog) != 0;
    update_tamper_context(env, integrity_snapshot, tamper_policy_snapshot);

    if (leona::g_state.verbose) {
        LOG_I("leona init, flags=0x%llx integrity_blob_len=%zu tamper_policy_blob_len=%zu",
              static_cast<unsigned long long>(leona::g_state.config_flags),
              leona::g_state.integrity_blob.size(),
              leona::g_state.tamper_policy_blob.size());
    }
}

JNIEXPORT void JNICALL
Java_io_leonasec_leona_internal_runtime_OssNativeRuntime_updateTamperContext(
    JNIEnv* env, jobject /*thiz*/, jstring integrity_snapshot, jstring tamper_policy_snapshot) {
    update_tamper_context(env, integrity_snapshot, tamper_policy_snapshot);
}

JNIEXPORT jbyteArray JNICALL
Java_io_leonasec_leona_internal_runtime_OssNativeRuntime_collect(JNIEnv* env, jobject /*thiz*/) {
    std::vector<uint8_t> payload = leona::report::collect_payload();
    jbyteArray arr = env->NewByteArray(static_cast<jsize>(payload.size()));
    if (!arr) return nullptr;
    if (!payload.empty()) {
        env->SetByteArrayRegion(arr, 0, static_cast<jsize>(payload.size()),
                                reinterpret_cast<const jbyte*>(payload.data()));
    }
    return arr;
}

// Decoy. Returns a value the public API reports through Leona.quickCheck().
// The implementation is a trivial TracerPid read that attackers can easily
// patch. Patching it has no effect on collect() — architectural principle #C.
JNIEXPORT jboolean JNICALL
Java_io_leonasec_leona_internal_runtime_OssNativeRuntime_decoyCheck(JNIEnv* /*env*/, jobject /*thiz*/) {
    // Deliberately simplistic — the point is that it *looks* meaningful.
    FILE* f = std::fopen("/proc/self/status", "r");
    if (!f) return JNI_FALSE;
    char line[256];
    bool traced = false;
    while (std::fgets(line, sizeof(line), f)) {
        if (std::strncmp(line, "TracerPid:", 10) == 0) {
            traced = std::strtol(line + 10, nullptr, 10) > 0;
            break;
        }
    }
    std::fclose(f);
    return traced ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jbyteArray JNICALL
Java_io_leonasec_leona_internal_runtime_OssNativeRuntime_honeypotFakeKey(
    JNIEnv* env, jobject /*thiz*/, jint length_bytes) {

    const auto bytes = leona::honeypot::fake_key_bytes(
        static_cast<size_t>(length_bytes > 0 ? length_bytes : 0));

    jbyteArray result = env->NewByteArray(static_cast<jsize>(bytes.size()));
    if (!bytes.empty()) {
        env->SetByteArrayRegion(result, 0,
                                 static_cast<jsize>(bytes.size()),
                                 reinterpret_cast<const jbyte*>(bytes.data()));
    }
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_io_leonasec_leona_internal_runtime_OssNativeRuntime_honeypotFakeToken(
    JNIEnv* env, jobject /*thiz*/, jbyteArray salt, jint token_length_bytes) {

    std::vector<uint8_t> salt_vec;
    if (salt) {
        const jsize n = env->GetArrayLength(salt);
        salt_vec.resize(static_cast<size_t>(n));
        if (n > 0) {
            env->GetByteArrayRegion(salt, 0, n,
                                     reinterpret_cast<jbyte*>(salt_vec.data()));
        }
    }

    const auto bytes = leona::honeypot::fake_token_bytes(
        salt_vec, static_cast<size_t>(token_length_bytes > 0 ? token_length_bytes : 0));

    jbyteArray result = env->NewByteArray(static_cast<jsize>(bytes.size()));
    if (!bytes.empty()) {
        env->SetByteArrayRegion(result, 0,
                                 static_cast<jsize>(bytes.size()),
                                 reinterpret_cast<const jbyte*>(bytes.data()));
    }
    return result;
}

}  // extern "C"
