# Consumer ProGuard rules — applied to any app that integrates the SDK.
# Keep the public API surface and every native method binding.

# --- Public API ---
-keep class io.leonasec.leona.Leona { *; }
-keep class io.leonasec.leona.BoxId { *; }
-keep interface io.leonasec.leona.BoxIdCallback { *; }
-keep class io.leonasec.leona.Honeypot { *; }
-keep class io.leonasec.leona.Honeypot$FakeUser { *; }
-keep class io.leonasec.leona.config.LeonaConfig { *; }
-keep class io.leonasec.leona.config.LeonaConfig$Builder { *; }

# --- JNI bindings ---
# Native method bodies live in libleona.so — their Java-side declarations
# must keep their exact names or JNI resolution fails at runtime.
-keep class io.leonasec.leona.internal.NativeBridge { *; }
-keep interface io.leonasec.leona.internal.runtime.NativeRuntime { *; }
-keep class io.leonasec.leona.internal.runtime.OssNativeRuntime { *; }
-keep class io.leonasec.leona.privatecore.PrivateNativeRuntime { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}

# --- Kotlin metadata for public API only ---
-keepattributes *Annotation*, InnerClasses, EnclosingMethod, Signature
