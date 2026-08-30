# Keep the external facade's JNI binary names. The owning AAR may ship
# additional rules; this adapter does not replace them.
-keep class com.leo.crypto.facade.NativeBindings { *; }
-keep class com.leo.crypto.facade.NativeResult { *; }
-keep class com.leo.crypto.facade.NativeResponseResult { *; }
-keep class com.leo.crypto.facade.NativeOperationsReadiness { *; }
-keep class com.leo.crypto.facade.OperationsAuditEvent { *; }
