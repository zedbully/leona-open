# Sample-app specific R8 rules. The SDK ships its own consumer-rules.pro so
# this file is intentionally minimal.

# The domestic Huawei provider is loaded by name so public builds do not need
# a compile-time HMS dependency.  A private Huawei release must preserve that
# exact class name and public constructor through R8.
-keep class io.leonasec.leona.privatecore.attestation.HuaweiSysIntegrityAttestationProvider {
    public <init>(android.content.Context, java.lang.String);
}
