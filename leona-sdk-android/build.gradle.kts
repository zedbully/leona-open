// Top-level Gradle file. Sub-modules declare their own plugins; this file
// pins plugin versions via the catalog and keeps known-vulnerable transitive
// build-tool dependencies off the AGP classpath. These dependencies are not
// packaged in the SDK/AAR, but they still process untrusted project inputs at
// build time and therefore need an explicit security floor.
buildscript {
    configurations.classpath {
        resolutionStrategy {
            force("org.apache.commons:commons-lang3:3.18.0")
            force("org.bitbucket.b_c:jose4j:0.9.6")
            force("org.bouncycastle:bcpkix-jdk18on:1.84")
            force("org.bouncycastle:bcprov-jdk18on:1.84")
            force("org.bouncycastle:bcutil-jdk18on:1.84")
            force("org.jdom:jdom2:2.0.6.1")
        }
    }
}

plugins {
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.android.application) apply false
}
