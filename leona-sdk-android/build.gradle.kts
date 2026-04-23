// Top-level Gradle file. Sub-modules declare their own plugins; this file
// only pins versions via the plugin catalog.
plugins {
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
}
