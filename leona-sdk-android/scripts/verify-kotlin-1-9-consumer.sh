#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${LEONA_SDK_VERSION:-$(grep '^VERSION_NAME=' "${ROOT_DIR}/gradle.properties" | cut -d= -f2-)}"
GROUP_ID="${LEONA_SDK_GROUP:-$(grep '^GROUP=' "${ROOT_DIR}/gradle.properties" | cut -d= -f2-)}"
ARTIFACT_ID="${LEONA_SDK_ARTIFACT:-leona-sdk-android}"
OUT_DIR="${LEONA_KOTLIN19_CONSUMER_OUT:-/tmp/leona-kotlin19-consumer-$(date +%Y%m%d-%H%M%S)}"
M2_DIR="${OUT_DIR}/m2"
CONSUMER_DIR="${OUT_DIR}/consumer"
TOOL_CACHE="${LEONA_COMPAT_TOOL_CACHE:-${HOME}/.gradle/leona-compat}"
GRADLE_VERSION="8.11.1"
GRADLE_SHA256="f397b287023acdba1e9f6fc5ea72d22dd63669d59ed4a289a29b1a76eee151c6"
GRADLE_ZIP="${TOOL_CACHE}/gradle-${GRADLE_VERSION}-bin.zip"
GRADLE_DIR="${TOOL_CACHE}/gradle-${GRADLE_VERSION}"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

resolve_gradle_bin() {
  if [[ -n "${LEONA_GRADLE_8_11_1_BIN:-}" ]]; then
    [[ -x "${LEONA_GRADLE_8_11_1_BIN}" ]] || {
      echo "LEONA_GRADLE_8_11_1_BIN is not executable" >&2
      return 1
    }
    printf '%s\n' "${LEONA_GRADLE_8_11_1_BIN}"
    return 0
  fi

  mkdir -p "${TOOL_CACHE}"
  if [[ -f "${GRADLE_ZIP}" ]]; then
    [[ "$(sha256_file "${GRADLE_ZIP}")" == "${GRADLE_SHA256}" ]] || {
      echo "Cached Gradle ${GRADLE_VERSION} archive failed SHA-256 verification" >&2
      return 1
    }
  else
    local partial="${GRADLE_ZIP}.partial.$$"
    curl --fail --location --retry 8 --retry-all-errors --retry-delay 2 \
      "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" \
      --output "${partial}"
    [[ "$(sha256_file "${partial}")" == "${GRADLE_SHA256}" ]] || {
      echo "Downloaded Gradle ${GRADLE_VERSION} archive failed SHA-256 verification" >&2
      return 1
    }
    mv "${partial}" "${GRADLE_ZIP}"
  fi

  if [[ ! -x "${GRADLE_DIR}/bin/gradle" ]]; then
    unzip -q -o "${GRADLE_ZIP}" -d "${TOOL_CACHE}"
  fi
  [[ -x "${GRADLE_DIR}/bin/gradle" ]] || {
    echo "Gradle ${GRADLE_VERSION} executable is unavailable after extraction" >&2
    return 1
  }
  printf '%s\n' "${GRADLE_DIR}/bin/gradle"
}

mkdir -p "${M2_DIR}" "${CONSUMER_DIR}/app/src/main/java/example/consumer"
GRADLE_8_BIN="$(resolve_gradle_bin)"
M2_URI="$(python3 - "${M2_DIR}" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).resolve().as_uri())
PY
)"

cat > "${CONSUMER_DIR}/settings.gradle.kts" <<EOF
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        maven { url = uri("${M2_URI}") }
        google()
        mavenCentral()
    }
}

rootProject.name = "leona-kotlin19-consumer"
include(":app")
EOF

cat > "${CONSUMER_DIR}/build.gradle.kts" <<'EOF'
plugins {
    id("com.android.application") version "8.9.1" apply false
    id("org.jetbrains.kotlin.android") version "1.9.24" apply false
}
EOF

cat > "${CONSUMER_DIR}/gradle.properties" <<'EOF'
android.useAndroidX=true
EOF

cat > "${CONSUMER_DIR}/app/build.gradle.kts" <<EOF
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "example.consumer"
    compileSdk = 36

    defaultConfig {
        applicationId = "example.consumer"
        minSdk = 21
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation("${GROUP_ID}:${ARTIFACT_ID}:${VERSION}")
}
EOF

cat > "${CONSUMER_DIR}/app/src/main/AndroidManifest.xml" <<'EOF'
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:theme="@android:style/Theme.Material.Light.NoActionBar" />
</manifest>
EOF

cat > "${CONSUMER_DIR}/app/src/main/java/example/consumer/LeonaConsumer.kt" <<'EOF'
package example.consumer

import io.leonasec.leona.config.LeonaConfig

object LeonaConsumer {
    fun create(): LeonaConfig = LeonaConfig.Builder()
        .appId("compatibility-check")
        .transportEnabled(false)
        .build()
}
EOF

if [[ -f "${ROOT_DIR}/local.properties" ]]; then
  cp "${ROOT_DIR}/local.properties" "${CONSUMER_DIR}/local.properties"
fi

echo "[kotlin19-consumer] publishing ${GROUP_ID}:${ARTIFACT_ID}:${VERSION}"
(
  cd "${ROOT_DIR}"
  ./gradlew --no-daemon --no-configuration-cache --console=plain \
    -Dmaven.repo.local="${M2_DIR}" \
    :sdk:publishReleasePublicationToMavenLocal
)

POM="${M2_DIR}/${GROUP_ID//.//}/${ARTIFACT_ID}/${VERSION}/${ARTIFACT_ID}-${VERSION}.pom"
[[ -f "${POM}" ]] || {
  echo "Published POM is missing" >&2
  exit 1
}
grep -A2 '<artifactId>kotlin-stdlib</artifactId>' "${POM}" | grep -q '<version>1.9.24</version>' || {
  echo "Published SDK must retain Kotlin stdlib 1.9.24 compatibility" >&2
  exit 1
}

echo "[kotlin19-consumer] compiling with AGP 8.9.1 / Gradle 8.11.1 / Kotlin 1.9.24"
"${GRADLE_8_BIN}" -p "${CONSUMER_DIR}" \
  --no-daemon --no-configuration-cache --console=plain \
  :app:assembleDebug

APK="${CONSUMER_DIR}/app/build/outputs/apk/debug/app-debug.apk"
[[ -f "${APK}" ]] || {
  echo "Kotlin 1.9 consumer APK was not produced" >&2
  exit 1
}
APK_SHA256="$(sha256_file "${APK}")"

cat > "${OUT_DIR}/summary.md" <<EOF
# Leona Kotlin 1.9 Consumer Compatibility

- status: pass
- coordinate: \`${GROUP_ID}:${ARTIFACT_ID}:${VERSION}\`
- producer: AGP 9.3.1 / Gradle 9.6.0 / built-in Kotlin language 2.0
- consumer: AGP 8.9.1 / Gradle 8.11.1 / Kotlin 1.9.24
- consumer APK SHA-256: \`${APK_SHA256}\`

This gate compiles an independent Android application against the published
public AAR. It prevents the producer toolchain from silently raising Kotlin
metadata or stdlib requirements beyond the supported Kotlin 1.9 consumer.
EOF

echo "[kotlin19-consumer] summary: ${OUT_DIR}/summary.md"
