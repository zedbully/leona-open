#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_DIR="${ROOT_DIR}/wrappers/nodejs"
JAVA_DIR="${ROOT_DIR}/wrappers/java"
OUT_DIR="${LEONA_WRAPPER_VERIFY_OUT:-/tmp/leona-backend-wrapper-verify-$(date +%Y%m%d-%H%M%S)}"

mkdir -p "${OUT_DIR}"

echo "[wrapper-verify] output: ${OUT_DIR}"

node --test "${NODE_DIR}/test/"*.test.mjs | tee "${OUT_DIR}/node-test.txt"
(
  cd "${NODE_DIR}"
  npm pack --dry-run > "${OUT_DIR}/node-pack-dry-run.txt"
)

javac -d "${OUT_DIR}/java-classes" \
  "${JAVA_DIR}/src/main/java/io/leonasec/wrapper/LeonaServerClient.java" \
  "${JAVA_DIR}/src/main/java/io/leonasec/wrapper/LeonaCryptoServerTransport.java" \
  "${JAVA_DIR}/src/test/java/io/leonasec/wrapper/LeonaServerClientSelfTest.java" \
  "${JAVA_DIR}/src/test/java/io/leonasec/wrapper/LeonaServerClientHttpSmoke.java" \
  "${JAVA_DIR}/src/test/java/io/leonasec/wrapper/LeonaCryptoServerTransportSelfTest.java"
java -cp "${OUT_DIR}/java-classes" io.leonasec.wrapper.LeonaServerClientSelfTest \
  | tee "${OUT_DIR}/java-self-test.txt"
java -cp "${OUT_DIR}/java-classes" io.leonasec.wrapper.LeonaServerClientHttpSmoke \
  | tee "${OUT_DIR}/java-http-smoke.txt"
java -cp "${OUT_DIR}/java-classes" io.leonasec.wrapper.LeonaCryptoServerTransportSelfTest \
  | tee "${OUT_DIR}/java-crypto-transport-test.txt"
(
  cd "${JAVA_DIR}"
  ../../gradlew --no-daemon --quiet \
    -p "${JAVA_DIR}" \
    clean jar sourcesJar javadocJar generatePomFileForMavenJavaPublication \
    > "${OUT_DIR}/java-gradle-package.txt"
)

if grep -R -nE '(sk_live_|AKIA|-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY|test_secret_do_not_use[[:alnum:]_+-])' \
  "${ROOT_DIR}/wrappers" > "${OUT_DIR}/secret-scan.txt"; then
  echo "[wrapper-verify] potential secret pattern found" >&2
  cat "${OUT_DIR}/secret-scan.txt" >&2
  exit 1
fi

{
  echo "# Leona Backend Wrapper Skeleton Verification"
  echo
  echo "- node tests: pass"
  echo "- node Leo transport integration smoke: pass"
  echo "- node package dry-run: pass"
  echo "- java self-test: pass"
  echo "- java Leo transport integration smoke: pass"
  echo "- java crypto envelope/server transport self-test: pass"
  echo "- java Gradle package skeleton: pass"
  echo "- secret scan: pass"
  echo "- output: \`${OUT_DIR}\`"
} > "${OUT_DIR}/summary.md"

echo "[wrapper-verify] summary: ${OUT_DIR}/summary.md"
