#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CPP_DIR="$ROOT/sdk/src/main/cpp"
TEST_DIR="$ROOT/sdk/src/test/native"
OUT_DIR="${TMPDIR:-/tmp}/leona-native-host-tests"
CXX_BIN="${CXX:-clang++}"

mkdir -p "$OUT_DIR"

"$CXX_BIN" \
  -std=c++17 \
  -Wall \
  -Wextra \
  -Werror \
  -I"$CPP_DIR" \
  "$TEST_DIR/injection_maps_baseline_test.cpp" \
  "$CPP_DIR/detection/process_maps.cpp" \
  "$CPP_DIR/detection/injection_detector.cpp" \
  "$CPP_DIR/detection/frida_signatures.cpp" \
  "$CPP_DIR/util/evidence_builder.cpp" \
  -o "$OUT_DIR/injection_maps_baseline_test"

"$OUT_DIR/injection_maps_baseline_test"
