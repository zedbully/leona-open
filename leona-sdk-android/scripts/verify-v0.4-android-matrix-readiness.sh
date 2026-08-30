#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${LEONA_V04_ANDROID_MATRIX_OUT:-$(mktemp -d /tmp/leona-v0.4-android-matrix-readiness.XXXXXX)}"
REQUIRE_FULL_MATRIX="${LEONA_REQUIRE_FULL_V04_ANDROID_MATRIX:-0}"

ROM_MATRIX="${ROOT_DIR}/docs/rom-matrix.md"
EMULATOR_MATRIX="${ROOT_DIR}/docs/emulator-matrix.md"
WETEST_RUNBOOK="${ROOT_DIR}/docs/wetest-matrix-runbook.md"

mkdir -p "${OUT_DIR}"

python3 - "${OUT_DIR}" "${REQUIRE_FULL_MATRIX}" "${ROM_MATRIX}" "${EMULATOR_MATRIX}" "${WETEST_RUNBOOK}" <<'PY'
import json
import re
import sys
from pathlib import Path

out_dir = Path(sys.argv[1])
require_full = sys.argv[2] == "1"
rom_path = Path(sys.argv[3])
emulator_path = Path(sys.argv[4])
wetest_path = Path(sys.argv[5])

paths = [rom_path, emulator_path, wetest_path]
missing = [str(path) for path in paths if not path.exists()]
if missing:
    raise SystemExit(f"missing matrix docs: {', '.join(missing)}")

raw_box_id = re.compile(r"\b01[0-9A-HJKMNP-TV-Z]{24}\b")
credential_value = re.compile(
    r"(?i)\b(secretkey|appsecret|providercredential|wdb[_ -]?token)\b\s*[:=]\s*['\"]?[^`'\"\s|]{8,}"
)

def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")

def table_rows(text: str):
    rows = []
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        if re.search(r"\|\s*---", line):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if cells and cells[0].lower() not in {"sample", "date", "brand / vendor"}:
            rows.append(cells)
    return rows

def has_redacted_boxid(value: str) -> bool:
    lower = value.lower()
    return "boxid hint" in lower or "boxid hash" in lower or "01" in value and "..." in value

def has_artifact(value: str) -> bool:
    return "/tmp/leona-" in value or "artifacts" in value.lower()

docs = {str(path): read(path) for path in paths}
raw_hits = []
sensitive_hits = []
for name, text in docs.items():
    for match in raw_box_id.finditer(text):
        raw_hits.append({"file": name, "value": match.group(0)[:6] + "..." + match.group(0)[-4:]})
    for match in credential_value.finditer(text):
        sensitive_hits.append({"file": name, "value": match.group(0)})

rom_rows = table_rows(docs[str(rom_path)])
rom_completed = []
rom_template_names = {
    "Clean OEM physical",
    "OEM unlocked BL",
    "LineageOS",
    "crDroid",
    "PixelExperience",
    "GrapheneOS",
    "Generic GSI",
    "Self-built AOSP",
    "Magisk hide custom ROM",
}
for cells in rom_rows:
    if len(cells) < 12:
        continue
    sample = cells[0]
    joined = " | ".join(cells)
    if sample in rom_template_names and not has_artifact(joined):
        continue
    device_class = cells[1].lower()
    if (
        has_artifact(joined)
        and has_redacted_boxid(joined)
        and any(token in device_class or token in sample.lower() for token in ["custom", "gsi", "unlocked", "lineage", "crdroid", "graphene", "aosp"])
    ):
        rom_completed.append(sample)

emulator_rows = table_rows(docs[str(emulator_path)])
external_targets = {"ldplayer", "nox", "bluestacks", "genymotion"}
baseline_emulators = []
external_completed = []
for cells in emulator_rows:
    if len(cells) < 10:
        continue
    sample = cells[0].strip()
    joined = " | ".join(cells)
    sample_lower = sample.lower()
    if sample_lower in {"mumu", "android studio emulator"} and has_redacted_boxid(joined) and has_artifact(joined):
        baseline_emulators.append(sample)
    if sample_lower in external_targets and has_redacted_boxid(joined) and has_artifact(joined):
        external_completed.append(sample)

wetest_rows = table_rows(docs[str(wetest_path)])
clean_cloud_android_10_11 = []
blocked_rows = []
for cells in wetest_rows:
    if len(cells) < 7:
        continue
    date, brand, model, android, result, output = cells[:6]
    row_text = " | ".join(cells)
    result_lower = result.lower()
    if result_lower == "pass" and re.fullmatch(r"(10|11)", android.strip()):
        if has_redacted_boxid(output) and has_artifact(output):
            clean_cloud_android_10_11.append(f"{brand} {model} Android {android}")
    elif result_lower == "blocked":
        blocked_rows.append(f"{brand} {model} Android {android}")

checks = [
    {
        "id": "redaction",
        "status": "pass" if not raw_hits and not sensitive_hits else "fail",
        "detail": "no full BoxId or sensitive credential-like strings in matrix docs",
        "rawHits": raw_hits,
        "sensitiveHits": sensitive_hits,
    },
    {
        "id": "baseline_emulators",
        "status": "pass" if len(baseline_emulators) >= 2 else "blocked",
        "current": len(baseline_emulators),
        "required": 2,
        "samples": baseline_emulators,
    },
    {
        "id": "external_emulators",
        "status": "pass" if len(external_completed) >= 2 else "blocked",
        "current": len(external_completed),
        "required": 2,
        "samples": external_completed,
        "blockedOn": ["LDPlayer", "Nox", "BlueStacks", "Genymotion"],
    },
    {
        "id": "custom_rom_gsi_unlocked",
        "status": "pass" if len(rom_completed) >= 2 else "blocked",
        "current": len(rom_completed),
        "required": 2,
        "samples": rom_completed,
        "blockedOn": ["custom ROM", "GSI", "unlocked bootloader device"],
    },
    {
        "id": "cloud_phone_android_10_11",
        "status": "pass" if len(clean_cloud_android_10_11) >= 1 else "blocked",
        "current": len(clean_cloud_android_10_11),
        "required": 1,
        "samples": clean_cloud_android_10_11[:8],
    },
    {
        "id": "hide_module_extra_combo",
        "status": "blocked",
        "current": 0,
        "required": 1,
        "blockedOn": ["additional hide module/version sample beyond current Magisk Canary/Zygisk/LSPosed/HMA/Shamiko baseline"],
    },
]

hard_failures = [check for check in checks if check["status"] == "fail"]
blocked = [check for check in checks if check["status"] == "blocked"]
status = "pass"
if hard_failures:
    status = "fail"
elif blocked:
    status = "blocked" if require_full else "local-pass-with-external-blockers"

summary = {
    "status": status,
    "requireFullMatrix": require_full,
    "docs": [str(path) for path in paths],
    "checks": checks,
    "blockedRows": blocked_rows[:12],
}
(out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

lines = [
    "# Leona v0.4 Android Matrix Readiness",
    "",
    f"- status: {status}",
    f"- requireFullMatrix: {str(require_full).lower()}",
    f"- reportDir: {out_dir}",
    "",
    "## Checks",
    "",
]
for check in checks:
    lines.append(f"- {check['id']}: {check['status']}")
    if "current" in check:
        lines.append(f"  - current: {check['current']} / {check['required']}")
    if check.get("samples"):
        lines.append("  - samples: " + "; ".join(check["samples"]))
    if check.get("blockedOn"):
        lines.append("  - blockedOn: " + "; ".join(check["blockedOn"]))

if blocked_rows:
    lines.extend(["", "## Blocked Existing Ledger Rows", ""])
    for row in blocked_rows[:12]:
        lines.append(f"- {row}")

(out_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

print(f"[v0.4-android-matrix] {status}: {out_dir / 'summary.md'}")
if hard_failures or (require_full and blocked):
    raise SystemExit(1)
PY
