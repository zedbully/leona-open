#!/usr/bin/env python3
"""Normalize Android matrix collection artifacts into a redacted import pack.

The importer accepts a bootstrap/cloud/WeTest-style artifact directory and
exports a small hash-only summary that can be attached to the Android matrix
without leaking full BoxIds, raw device identifiers, or credentials.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RAW_BOX_ID = re.compile(
    r"\b(?:[0-9A-HJKMNP-TV-Z]{26}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b"
)
SECRETISH = re.compile(
    r"(?i)(ghp_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"LEONA_[A-Z0-9_]*(SECRET|TOKEN|KEY)[A-Z0-9_]*=[^\s]+|"
    r"(secret|token|credential)[=:]\s*[A-Za-z0-9._~+/=-]{16,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)
RAW_ADB_SERIAL_LINE = re.compile(
    r"(?i)\b(?:adb serial|serial)\b\s*[:=]\s*(?!sha256|hash|absent|not_generated|not collected)([`'\"]?)([A-Za-z0-9_.:-]{5,})\1"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", required=True, help="Matrix artifact directory to import")
    parser.add_argument(
        "--output-dir",
        default="/tmp/leona-android-matrix-external-import-active",
        help="Output directory for normalized import pack",
    )
    parser.add_argument("--source-label", default="external-or-local-matrix", help="Non-sensitive source label")
    parser.add_argument(
        "--require-sample",
        action="store_true",
        help="Fail when no importable sample is found",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)
    if not input_dir.exists():
        raise SystemExit(f"input directory does not exist: {input_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    samples = collect_samples(input_dir)
    status = "pass" if samples else "empty"
    if args.require_sample and not samples:
        status = "failed"

    report = {
        "status": status,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "sourceLabel": args.source_label,
        "inputDir": str(input_dir),
        "sampleCount": len(samples),
        "samples": samples,
        "secretValuesPrinted": False,
        "rawIdentifiersPrinted": False,
    }
    write_report(output_dir, report)
    reject_sensitive_output(output_dir)
    print(f"[android-matrix-external-import] {status}: {output_dir / 'summary.md'}")
    return 0 if status != "failed" else 1


def collect_samples(input_dir: Path) -> list[dict[str, Any]]:
    matrix_rows = sorted(input_dir.rglob("matrix-row.md"), key=lambda path: (0 if path.parent.name == "cloud-collection" else 1, str(path)))
    samples: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for row_path in matrix_rows:
        metadata = parse_markdown_fields(row_path)
        collection_dir = row_path.parent
        posture_env = read_env_file(first_existing([
            collection_dir / "posture.env",
            collection_dir.parent / "posture/device-posture.env",
        ]))
        device_env = read_env_file(collection_dir / "device-summary.env")
        sample = normalize_sample(row_path, metadata, posture_env, device_env)
        if sample:
            key = (
                sample.get("serialHashHint", ""),
                sample.get("model", ""),
                sample.get("androidApi", ""),
                sample.get("result", ""),
            )
            if key in seen:
                continue
            seen.add(key)
            samples.append(sample)
    return samples


def normalize_sample(
    row_path: Path,
    metadata: dict[str, str],
    posture_env: dict[str, str],
    device_env: dict[str, str],
) -> dict[str, Any] | None:
    brand = metadata.get("Brand") or device_env.get("brand") or ""
    model = metadata.get("Model") or device_env.get("model") or ""
    android_api = metadata.get("Android version / API") or join_version_api(
        device_env.get("android_release"),
        device_env.get("android_sdk"),
    )
    serial_hash = (
        metadata.get("Serial hash")
        or device_env.get("serial_sha256")
        or posture_env.get("adb_serial_hash")
        or ""
    )
    if not any([brand, model, android_api, serial_hash]):
        return None

    derived = posture_env.get("derived_evidence", "")
    raw_environment_type = (metadata.get("Environment type") or "").strip().lower()
    environment_type = raw_environment_type if raw_environment_type and raw_environment_type != "unknown" else classify_environment(brand, model, derived, row_path)
    result = metadata.get("Pass / blocked / failed") or "unknown"
    box = metadata.get("BoxId") or metadata.get("Canonical hash or hint") or ""
    reason = metadata.get("Reason") or ""
    trigger_match = re.search(r"generated through ([a-z-]+) trigger", reason, re.IGNORECASE)
    trigger_type = trigger_match.group(1).lower() if trigger_match else "unknown"
    sense_triggered = result == "pass" and trigger_type in {"direct", "ui"}
    report_verified = result == "pass" and bool(box) and box != "not_generated"
    artifact = str(row_path.parent)
    collected_at = datetime.fromtimestamp(row_path.stat().st_mtime, timezone.utc).isoformat()
    return {
        "sampleHash": short_hash(serial_hash or artifact),
        "environmentType": environment_type,
        "brand": brand,
        "model": model,
        "androidApi": android_api,
        "serialHashHint": serial_hash[:16] if serial_hash else "",
        "androidIdHashHint": (device_env.get("android_id_sha256") or posture_env.get("android_id_hash") or "")[:16],
        "fingerprintHashHint": (device_env.get("fingerprint_sha256") or posture_env.get("fingerprint_hash") or "")[:16],
        "boxIdHintOrHash": sanitize_hint(box),
        "result": result,
        "triggerType": trigger_type,
        "senseTriggered": sense_triggered,
        "reportVerified": report_verified,
        "collectedAt": collected_at,
        "derivedEvidence": split_csv(derived),
        "artifactPath": artifact,
    }


def parse_markdown_fields(path: Path) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.startswith("- ") or ":" not in line:
            continue
        key, value = line[2:].split(":", 1)
        fields[key.strip()] = value.strip().strip("`")
    return fields


def read_env_file(path: Path | None) -> dict[str, str]:
    if not path or not path.exists():
        return {}
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("'\"")
    return values


def first_existing(paths: list[Path]) -> Path | None:
    for path in paths:
        if path.exists():
            return path
    return None


def join_version_api(version: str | None, api: str | None) -> str:
    if version and api:
        return f"{version} / {api}"
    return version or api or ""


def classify_environment(brand: str, model: str, derived: str, row_path: Path) -> str:
    text = " ".join([brand, model, derived, str(row_path)]).lower()
    if any(
        marker in text
        for marker in (
            "mumu",
            "nox",
            "ldplayer",
            "bluestacks",
            "genymotion",
            "ranchu",
            "goldfish",
            "emulator",
            "android sdk built for",
            "qemu",
            "sdk_gphone",
        )
    ):
        return "emulator"
    if any(marker in text for marker in ("gsi", "lineage", "crdroid", "graphene", "aosp", "unlocked", "vbmeta", "orange")):
        return "custom-rom-or-unlocked"
    if "cloud" in text or "wetest" in text:
        return "cloud-phone"
    return "physical-or-unknown"


def sanitize_hint(value: str) -> str:
    value = value.strip()
    if not value or value == "not_generated":
        return value
    value = RAW_BOX_ID.sub(lambda match: match.group(0)[:4] + "..." + match.group(0)[-4:], value)
    return value[:96]


def split_csv(value: str) -> list[str]:
    return [item.strip() for item in re.split(r"[,;]", value) if item.strip()]


def short_hash(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def write_report(output_dir: Path, report: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    rows_path = output_dir / "samples.jsonl"
    rows_path.write_text("".join(json.dumps(sample, ensure_ascii=False, sort_keys=True) + "\n" for sample in report["samples"]), encoding="utf-8")
    lines = [
        "# Android Matrix External Sample Import",
        "",
        f"- status: {report['status']}",
        f"- source label: {report['sourceLabel']}",
        f"- sample count: {report['sampleCount']}",
        "- secret values printed: false",
        "- raw identifiers printed: false",
        f"- samples jsonl: `{rows_path}`",
        "",
        "## Samples",
        "",
    ]
    if not report["samples"]:
        lines.append("- none")
    for sample in report["samples"]:
        lines.append(
            "- "
            f"sampleHash={sample['sampleHash']} "
            f"type={sample['environmentType']} "
            f"device={sample['brand']} {sample['model']} "
            f"android={sample['androidApi']} "
            f"result={sample['result']}"
        )
    lines.append("")
    (output_dir / "summary.md").write_text("\n".join(lines), encoding="utf-8")


def reject_sensitive_output(output_dir: Path) -> None:
    hits: list[str] = []
    for path in output_dir.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for line_no, line in enumerate(text.splitlines(), 1):
            if RAW_BOX_ID.search(line) or SECRETISH.search(line) or RAW_ADB_SERIAL_LINE.search(line):
                hits.append(f"{path}:{line_no}")
    if hits:
        raise RuntimeError("sensitive-looking values found in import output: " + ", ".join(hits[:20]))


if __name__ == "__main__":
    sys.exit(main())
