#!/usr/bin/env python3
"""Verify retained physical/OEM closure against the API 23-36 runtime candidate.

The verifier consumes redacted summaries only. It requires two distinct OEMs
and Android API levels, direct sense/report evidence, hash-only BoxId pointers,
one APK candidate, and an exact match with a complete API 23-36 runtime set.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SHA256 = re.compile(r"[0-9a-f]{64}")
BOX_HASH = re.compile(r"sha256:[0-9a-f]{64}")
RAW_BOX_ID = re.compile(r"\b(?:[0-9A-HJKMNP-TV-Z]{26}|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})\b")
SECRETISH = re.compile(
    r"(?i)(ghp_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"LEONA_[A-Z0-9_]*(SECRET|TOKEN|KEY)[A-Z0-9_]*=[^\s]+|"
    r"(secret|token|credential)[=:]\s*[A-Za-z0-9._~+/=-]{16,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--physical-summary", required=True)
    parser.add_argument("--runtime-evidence", required=True)
    parser.add_argument("--output-dir", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    physical = load_redacted_json(Path(args.physical_summary), "physical summary", failures)
    runtime = load_redacted_json(Path(args.runtime_evidence), "runtime evidence", failures)

    physical_samples = physical.get("samples") if isinstance(physical.get("samples"), list) else []
    runtime_samples = runtime.get("samples") if isinstance(runtime.get("samples"), list) else []
    validate_physical(physical, physical_samples, failures)
    validate_runtime(runtime_samples, failures)

    physical_hashes = hashes(physical_samples)
    runtime_hashes = hashes(runtime_samples)
    candidate_match = len(physical_hashes) == 1 and physical_hashes == runtime_hashes
    if not candidate_match:
        failures.append("physical and API 23-36 runtime candidates must match exactly")

    status = "pass" if not failures else "failed"
    apis = {api_level(sample.get("androidApi")) for sample in physical_samples}
    apis.discard(None)
    brands = {normalize_brand(sample.get("brand")) for sample in physical_samples}
    brands.discard("")
    report: dict[str, Any] = {
        "status": status,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "physicalSampleCount": len(physical_samples),
        "distinctOemCount": len(brands),
        "distinctPhysicalApiCount": len(apis),
        "runtimeApiCount": len({sample.get("apiLevel") for sample in runtime_samples}),
        "physicalSameApk": len(physical_hashes) == 1,
        "runtimeSameApk": len(runtime_hashes) == 1,
        "physicalRuntimeCandidateMatches": candidate_match,
        "candidateApkSha256": next(iter(physical_hashes), None) if candidate_match else None,
        "physicalSummarySha256": file_sha256(Path(args.physical_summary)),
        "runtimeEvidenceSha256": file_sha256(Path(args.runtime_evidence)),
        "rawIdentifiersPrinted": False,
        "secretValuesPrinted": False,
        "commercialAdmissionClaimed": False,
        "failures": failures,
    }
    (output_dir / "summary.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_markdown(output_dir / "summary.md", report)
    print(f"[android-physical-oem-closure] {status}: {output_dir / 'summary.md'}")
    return 0 if status == "pass" else 1


def load_redacted_json(path: Path, label: str, failures: list[str]) -> dict[str, Any]:
    if not path.is_file():
        failures.append(f"{label} file missing")
        return {}
    text = path.read_text(encoding="utf-8", errors="strict")
    if RAW_BOX_ID.search(text) or SECRETISH.search(text):
        failures.append(f"{label} contains sensitive-looking values")
        return {}
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError:
        failures.append(f"{label} is invalid JSON")
        return {}
    if not isinstance(loaded, dict):
        failures.append(f"{label} must be an object")
        return {}
    return loaded


def validate_physical(data: dict[str, Any], samples: list[dict[str, Any]], failures: list[str]) -> None:
    if data.get("status") != "pass":
        failures.append("physical summary status must be pass")
    if data.get("sampleCount") != len(samples) or len(samples) < 2:
        failures.append("physical summary must contain at least two samples with matching count")
    if data.get("rawIdentifiersPrinted") is not False or data.get("secretValuesPrinted") is not False:
        failures.append("physical summary privacy flags must be false")
    brands: set[str] = set()
    apis: set[int] = set()
    for index, sample in enumerate(samples):
        if not isinstance(sample, dict):
            failures.append(f"physical sample {index} must be an object")
            continue
        brands.add(normalize_brand(sample.get("brand")))
        api = api_level(sample.get("androidApi"))
        if api is not None:
            apis.add(api)
        if sample.get("environmentType") != "wetest-physical-oem":
            failures.append(f"physical sample {index} environment type mismatch")
        if sample.get("result") != "pass" or sample.get("triggerType") != "direct":
            failures.append(f"physical sample {index} must be a direct pass")
        if sample.get("senseTriggered") is not True or sample.get("reportVerified") is not True:
            failures.append(f"physical sample {index} must prove sense and report")
        if not BOX_HASH.fullmatch(str(sample.get("boxIdHintOrHash") or "")):
            failures.append(f"physical sample {index} BoxId pointer must be SHA-256 only")
        if not SHA256.fullmatch(str(sample.get("apkSha256") or "")):
            failures.append(f"physical sample {index} APK hash invalid")
    brands.discard("")
    if len(brands) < 2:
        failures.append("physical closure requires at least two distinct OEMs")
    if len(apis) < 2:
        failures.append("physical closure requires at least two distinct Android APIs")


def validate_runtime(samples: list[dict[str, Any]], failures: list[str]) -> None:
    expected_apis = set(range(23, 37))
    actual_apis = {sample.get("apiLevel") for sample in samples if isinstance(sample, dict)}
    if actual_apis != expected_apis or len(samples) != len(expected_apis):
        failures.append("runtime evidence must cover API 23-36 exactly once")
    for index, sample in enumerate(samples):
        if not isinstance(sample, dict):
            failures.append(f"runtime sample {index} must be an object")
            continue
        if sample.get("result") != "pass":
            failures.append(f"runtime sample {index} result must be pass")
        if sample.get("senseTriggered") is not True or sample.get("reportVerified") is not True:
            failures.append(f"runtime sample {index} must prove sense and report")
        if sample.get("redacted") is not True or sample.get("rawIdentifiersPrinted") is not False:
            failures.append(f"runtime sample {index} redaction flags invalid")
        if not SHA256.fullmatch(str(sample.get("apkSha256") or "")):
            failures.append(f"runtime sample {index} APK hash invalid")


def hashes(samples: list[dict[str, Any]]) -> set[str]:
    return {
        str(sample.get("apkSha256"))
        for sample in samples
        if isinstance(sample, dict) and SHA256.fullmatch(str(sample.get("apkSha256") or ""))
    }


def api_level(value: Any) -> int | None:
    match = re.search(r"(?:^|/)\s*(\d{2})\s*$", str(value or ""))
    return int(match.group(1)) if match else None


def normalize_brand(value: Any) -> str:
    return str(value or "").strip().lower()


def file_sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    lines = [
        "# Android Physical/OEM Closure Verification",
        "",
        f"- status: {report['status']}",
        f"- physical sample count: {report['physicalSampleCount']}",
        f"- distinct OEM count: {report['distinctOemCount']}",
        f"- distinct physical API count: {report['distinctPhysicalApiCount']}",
        f"- runtime API count: {report['runtimeApiCount']}",
        f"- physical/runtime candidate matches: {str(report['physicalRuntimeCandidateMatches']).lower()}",
        "- raw identifiers printed: false",
        "- secret values printed: false",
        "- commercial admission claimed: false",
        "",
        "## Failures",
    ]
    lines.extend(f"- {item}" for item in report["failures"])
    if not report["failures"]:
        lines.append("- none")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
