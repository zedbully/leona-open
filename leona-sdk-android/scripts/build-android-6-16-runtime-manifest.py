#!/usr/bin/env python3
"""Build a fail-closed Android API23-36 runtime manifest from redacted imports."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


VERSIONS = {
    23: "6.0",
    24: "7.0",
    25: "7.1",
    26: "8.0",
    27: "8.1",
    28: "9",
    29: "10",
    30: "11",
    31: "12",
    32: "12L",
    33: "13",
    34: "14",
    35: "15",
    36: "16",
}
FULL_BOX_ID_RE = re.compile(r"\b01[0-9A-HJKMNP-TV-Z]{24}\b")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CREDENTIAL_RE = re.compile(
    r"(?i)(?:lk_(?:live|dev)_(?:app_|sec_)?|ct_)[A-Za-z0-9_-]{12,}|"
    r"bearer\s+[A-Za-z0-9._~+/=-]{12,}|BEGIN (?:RSA |OPENSSH |PGP )?PRIVATE KEY"
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sample",
        action="append",
        default=[],
        metavar="API=SUMMARY_JSON",
        help="Redacted importer summary for one API; repeat for each row",
    )
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--require-complete", action="store_true")
    return parser.parse_args(argv)


def parse_sample_arg(value: str) -> tuple[int, Path]:
    if "=" not in value:
        raise ValueError("sample must use API=SUMMARY_JSON")
    raw_api, raw_path = value.split("=", 1)
    try:
        api = int(raw_api)
    except ValueError as error:
        raise ValueError("sample API must be an integer") from error
    if api not in VERSIONS:
        raise ValueError("sample API must be in 23..36")
    if not raw_path:
        raise ValueError("sample summary path is empty")
    return api, Path(raw_path).expanduser()


def parse_timestamp(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def source_is_sensitive(value: Any) -> bool:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    return bool(FULL_BOX_ID_RE.search(text) or CREDENTIAL_RE.search(text))


def validate_import(api: int, path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.is_file():
        return None, "summary-missing"
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, "summary-invalid-json"
    if source_is_sensitive(report):
        return None, "summary-sensitive-material"
    if report.get("status") != "pass" or report.get("sampleCount") != 1:
        return None, "summary-not-single-pass"
    if report.get("rawIdentifiersPrinted") is not False or report.get("secretValuesPrinted") is not False:
        return None, "summary-redaction-flags-invalid"
    samples = report.get("samples")
    if not isinstance(samples, list) or len(samples) != 1 or not isinstance(samples[0], dict):
        return None, "summary-samples-invalid"
    sample = samples[0]
    android_api = sample.get("androidApi", "")
    api_match = re.fullmatch(r"\s*.+?\s*/\s*(\d+)\s*", android_api) if isinstance(android_api, str) else None
    if not api_match or int(api_match.group(1)) != api:
        return None, "summary-api-mismatch"
    if sample.get("result") != "pass":
        return None, "sample-result-not-pass"
    if sample.get("triggerType") != "direct" or sample.get("senseTriggered") is not True:
        return None, "sample-trigger-not-direct"
    if sample.get("reportVerified") is not True:
        return None, "sample-report-not-verified"
    apk_sha256 = str(sample.get("apkSha256") or "").strip().lower()
    if SHA256_RE.fullmatch(apk_sha256) is None:
        return None, "sample-apk-sha256-invalid"
    if not parse_timestamp(sample.get("collectedAt")):
        return None, "sample-collected-at-invalid"
    if not parse_timestamp(report.get("generatedAt")):
        return None, "summary-generated-at-invalid"
    artifact = path.resolve()
    return {
        "apiLevel": api,
        "androidVersion": VERSIONS[api],
        "collectedAt": sample["collectedAt"],
        "evidenceClass": "current-direct-runtime",
        "result": "pass",
        "artifactType": "redacted-matrix-import-summary-v1",
        "senseTriggered": True,
        "reportVerified": True,
        "apkSha256": apk_sha256,
        "redacted": True,
        "rawIdentifiersPrinted": False,
        "artifactPath": str(artifact),
        "artifactSha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
    }, None


def render_markdown(summary: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Android 6-16 Runtime Manifest Build",
            "",
            f"- status: {summary['status']}",
            f"- requireComplete: {str(summary['requireComplete']).lower()}",
            f"- runtime evidence: `{summary['runtimeEvidencePath']}`",
            f"- passing APIs: {', '.join(map(str, summary['passingApis'])) or 'none'}",
            f"- missing APIs: {', '.join(map(str, summary['missingApis'])) or 'none'}",
            f"- same APK across matrix: {str(summary['sameApkAcrossMatrix']).lower()}",
            f"- failures: {', '.join(summary['failures']) or 'none'}",
            "- secret values printed: false",
            "- raw identifiers printed: false",
            "- SDK role: collect and report evidence only",
            "- final decision owner: customer backend",
            "",
        ]
    )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []
    parsed: dict[int, Path] = {}
    for raw in args.sample:
        try:
            api, path = parse_sample_arg(raw)
        except ValueError as error:
            failures.append(f"argument:{error}")
            continue
        if api in parsed:
            failures.append(f"api{api}:duplicate")
            continue
        parsed[api] = path

    runtime_samples: list[dict[str, Any]] = []
    for api, path in sorted(parsed.items()):
        sample, error = validate_import(api, path)
        if error:
            failures.append(f"api{api}:{error}")
        elif sample:
            runtime_samples.append(sample)

    passing = [sample["apiLevel"] for sample in runtime_samples]
    missing = [api for api in VERSIONS if api not in passing]
    apk_hashes = {sample["apkSha256"] for sample in runtime_samples}
    same_apk = bool(runtime_samples) and len(apk_hashes) == 1
    if len(runtime_samples) > 1 and not same_apk:
        failures.append("matrix:apk-sha256-mismatch")
    if failures or (args.require_complete and missing):
        status = "fail"
    elif missing:
        status = "partial"
    else:
        status = "pass"

    runtime_path = output_dir / "runtime-evidence.json"
    runtime_path.write_text(
        json.dumps({"schemaVersion": 1, "samples": runtime_samples}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    summary = {
        "schemaVersion": 1,
        "status": status,
        "requireComplete": args.require_complete,
        "runtimeEvidencePath": str(runtime_path),
        "passingApis": passing,
        "missingApis": missing,
        "sameApkAcrossMatrix": same_apk,
        "apkSha256": next(iter(apk_hashes)) if same_apk else "",
        "failures": failures,
        "secretValuesPrinted": False,
        "rawIdentifiersPrinted": False,
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (output_dir / "summary.md").write_text(render_markdown(summary), encoding="utf-8")
    print(f"[android-6-16-runtime-manifest] {status}: {output_dir / 'summary.md'}")
    return 1 if status == "fail" else 0


if __name__ == "__main__":
    sys.exit(main())
