#!/usr/bin/env python3
"""Verify redacted GitHub-hosted Android runtime evidence.

This verifier proves that the same cloudTest APK completed a direct
``sense()``/public-hosted report on each required GitHub-managed AVD boundary.
It is runtime compatibility evidence, not Play Integrity/OEM admission and not
a customer business decision.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SHA256 = re.compile(r"^[0-9a-f]{64}$")
BOX_ID_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
RAW_BOX_ID = re.compile(
    r"\b(?:[0-9A-HJKMNP-TV-Z]{26}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b"
)
SECRETISH = re.compile(
    r"(?i)(ghp_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"LEONA_[A-Z0-9_]*(SECRET|TOKEN|KEY)[A-Z0-9_]*=[^\s]+|"
    r"(secret|token|credential)[=:]\s*[A-Za-z0-9._~+/=-]{16,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-root", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument(
        "--required-api",
        action="append",
        type=int,
        dest="required_apis",
        help="Required API level; repeat for multiple levels (default: 23 and 36)",
    )
    return parser.parse_args()


def read_json(path: Path, failures: list[str]) -> dict[str, Any]:
    if not path.is_file():
        failures.append(f"missing required JSON: {path}")
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        failures.append(f"invalid JSON {path}: {error}")
        return {}
    if not isinstance(value, dict):
        failures.append(f"JSON root must be an object: {path}")
        return {}
    return value


def expect(condition: bool, failures: list[str], message: str) -> None:
    if not condition:
        failures.append(message)


def api_from_version(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    match = re.search(r"(?:^|/)\s*(\d+)\s*$", value)
    return int(match.group(1)) if match else None


def sensitive_hits(root: Path, ignored_root: Path) -> list[str]:
    hits: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or ignored_root == path or ignored_root in path.parents:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for line_no, line in enumerate(text.splitlines(), 1):
            if RAW_BOX_ID.search(line) or SECRETISH.search(line):
                hits.append(f"{path}:{line_no}")
    return hits


def verify_api(root: Path, api: int, failures: list[str]) -> dict[str, Any]:
    api_dir = root / f"api-{api}"
    import_summary_path = api_dir / "redacted" / "summary.json"
    receipt_path = api_dir / "fixture-receipt.json"
    provenance_path = api_dir / "provenance.json"
    report = read_json(import_summary_path, failures)
    receipt = read_json(receipt_path, failures)
    provenance = read_json(provenance_path, failures)

    expect(report.get("status") == "pass", failures, f"API {api}: import status must be pass")
    expect(report.get("sampleCount") == 1, failures, f"API {api}: sampleCount must be 1")
    expect(report.get("sourceLabel") == f"github-hosted-avd-api-{api}", failures, f"API {api}: sourceLabel mismatch")
    expect(report.get("secretValuesPrinted") is False, failures, f"API {api}: secretValuesPrinted must be false")
    expect(report.get("rawIdentifiersPrinted") is False, failures, f"API {api}: rawIdentifiersPrinted must be false")
    samples = report.get("samples")
    sample = samples[0] if isinstance(samples, list) and len(samples) == 1 and isinstance(samples[0], dict) else {}
    expect(bool(sample), failures, f"API {api}: one sample object is required")
    expect(sample.get("environmentType") == "github-hosted-avd", failures, f"API {api}: environmentType mismatch")
    expect(api_from_version(sample.get("androidApi")) == api, failures, f"API {api}: androidApi mismatch")
    expect(sample.get("result") == "pass", failures, f"API {api}: result must be pass")
    expect(sample.get("triggerType") == "direct", failures, f"API {api}: triggerType must be direct")
    expect(sample.get("senseTriggered") is True, failures, f"API {api}: senseTriggered must be true")
    expect(sample.get("reportVerified") is True, failures, f"API {api}: reportVerified must be true")
    apk_sha = sample.get("apkSha256")
    expect(isinstance(apk_sha, str) and bool(SHA256.fullmatch(apk_sha)), failures, f"API {api}: apkSha256 must be 64 lowercase hex")
    box_hint = sample.get("boxIdHintOrHash")
    expect(
        isinstance(box_hint, str) and ("..." in box_hint or bool(BOX_ID_SHA256.fullmatch(box_hint))),
        failures,
        f"API {api}: BoxId must be redacted to a hint or SHA-256",
    )

    expect(receipt.get("schemaVersion") == 1, failures, f"API {api}: receipt schemaVersion mismatch")
    expect(receipt.get("status") == "pass", failures, f"API {api}: receipt status must be pass")
    expect(receipt.get("mode") == "public_hosted", failures, f"API {api}: receipt mode mismatch")
    expect(receipt.get("apiKeyAccepted") is True, failures, f"API {api}: fixture AppKey was not accepted")
    expect(receipt.get("sdkInt") == api, failures, f"API {api}: receipt sdkInt mismatch")
    expect(receipt.get("businessDecisionProduced") is False, failures, f"API {api}: fixture must not produce a business decision")
    expect(receipt.get("secretValuesPrinted") is False, failures, f"API {api}: receipt secret flag drift")
    expect(receipt.get("rawIdentifiersPrinted") is False, failures, f"API {api}: receipt raw identifier flag drift")
    for field in ("requestBodySha256", "payloadSha256", "deviceContextSha256"):
        value = receipt.get(field)
        expect(isinstance(value, str) and bool(SHA256.fullmatch(value)), failures, f"API {api}: receipt {field} must be SHA-256")

    expect(provenance.get("schemaVersion") == 1, failures, f"API {api}: provenance schemaVersion mismatch")
    expect(provenance.get("provider") == "github-actions", failures, f"API {api}: provider mismatch")
    expect(provenance.get("runnerManaged") is True, failures, f"API {api}: runnerManaged must be true")
    expect(provenance.get("apiLevel") == api, failures, f"API {api}: provenance apiLevel mismatch")
    expect(provenance.get("architecture") == "x86_64", failures, f"API {api}: architecture mismatch")
    expect(provenance.get("target") == "google_apis", failures, f"API {api}: target mismatch")
    expect(provenance.get("triggerType") == "direct", failures, f"API {api}: provenance trigger mismatch")
    expect(provenance.get("artifactBoundary") == "redacted-only", failures, f"API {api}: artifact boundary mismatch")
    expect(provenance.get("businessDecisionOwner") == "customer-backend", failures, f"API {api}: business decision owner mismatch")
    expect(provenance.get("sdkRole") == "collect-and-report-evidence-only", failures, f"API {api}: SDK role mismatch")
    commit_sha = provenance.get("gitCommit")
    expect(isinstance(commit_sha, str) and bool(COMMIT_SHA.fullmatch(commit_sha)), failures, f"API {api}: gitCommit must be full SHA")
    expect(provenance.get("apkSha256") == apk_sha, failures, f"API {api}: provenance APK hash mismatch")

    return {
        "apiLevel": api,
        "status": "pass" if not any(item.startswith(f"API {api}:") for item in failures) else "fail",
        "apkSha256": apk_sha if isinstance(apk_sha, str) else "",
        "gitCommit": commit_sha if isinstance(commit_sha, str) else "",
        "importSummary": str(import_summary_path),
        "receipt": str(receipt_path),
        "provenance": str(provenance_path),
    }


def main() -> int:
    args = parse_args()
    root = Path(args.input_root).resolve()
    output_dir = Path(args.output_dir).resolve()
    required_apis = sorted(set(args.required_apis or [23, 36]))
    failures: list[str] = []
    expect(root.is_dir(), failures, f"input root does not exist: {root}")
    expect(bool(required_apis), failures, "at least one required API is needed")
    expect(all(23 <= api <= 36 for api in required_apis), failures, "required APIs must be within 23..36")

    api_results = [verify_api(root, api, failures) for api in required_apis] if root.is_dir() else []
    apk_hashes = {item["apkSha256"] for item in api_results if item.get("apkSha256")}
    commit_hashes = {item["gitCommit"] for item in api_results if item.get("gitCommit")}
    expect(len(apk_hashes) == 1, failures, "all required APIs must use the exact same APK SHA-256")
    expect(len(commit_hashes) == 1, failures, "all required APIs must bind the same Git commit")

    hits = sensitive_hits(root, output_dir) if root.is_dir() else []
    expect(not hits, failures, "sensitive-looking values found: " + ", ".join(hits[:20]))
    status = "pass" if not failures else "fail"
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = {
        "schemaVersion": 1,
        "status": status,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "inputRoot": str(root),
        "requiredApis": required_apis,
        "runtimeComplete": status == "pass" and len(api_results) == len(required_apis),
        "sameApkCandidate": len(apk_hashes) == 1 and bool(apk_hashes),
        "sdkRole": "collect-and-report-evidence-only",
        "businessDecisionOwner": "customer-backend",
        "commercialAdmissionClaimed": False,
        "secretValuesPrinted": False,
        "rawIdentifiersPrinted": False,
        "failures": failures,
        "apis": api_results,
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "# GitHub-hosted Android Runtime Evidence",
        "",
        f"- status: {status}",
        f"- required APIs: {', '.join(map(str, required_apis))}",
        f"- runtime complete: {str(summary['runtimeComplete']).lower()}",
        f"- same APK candidate: {str(summary['sameApkCandidate']).lower()}",
        "- SDK role: collect and report evidence only",
        "- business decision owner: customer backend",
        "- commercial admission claimed: false",
        "- secret values printed: false",
        "- raw identifiers printed: false",
        "",
        "## APIs",
        "",
    ]
    for item in api_results:
        lines.append(f"- API {item['apiLevel']}: {item['status']}")
    if failures:
        lines.extend(["", "## Failures", ""])
        lines.extend(f"- {failure}" for failure in failures)
    (output_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[github-hosted-runtime-evidence] {status}: {output_dir / 'summary.md'}")
    return 0 if status == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
