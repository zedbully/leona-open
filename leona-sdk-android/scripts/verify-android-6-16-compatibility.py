#!/usr/bin/env python3
"""Verify the Android 6/API 23 through Android 16/API 36 contract.

Build compatibility and runtime acceptance are deliberately separate. A green
Gradle build never creates a runtime pass. Strict runtime mode requires one
fresh, redacted, hash-verified direct sample for every API in the contract.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_PROJECT_ROOT = SCRIPT_DIR.parent
DEFAULT_CONTRACT = DEFAULT_PROJECT_ROOT / "compatibility" / "android-6-16-contract.json"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FULL_BOX_ID_RE = re.compile(r"\b01[0-9A-HJKMNP-TV-Z]{24}\b")
SECRET_VALUE_RE = re.compile(
    r"(?i)(?:bearer\s+[A-Za-z0-9._~+/=-]{12,}|"
    r"(?:api|app|access|secret)[_-]?(?:key|token|secret)\s*[:=]\s*[^\s,}\]]{8,})"
)
BANNED_RAW_KEYS = {
    "androidid",
    "appkey",
    "boxid",
    "deviceid",
    "imei",
    "rawdeviceid",
    "secret",
    "serial",
    "token",
}


def version_tuple(value: str) -> tuple[int, ...]:
    numbers = re.findall(r"\d+", value)
    if not numbers:
        raise ValueError("version has no numeric components")
    return tuple(int(part) for part in numbers)


def version_at_least(actual: str, required: str) -> bool:
    left = version_tuple(actual)
    right = version_tuple(required)
    width = max(len(left), len(right))
    return left + (0,) * (width - len(left)) >= right + (0,) * (width - len(right))


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def extract_int_assignment(text: str, name: str) -> int | None:
    match = re.search(rf"(?m)^\s*{re.escape(name)}\s*=\s*(\d+)\s*$", text)
    return int(match.group(1)) if match else None


def extract_sample_min_sdk(text: str) -> int | None:
    direct = extract_int_assignment(text, "minSdk")
    if direct is not None:
        return direct
    values = [int(value) for value in re.findall(r"\bminSdk\s*=\s*[^\n]*?\b(\d+)\b", text)]
    return min(values) if values else None


def add_check(checks: list[dict[str, Any]], check_id: str, passed: bool, detail: str) -> None:
    checks.append({"id": check_id, "status": "pass" if passed else "fail", "detail": detail})


def validate_contract(contract: dict[str, Any], checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    scope = contract.get("scope", {})
    rows = scope.get("apiLevels", [])
    expected = [
        (23, "6.0"),
        (24, "7.0"),
        (25, "7.1"),
        (26, "8.0"),
        (27, "8.1"),
        (28, "9"),
        (29, "10"),
        (30, "11"),
        (31, "12"),
        (32, "12L"),
        (33, "13"),
        (34, "14"),
        (35, "15"),
        (36, "16"),
    ]
    actual = [(row.get("apiLevel"), row.get("androidVersion")) for row in rows if isinstance(row, dict)]
    add_check(checks, "contract.schema", contract.get("schemaVersion") == 1, "schemaVersion must equal 1")
    add_check(
        checks,
        "contract.api-range",
        scope.get("minimumApi") == 23 and scope.get("maximumApi") == 36,
        "minimumApi/maximumApi must be 23/36",
    )
    add_check(
        checks,
        "contract.api-rows",
        actual == expected,
        "API rows must exactly and contiguously map Android 6.0/API23 through Android 16/API36",
    )
    boundary = contract.get("decisionBoundary", {})
    add_check(
        checks,
        "contract.evidence-only-boundary",
        boundary.get("sdkRole") == "collect-and-report-evidence-only"
        and boundary.get("finalDecisionOwner") == "customer-backend",
        "SDK must collect/report evidence only and customer backend must own final decisions",
    )
    add_check(
        checks,
        "contract.same-apk-runtime",
        contract.get("runtimeContract", {}).get("requiresSameApkSha256AcrossMatrix") is True,
        "runtime evidence must prove the same APK SHA-256 across API23..36",
    )
    return rows


def verify_build(project_root: Path, contract: dict[str, Any], checks: list[dict[str, Any]], sdk_root: Path | None) -> None:
    build = contract["buildContract"]
    required_files = {
        key: project_root / build[key]
        for key in ("sdkGradleFile", "sampleGradleFile", "versionCatalogFile", "gradleWrapperFile")
    }
    missing = [key for key, path in required_files.items() if not path.is_file()]
    add_check(checks, "build.required-files", not missing, "required build files are present")
    if missing:
        return

    sdk_text = read_text(required_files["sdkGradleFile"])
    sample_text = read_text(required_files["sampleGradleFile"])
    catalog_text = read_text(required_files["versionCatalogFile"])
    wrapper_text = read_text(required_files["gradleWrapperFile"])
    sdk_compile = extract_int_assignment(sdk_text, "compileSdk")
    sdk_min = extract_int_assignment(sdk_text, "minSdk")
    sample_compile = extract_int_assignment(sample_text, "compileSdk")
    sample_target = extract_int_assignment(sample_text, "targetSdk")
    sample_min = extract_sample_min_sdk(sample_text)

    add_check(checks, "build.sdk-compile-sdk", sdk_compile is not None and sdk_compile >= build["minimumCompileSdk"], "SDK compileSdk >= 36")
    add_check(checks, "build.sample-compile-sdk", sample_compile is not None and sample_compile >= build["minimumCompileSdk"], "sample compileSdk >= 36")
    add_check(checks, "build.sample-target-sdk", sample_target is not None and sample_target >= build["minimumTargetSdk"], "sample targetSdk >= 36")
    add_check(checks, "build.sdk-min-sdk", sdk_min is not None and sdk_min <= build["maximumMinSdk"], "SDK minSdk <= API23")
    add_check(checks, "build.sample-min-sdk", sample_min is not None and sample_min <= build["maximumMinSdk"], "sample minSdk <= API23")

    agp_match = re.search(r'(?m)^\s*agp\s*=\s*"([^"]+)"\s*$', catalog_text)
    gradle_match = re.search(r"gradle-([0-9][0-9.]*)-bin\.zip", wrapper_text)
    gradle_sha_match = re.search(r"(?m)^distributionSha256Sum=([0-9a-f]{64})$", wrapper_text)
    agp = agp_match.group(1) if agp_match else ""
    gradle = gradle_match.group(1) if gradle_match else ""
    gradle_sha = gradle_sha_match.group(1) if gradle_sha_match else ""
    add_check(
        checks,
        "build.agp",
        bool(agp) and version_at_least(agp, build["minimumAgp"]),
        f"AGP >= {build['minimumAgp']}",
    )
    add_check(
        checks,
        "build.gradle",
        bool(gradle) and version_at_least(gradle, build["minimumGradle"]),
        f"Gradle >= {build['minimumGradle']}",
    )
    add_check(
        checks,
        "build.gradle-distribution-sha256",
        gradle_sha == build["requiredGradleDistributionSha256"],
        "Gradle wrapper distribution SHA-256 must match the contract",
    )

    if sdk_root is None:
        checks.append({"id": "host.android-sdk", "status": "not-run", "detail": "Android SDK root not provided or discovered"})
        return
    platform = sdk_root / "platforms" / "android-36" / "android.jar"
    build_tools = sdk_root / "build-tools" / build["requiredBuildTools"].split(";", 1)[1]
    add_check(checks, "host.android-36-platform", platform.is_file() and platform.stat().st_size > 1_000_000, "Android 16 platform android.jar is complete")
    add_check(checks, "host.build-tools-36", (build_tools / "aapt2").is_file(), "Android Build-Tools 36.0.0 is installed")


def iter_keys(value: Any):
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key)
            yield from iter_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_keys(child)


def contains_sensitive_material(value: Any) -> bool:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    if FULL_BOX_ID_RE.search(text) or SECRET_VALUE_RE.search(text):
        return True
    for key in iter_keys(value):
        normalized = re.sub(r"[^a-z0-9]", "", key.lower())
        if normalized in BANNED_RAW_KEYS:
            return True
    return False


def parse_utc(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def verify_redacted_import_artifact(artifact: Path, api: int, collected_at: str, apk_sha256: str) -> bool:
    try:
        report = json.loads(read_text(artifact))
    except (OSError, json.JSONDecodeError):
        return False
    if contains_sensitive_material(report):
        return False
    if (
        report.get("status") != "pass"
        or report.get("sampleCount") != 1
        or report.get("rawIdentifiersPrinted") is not False
        or report.get("secretValuesPrinted") is not False
    ):
        return False
    samples = report.get("samples")
    if not isinstance(samples, list) or len(samples) != 1 or not isinstance(samples[0], dict):
        return False
    source = samples[0]
    android_api = source.get("androidApi", "")
    api_match = re.fullmatch(r"\s*.+?\s*/\s*(\d+)\s*", android_api) if isinstance(android_api, str) else None
    return bool(
        api_match
        and int(api_match.group(1)) == api
        and source.get("result") == "pass"
        and source.get("triggerType") == "direct"
        and source.get("senseTriggered") is True
        and source.get("reportVerified") is True
        and source.get("collectedAt") == collected_at
        and source.get("apkSha256") == apk_sha256
    )


def verify_runtime(
    runtime_path: Path | None,
    rows: list[dict[str, Any]],
    contract: dict[str, Any],
    checks: list[dict[str, Any]],
    now: datetime,
) -> dict[str, Any]:
    required_apis = [row["apiLevel"] for row in rows]
    versions = {row["apiLevel"]: row["androidVersion"] for row in rows}
    result: dict[str, Any] = {"requiredApis": required_apis, "passingApis": [], "missingApis": required_apis}
    if runtime_path is None:
        checks.append({"id": "runtime.manifest", "status": "missing", "detail": "no runtime evidence manifest supplied"})
        return result
    if not runtime_path.is_file():
        checks.append({"id": "runtime.manifest", "status": "fail", "detail": "runtime evidence manifest does not exist"})
        return result
    try:
        manifest = json.loads(read_text(runtime_path))
    except (OSError, json.JSONDecodeError):
        checks.append({"id": "runtime.manifest", "status": "fail", "detail": "runtime evidence manifest is not valid JSON"})
        return result
    sensitive = contains_sensitive_material(manifest)
    add_check(
        checks,
        "runtime.redaction",
        not sensitive,
        "runtime manifest contains no forbidden raw identifier or credential-like material",
    )
    if sensitive:
        return result
    add_check(checks, "runtime.schema", manifest.get("schemaVersion") == 1, "runtime schemaVersion must equal 1")
    samples = manifest.get("samples")
    if not isinstance(samples, list):
        checks.append({"id": "runtime.samples", "status": "fail", "detail": "samples must be an array"})
        return result

    by_api: dict[int, list[dict[str, Any]]] = {}
    for sample in samples:
        if isinstance(sample, dict) and isinstance(sample.get("apiLevel"), int):
            by_api.setdefault(sample["apiLevel"], []).append(sample)
    duplicates = sorted(api for api, values in by_api.items() if len(values) != 1)
    extras = sorted(api for api in by_api if api not in required_apis)
    add_check(checks, "runtime.unique-api-rows", not duplicates, "exactly one sample is allowed per API")
    add_check(checks, "runtime.no-extra-apis", not extras, "runtime manifest must not contain APIs outside 23..36")

    supplied_samples = [sample for sample in samples if isinstance(sample, dict)]
    supplied_apk_hashes = [str(sample.get("apkSha256") or "").strip().lower() for sample in supplied_samples]
    valid_apk_hashes = [value for value in supplied_apk_hashes if SHA256_RE.fullmatch(value)]
    same_apk = bool(supplied_samples) and len(valid_apk_hashes) == len(supplied_samples) and len(set(valid_apk_hashes)) == 1
    if not supplied_samples:
        checks.append({
            "id": "runtime.same-apk-candidate",
            "status": "incomplete",
            "detail": "no runtime samples were supplied to establish one APK candidate",
        })
    else:
        add_check(
            checks,
            "runtime.same-apk-candidate",
            same_apk,
            "every supplied runtime row must carry the same valid APK SHA-256",
        )
    result["sameApkAcrossMatrix"] = same_apk
    result["apkSha256"] = valid_apk_hashes[0] if same_apk else ""

    runtime = contract["runtimeContract"]
    max_age = float(runtime["maximumEvidenceAgeHours"])
    passing: list[int] = []
    failures: list[str] = []
    invalid_evidence = False
    for api in required_apis:
        values = by_api.get(api, [])
        if len(values) != 1:
            failures.append(f"api{api}:missing-or-duplicate")
            continue
        sample = values[0]
        collected = parse_utc(sample.get("collectedAt", ""))
        age_hours = (now - collected).total_seconds() / 3600 if collected else max_age + 1
        artifact_value = sample.get("artifactPath")
        artifact = Path(artifact_value).expanduser().resolve() if isinstance(artifact_value, str) else None
        prefix_ok = bool(artifact) and any(str(artifact).startswith(prefix) for prefix in runtime["artifactPathPrefixes"])
        expected_hash = sample.get("artifactSha256", "")
        hash_ok = isinstance(expected_hash, str) and SHA256_RE.fullmatch(expected_hash) is not None
        apk_sha256 = str(sample.get("apkSha256") or "").strip().lower()
        apk_hash_ok = SHA256_RE.fullmatch(apk_sha256) is not None
        actual_hash_ok = False
        artifact_semantics_ok = False
        if artifact and artifact.is_file() and hash_ok:
            actual_hash = hashlib.sha256(artifact.read_bytes()).hexdigest()
            actual_hash_ok = actual_hash == expected_hash
            artifact_semantics_ok = actual_hash_ok and verify_redacted_import_artifact(
                artifact,
                api,
                sample.get("collectedAt", ""),
                apk_sha256,
            )
        fields_ok = (
            sample.get("androidVersion") == versions[api]
            and sample.get("evidenceClass") == runtime["requiredEvidenceClass"]
            and sample.get("result") == runtime["requiredResult"]
            and sample.get("artifactType") == runtime["requiredArtifactType"]
            and sample.get("senseTriggered") is True
            and sample.get("reportVerified") is True
            and sample.get("redacted") is True
            and sample.get("rawIdentifiersPrinted") is False
            and apk_hash_ok
            and same_apk
            and collected is not None
            and 0 <= age_hours <= max_age
            and prefix_ok
            and actual_hash_ok
            and artifact_semantics_ok
        )
        if fields_ok:
            passing.append(api)
        else:
            invalid_evidence = True
            failures.append(f"api{api}:invalid-direct-runtime-evidence")

    result["passingApis"] = passing
    result["missingApis"] = [api for api in required_apis if api not in passing]
    if len(passing) == len(required_apis):
        checks.append({
            "id": "runtime.direct-api23-36",
            "status": "pass",
            "detail": "every API23..36 has fresh direct sense/report evidence with a verified redacted artifact",
        })
    elif invalid_evidence:
        checks.append({
            "id": "runtime.direct-api23-36",
            "status": "fail",
            "detail": "one or more supplied API rows contain invalid direct runtime evidence",
        })
    else:
        checks.append({
            "id": "runtime.direct-api23-36",
            "status": "incomplete",
            "detail": "valid direct runtime evidence exists for only part of API23..36",
        })
    result["failureHints"] = failures
    return result


def render_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# Android 6–16 Compatibility Verification",
        "",
        f"- status: {summary['status']}",
        f"- strictRuntime: {str(summary['strictRuntime']).lower()}",
        f"- contractId: {summary['contractId']}",
        f"- buildContractPassed: {str(summary['buildContractPassed']).lower()}",
        f"- runtimeComplete: {str(summary['runtimeComplete']).lower()}",
        "- SDK role: collect and report evidence only",
        "- final decision owner: customer backend",
        "",
        "## Checks",
        "",
    ]
    for check in summary["checks"]:
        lines.append(f"- {check['id']}: {check['status']} — {check['detail']}")
    lines.extend(
        [
            "",
            "## Runtime Matrix",
            "",
            "- required APIs: " + ", ".join(map(str, summary["runtime"]["requiredApis"])),
            "- passing APIs: " + (", ".join(map(str, summary["runtime"]["passingApis"])) or "none"),
            "- missing APIs: " + (", ".join(map(str, summary["runtime"]["missingApis"])) or "none"),
            "- same APK across matrix: " + str(summary["runtime"].get("sameApkAcrossMatrix") is True).lower(),
        ]
    )
    return "\n".join(lines) + "\n"


def discover_sdk_root(explicit: str | None) -> Path | None:
    value = explicit or os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
    if value:
        return Path(value).expanduser().resolve()
    default = Path.home() / "Library" / "Android" / "sdk"
    return default if default.is_dir() else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", default=str(DEFAULT_CONTRACT))
    parser.add_argument("--project-root", default=str(DEFAULT_PROJECT_ROOT))
    parser.add_argument("--runtime-evidence")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--android-sdk-root")
    parser.add_argument("--strict-runtime", action="store_true")
    parser.add_argument("--now", help="UTC ISO timestamp used only for reproducible verification")
    args = parser.parse_args(argv)

    out_dir = Path(args.output_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    checks: list[dict[str, Any]] = []
    try:
        contract = json.loads(read_text(Path(args.contract).expanduser().resolve()))
    except (OSError, json.JSONDecodeError):
        contract = {}
        checks.append({"id": "contract.load", "status": "fail", "detail": "contract file is missing or invalid"})
    rows = validate_contract(contract, checks) if contract else []
    if contract:
        verify_build(Path(args.project_root).expanduser().resolve(), contract, checks, discover_sdk_root(args.android_sdk_root))
    now = parse_utc(args.now) if args.now else datetime.now(timezone.utc)
    if now is None:
        checks.append({"id": "runtime.now", "status": "fail", "detail": "--now must be a timezone-qualified ISO timestamp"})
        now = datetime.now(timezone.utc)
    runtime = verify_runtime(
        Path(args.runtime_evidence).expanduser().resolve() if args.runtime_evidence else None,
        rows,
        contract,
        checks,
        now,
    ) if contract and rows else {"requiredApis": list(range(23, 37)), "passingApis": [], "missingApis": list(range(23, 37))}

    contract_failures = [check for check in checks if check["status"] == "fail" and not check["id"].startswith("runtime.")]
    runtime_failures = [check for check in checks if check["status"] == "fail" and check["id"].startswith("runtime.")]
    build_passed = not contract_failures
    runtime_complete = not runtime["missingApis"] and not runtime_failures
    if not build_passed or runtime_failures or (args.strict_runtime and not runtime_complete):
        status = "fail"
    elif runtime_complete:
        status = "pass"
    else:
        status = "build-pass-runtime-incomplete"
    summary = {
        "schemaVersion": 1,
        "status": status,
        "strictRuntime": args.strict_runtime,
        "contractId": contract.get("contractId", "unknown") if isinstance(contract, dict) else "unknown",
        "buildContractPassed": build_passed,
        "runtimeComplete": runtime_complete,
        "decisionBoundary": contract.get("decisionBoundary", {}) if isinstance(contract, dict) else {},
        "checks": checks,
        "runtime": runtime,
        "secretValuesPrinted": False,
        "rawIdentifiersPrinted": False,
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out_dir / "summary.md").write_text(render_markdown(summary), encoding="utf-8")
    print(f"[android-6-16] {status}: {out_dir / 'summary.md'}")
    return 1 if status == "fail" else 0


if __name__ == "__main__":
    sys.exit(main())
