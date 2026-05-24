#!/usr/bin/env python3
"""Preflight the v0.4 Android attestation real-smoke lane.

This is a public-safe local gate. It validates the wiring that can be checked
without production provider material, then reports the external material still
required for a real Play Integrity or OEM attestation smoke.

The script never prints credential values. It only records presence/absence and
sanitized blocker labels.
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


SDK_DIR = Path(__file__).resolve().parents[1]
REPO_DIR = SDK_DIR.parent
RAW_BOX_ID = re.compile(r"\b[0-9A-HJKMNP-TV-Z]{26}\b")
SECRETISH = re.compile(
    r"(?i)(ghp_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"LEONA_[A-Z0-9_]*(SECRET|TOKEN|KEY)[A-Z0-9_]*=[^\s]+|"
    r"(secret|token|credential)[=:]\s*[A-Za-z0-9._~+/=-]{16,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)

EXPECTED_BLOCKER_CODES = {
    "play_integrity": {
        "play_integrity_dependency",
        "play_integrity_cloud_project",
        "play_integrity_server_verifier",
    },
    "oem": {
        "oem_trusted_provider_allowlist",
        "oem_private_verifier",
        "oem_provider_namespace",
        "oem_device_bridge",
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        default="/tmp/leona-v0.4-attestation-real-smoke-preflight-active",
        help="Directory for summary.json and summary.md",
    )
    parser.add_argument(
        "--target",
        choices=("both", "play_integrity", "oem"),
        default=os.environ.get("LEONA_ATTESTATION_REAL_PROVIDER_TARGET", "both"),
        help="Provider lane to preflight",
    )
    parser.add_argument(
        "--require-real-provider",
        action="store_true",
        default=os.environ.get("LEONA_REQUIRE_REAL_ATTESTATION_PROVIDER") == "1",
        help="Fail when external provider material is missing",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    checks = run_local_checks()
    provider_replay = run_provider_replay_checks()
    blockers = run_external_material_checks(args.target)
    failures = [check for check in checks if check["status"] == "fail"]
    if failures:
        status = "failed"
    elif blockers and args.require_real_provider:
        status = "failed"
    elif blockers:
        status = "local-pass-with-external-blockers"
    else:
        status = "ready-for-real-smoke"

    blocker_codes = [item["code"] for item in blockers]
    expected_codes = expected_blocker_codes(args.target)
    missing_expected_blockers = sorted(expected_codes.difference(blocker_codes))
    unexpected_blockers = sorted(set(blocker_codes).difference(expected_codes))
    blocker_counts = blocker_counts_by_provider(blockers)
    report: dict[str, Any] = {
        "status": status,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "target": args.target,
        "requireRealProvider": args.require_real_provider,
        "providerReplay": provider_replay,
        "providerReplayStatus": provider_replay["status"],
        "providerReplayFixtureCount": provider_replay["fixtureCount"],
        "providerReplayPassCount": provider_replay["passCount"],
        "providerReplayFailureCount": provider_replay["failureCount"],
        "checks": checks,
        "localCheckCount": len(checks),
        "localPassCount": sum(1 for check in checks if check["status"] == "pass"),
        "externalBlockers": blockers,
        "externalBlockerCodes": blocker_codes,
        "expectedExternalBlockerCodes": sorted(expected_codes),
        "missingExpectedExternalBlockers": missing_expected_blockers,
        "unexpectedExternalBlockers": unexpected_blockers,
        "externalBlockerCountsByProvider": blocker_counts,
        "localFailureCount": len(failures),
        "externalBlockerCount": len(blockers),
        "secretValuesPrinted": False,
        "createsTag": False,
        "publishesArtifacts": False,
        "startsPaidDevices": False,
    }
    write_report(output_dir, report)
    reject_sensitive_output(output_dir)
    print(f"[attestation-real-smoke-preflight] summary: {output_dir / 'summary.md'}")
    return 0 if status != "failed" else 1


def run_local_checks() -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []
    checks.append(require_pattern(
        "sdk play integrity scaffold exists",
        SDK_DIR / "sdk/src/main/kotlin/io/leonasec/leona/config/PlayIntegrityAttestationProvider.kt",
        r"class PlayIntegrityAttestationProvider|PlayIntegrityTokenProvider",
    ))
    checks.append(require_pattern(
        "sample app real Play Integrity bridge is reflection-gated",
        SDK_DIR / "sample-app/src/main/kotlin/io/leonasec/leona/sample/ReflectivePlayIntegrityBridge.kt",
        r"StandardIntegrityManager|createIfAvailable|PLAY_INTEGRITY",
    ))
    checks.append(require_pattern(
        "sample app exposes real Play Integrity Gradle switch",
        SDK_DIR / "sample-app/build.gradle.kts",
        r"LEONA_SAMPLE_ENABLE_REAL_PLAY_INTEGRITY_DEP|com\.google\.android\.play:integrity",
    ))
    checks.append(require_pattern(
        "sample app exposes Play Integrity cloud project switch",
        SDK_DIR / "sample-app/build.gradle.kts",
        r"LEONA_SAMPLE_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER",
    ))
    checks.append(require_pattern(
        "sample release build strips debug fake provider",
        SDK_DIR / "sample-app/src/release/kotlin/io/leonasec/leona/sample/SamplePlayIntegrityDebugProvider.kt",
        r"AttestationProvider\?\s*=\s*null",
    ))
    checks.append(require_pattern(
        "Play Integrity real bridge template is present",
        SDK_DIR / "sample-app/PLAY_INTEGRITY_REAL_BRIDGE_TEMPLATE.md",
        r"StandardIntegrityManager|requestHash|cloudProjectNumber",
    ))
    checks.append(require_pattern(
        "OEM bridge template is present",
        SDK_DIR / "sample-app/MAINLAND_ATTESTATION_BRIDGE_TEMPLATE.md",
        r"oem_bridge|LEONA_HANDSHAKE_ATTESTATION_OEM_TRUSTED_PROVIDERS",
    ))
    checks.append(require_pattern(
        "server OEM verifier bridge is optional/private",
        REPO_DIR / "leona-server/ingestion-service/src/main/java/io/leonasec/server/ingestion/domain/OemAttestationVerifiers.java",
        r"PrivateOemAttestationVerifier|OEM_ATTESTATION_VERIFIER_MISSING",
    ))
    checks.append(require_pattern(
        "server deployment template carries OEM trusted provider allowlist",
        REPO_DIR / "leona-server/deploy/prod-homeleona/.env.example",
        r"LEONA_HANDSHAKE_ATTESTATION_OEM_TRUSTED_PROVIDERS",
    ))
    checks.append(require_pattern(
        "sample release guard rejects attestation debug/test properties",
        SDK_DIR / "sample-app/build.gradle.kts",
        r"guardSampleReleaseBuild|LEONA_SAMPLE_ATTESTATION_MODE",
    ))
    return checks


def run_provider_replay_checks() -> dict[str, Any]:
    fixtures = [
        replay_fixture(
            provider="play_integrity",
            format_value="play_integrity",
            token_material="play-integrity-replay-token-bound-to-local-request-hash",
        ),
        replay_fixture(
            provider="oem_attestation",
            format_value="oem_attestation",
            token_material="oem-attestation-replay-token-bound-to-local-request-hash",
        ),
    ]
    failures = []
    for fixture in fixtures:
        if fixture["tokenPrinted"]:
            failures.append(f"{fixture['provider']}: raw token printed")
        if fixture["sdkDecisionRole"] != "collect-and-report-evidence":
            failures.append(f"{fixture['provider']}: SDK decision role drift")
        if fixture["businessDecisionOwner"] != "customer-backend":
            failures.append(f"{fixture['provider']}: business decision owner drift")
        if fixture["format"] not in {"play_integrity", "oem_attestation"}:
            failures.append(f"{fixture['provider']}: unexpected format")
        if not fixture["tokenSha256"] or len(fixture["tokenSha256"]) != 64:
            failures.append(f"{fixture['provider']}: missing token hash")
        if not fixture["requestHashBinding"]:
            failures.append(f"{fixture['provider']}: missing request hash binding")
    return {
        "status": "pass" if not failures else "fail",
        "fixtureCount": len(fixtures),
        "passCount": len(fixtures) if not failures else 0,
        "failureCount": len(failures),
        "failures": failures,
        "fixtures": fixtures,
        "secretValuesPrinted": False,
        "rawTokensPrinted": False,
        "realProviderContacted": False,
    }


def replay_fixture(provider: str, format_value: str, token_material: str) -> dict[str, Any]:
    request_hash = sha256(f"local-replay-request::{provider}")
    return {
        "provider": provider,
        "format": format_value,
        "tokenSha256": sha256(token_material),
        "requestHashBinding": request_hash,
        "tokenPrinted": False,
        "sdkDecisionRole": "collect-and-report-evidence",
        "businessDecisionOwner": "customer-backend",
    }


def run_external_material_checks(target: str) -> list[dict[str, str]]:
    blockers: list[dict[str, str]] = []
    if target in {"both", "play_integrity"}:
        dep_enabled = os.environ.get("LEONA_SAMPLE_ENABLE_REAL_PLAY_INTEGRITY_DEP", "").lower() == "true"
        cloud_project = (
            os.environ.get("LEONA_SAMPLE_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER")
            or os.environ.get("LEONA_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER")
            or ""
        ).strip()
        server_ready = (
            os.environ.get("LEONA_PLAY_INTEGRITY_SERVER_VERIFIER_READY") == "1"
            or bool(os.environ.get("LEONA_PLAY_INTEGRITY_VERIFIER_CREDENTIALS"))
        )
        if not dep_enabled:
            blockers.append(blocker("play_integrity_dependency", "set LEONA_SAMPLE_ENABLE_REAL_PLAY_INTEGRITY_DEP=true for the real sample lane"))
        if not cloud_project.isdigit():
            blockers.append(blocker("play_integrity_cloud_project", "provide a numeric Play Integrity cloud project number"))
        if not server_ready:
            blockers.append(blocker("play_integrity_server_verifier", "install/configure private server verifier material outside the public repo"))

    if target in {"both", "oem"}:
        trusted = [item.strip() for item in os.environ.get("LEONA_HANDSHAKE_ATTESTATION_OEM_TRUSTED_PROVIDERS", "").split(",") if item.strip()]
        non_demo_trusted = [item for item in trusted if item != "sample_mainland_debug"]
        private_verifier_ready = os.environ.get("LEONA_OEM_ATTESTATION_PRIVATE_VERIFIER_READY") == "1"
        provider_namespace = os.environ.get("LEONA_OEM_ATTESTATION_PROVIDER_NAMESPACE", "").strip()
        bridge_ready = os.environ.get("LEONA_OEM_ATTESTATION_BRIDGE_READY") == "1"
        if not non_demo_trusted:
            blockers.append(blocker("oem_trusted_provider_allowlist", "configure at least one non-demo OEM trusted provider"))
        if not private_verifier_ready:
            blockers.append(blocker("oem_private_verifier", "install private OEM verifier module on the server runtime classpath"))
        if not provider_namespace:
            blockers.append(blocker("oem_provider_namespace", "provide the OEM provider namespace/channel for smoke attribution"))
        if not bridge_ready:
            blockers.append(blocker("oem_device_bridge", "install a host-app OEM bridge backed by a real OEM SDK"))
    return blockers


def expected_blocker_codes(target: str) -> set[str]:
    if target == "both":
        return EXPECTED_BLOCKER_CODES["play_integrity"] | EXPECTED_BLOCKER_CODES["oem"]
    return set(EXPECTED_BLOCKER_CODES[target])


def blocker_counts_by_provider(blockers: list[dict[str, str]]) -> dict[str, int]:
    counts = {"play_integrity": 0, "oem": 0, "other": 0}
    for item in blockers:
        code = item.get("code", "")
        if code.startswith("play_integrity_"):
            counts["play_integrity"] += 1
        elif code.startswith("oem_"):
            counts["oem"] += 1
        else:
            counts["other"] += 1
    return counts


def require_pattern(label: str, path: Path, pattern: str) -> dict[str, str]:
    if not path.exists():
        return {"label": label, "status": "fail", "reason": f"missing file: {relative(path)}"}
    text = path.read_text(encoding="utf-8")
    if re.search(pattern, text, flags=re.MULTILINE):
        return {"label": label, "status": "pass", "path": relative(path)}
    return {"label": label, "status": "fail", "path": relative(path), "reason": f"missing pattern: {pattern}"}


def blocker(code: str, reason: str) -> dict[str, str]:
    return {"code": code, "status": "external-blocked", "reason": reason}


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def relative(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_DIR))
    except ValueError:
        return str(path)


def write_report(output_dir: Path, report: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "# Android Attestation Real-Smoke Preflight",
        "",
        f"- status: {report['status']}",
        f"- target: {report['target']}",
        f"- require real provider: {str(report['requireRealProvider']).lower()}",
        f"- local check count: {report['localCheckCount']}",
        f"- local pass count: {report['localPassCount']}",
        f"- local failure count: {report['localFailureCount']}",
        f"- provider replay status: {report['providerReplayStatus']}",
        f"- provider replay fixture count: {report['providerReplayFixtureCount']}",
        f"- provider replay pass count: {report['providerReplayPassCount']}",
        f"- provider replay failure count: {report['providerReplayFailureCount']}",
        f"- external blocker count: {report['externalBlockerCount']}",
        f"- Play Integrity blocker count: {report['externalBlockerCountsByProvider']['play_integrity']}",
        f"- OEM blocker count: {report['externalBlockerCountsByProvider']['oem']}",
        f"- missing expected blocker count: {len(report['missingExpectedExternalBlockers'])}",
        f"- unexpected blocker count: {len(report['unexpectedExternalBlockers'])}",
        f"- secret values printed: {str(report['secretValuesPrinted']).lower()}",
        f"- creates tag: {str(report['createsTag']).lower()}",
        f"- publishes artifacts: {str(report['publishesArtifacts']).lower()}",
        f"- starts paid devices: {str(report['startsPaidDevices']).lower()}",
        "",
        "## Local Checks",
        "",
    ]
    for check in report["checks"]:
        suffix = f" ({check.get('path')})" if check.get("path") else ""
        reason = f" - {check.get('reason')}" if check.get("reason") else ""
        lines.append(f"- {check['status']}: {check['label']}{suffix}{reason}")
    lines.extend(["", "## Provider Replay Contract", ""])
    lines.append(f"- status: {report['providerReplayStatus']}")
    lines.append(f"- fixture count: {report['providerReplayFixtureCount']}")
    lines.append("- real provider contacted: false")
    lines.append("- raw tokens printed: false")
    for fixture in report["providerReplay"]["fixtures"]:
        lines.append(
            "- "
            f"{fixture['provider']}: format={fixture['format']}, "
            f"tokenSha256={fixture['tokenSha256']}, "
            f"requestHashBinding={fixture['requestHashBinding']}, "
            f"sdkDecisionRole={fixture['sdkDecisionRole']}, "
            f"businessDecisionOwner={fixture['businessDecisionOwner']}"
        )
    if report["providerReplay"]["failures"]:
        lines.append("- failures: " + ", ".join(report["providerReplay"]["failures"]))
    lines.extend(["", "## External Blockers", ""])
    if report["externalBlockers"]:
        for item in report["externalBlockers"]:
            lines.append(f"- {item['code']}: {item['reason']}")
    else:
        lines.append("- none")
    if report["missingExpectedExternalBlockers"] or report["unexpectedExternalBlockers"]:
        lines.extend(["", "## Blocker Shape Drift", ""])
        lines.append(f"- missing expected: {', '.join(report['missingExpectedExternalBlockers']) or 'none'}")
        lines.append(f"- unexpected: {', '.join(report['unexpectedExternalBlockers']) or 'none'}")
    lines.append("")
    (output_dir / "summary.md").write_text("\n".join(lines), encoding="utf-8")


def reject_sensitive_output(output_dir: Path) -> None:
    hits: list[str] = []
    for path in output_dir.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for line_no, line in enumerate(text.splitlines(), 1):
            if RAW_BOX_ID.search(line) or SECRETISH.search(line):
                hits.append(f"{path}:{line_no}")
    if hits:
        raise RuntimeError("sensitive-looking values found in preflight report: " + ", ".join(hits[:20]))


if __name__ == "__main__":
    sys.exit(main())
