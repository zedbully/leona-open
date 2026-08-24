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
        "play_integrity_server_verifier_contract",
        "play_integrity_package_name",
        "play_integrity_certificate_allowlist",
        "play_integrity_application_default_credentials",
        "play_integrity_device_token_artifact",
    },
    "oem": {
        "oem_server_verifier_contract",
        "oem_trusted_provider_allowlist",
        "oem_provider_public_keys",
        "oem_package_name_allowlist",
        "oem_private_verifier",
        "oem_provider_namespace",
        "oem_device_bridge",
    },
    # These are deliberately unconditional.  A public local preflight cannot
    # authenticate an AppGallery account, mint an App ID, or establish that an
    # HMS response came from the same final signed APK on a physical Huawei
    # device.  Do not replace these with environment "ready" flags.
    "huawei": {
        "huawei_oauth_account_session",
        "huawei_appgallery_app_id",
        "huawei_final_candidate_signer",
        "huawei_hms_same_session_token_context",
        "huawei_physical_oem_exact_candidate",
    },
}

PACKAGE_NAME = re.compile(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+")
CERTIFICATE_DIGEST = re.compile(r"(?:[0-9A-Fa-f]{64}|[A-Za-z0-9_-]{43})")
ADC_TYPES = {"service_account", "external_account", "authorized_user"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        default="/tmp/leona-v0.4-attestation-real-smoke-preflight-active",
        help="Directory for summary.json and summary.md",
    )
    parser.add_argument(
        "--target",
        choices=("both", "play_integrity", "oem", "huawei"),
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

    private_server_root = attestation_server_root()
    checks = run_local_checks(private_server_root, args.target)
    provider_replay = run_provider_replay_checks()
    blockers = run_external_material_checks(args.target, private_server_root)
    failures = [check for check in checks if check["status"] == "fail"]
    if failures or provider_replay["failureCount"]:
        status = "failed"
    elif blockers and args.require_real_provider:
        status = "failed"
    elif blockers:
        status = "local-pass-with-external-blockers"
    else:
        status = "ready-for-real-smoke"

    blocker_codes = [item["code"] for item in blockers]
    expected_codes = expected_blocker_codes(args.target)
    # These codes are the complete allowlist of conditional blockers, not a
    # requirement that every blocker remain present after material is supplied.
    missing_expected_blockers: list[str] = []
    unexpected_blockers = sorted(set(blocker_codes).difference(expected_codes))
    if unexpected_blockers:
        status = "failed"
    blocker_counts = blocker_counts_by_provider(blockers)
    report: dict[str, Any] = {
        "status": status,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "target": args.target,
        "admissionScope": admission_scope(args.target),
        "commercialAdmissionClaimed": False,
        "exactCandidateHuaweiAdmissionSatisfied": False,
        "requireRealProvider": args.require_real_provider,
        "providerReplay": provider_replay,
        "providerReplayStatus": provider_replay["status"],
        "providerReplayFixtureCount": provider_replay["fixtureCount"],
        "providerReplayPassCount": provider_replay["passCount"],
        "providerReplayFailureCount": provider_replay["failureCount"],
        "realProviderContacted": False,
        "privateServerContractAvailable": server_contract_available(args.target, private_server_root),
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


def run_local_checks(private_server_root: Path, target: str) -> list[dict[str, str]]:
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
    if private_server_root.is_dir():
        checks.append(require_pattern(
            "server OEM verifier bridge is optional/private",
            private_server_root / "ingestion-service/src/main/java/io/leonasec/server/ingestion/domain/OemAttestationVerifiers.java",
            r"PrivateOemAttestationVerifier|OEM_ATTESTATION_VERIFIER_MISSING",
        ))
        checks.append(require_pattern(
            "private OEM verifier requires out-of-band ES256 provider keys",
            private_server_root / "private/api-backend/src/main/java/io/leonasec/server/privatebackend/attestation/PrivateOemAttestationJwsVerifier.java",
            r"ES256[\s\S]*OEM_ATTESTATION_KEY_NOT_CONFIGURED[\s\S]*forbiddenDynamicKeyHeaderPresent",
        ))
        checks.append(require_pattern(
            "private OEM verifier binds provider signature package challenge and install",
            private_server_root / "private/api-backend/src/main/java/io/leonasec/server/privatebackend/attestation/PrivateOemAttestationVerifier.java",
            r"jwsVerifier\.authenticate[\s\S]*attestation_challenge_mismatch[\s\S]*attestation_install_mismatch[\s\S]*attestation_package_untrusted",
        ))
        checks.append(require_pattern(
            "server Play Integrity verifier bridge is optional/private",
            private_server_root / "ingestion-service/src/main/java/io/leonasec/server/ingestion/domain/PlayIntegrityAttestationVerifiers.java",
            r"PrivatePlayIntegrityAttestationVerifier|PLAY_INTEGRITY_VERIFIER_MISSING",
        ))
        checks.append(require_pattern(
            "private Play Integrity verifier binds package certificate and request hash",
            private_server_root / "private/api-backend/src/main/java/io/leonasec/server/privatebackend/attestation/PrivatePlayIntegrityAttestationVerifier.java",
            r"LEONA_PLAY_INTEGRITY_PACKAGE_NAME[\s\S]*LEONA_PLAY_INTEGRITY_CERTIFICATE_SHA256_DIGESTS[\s\S]*PLAY_INTEGRITY_CHALLENGE_MISMATCH",
        ))
        checks.append(require_pattern(
            "private Play Integrity decoder uses official Google endpoint and OAuth scope",
            private_server_root / "private/api-backend/src/main/java/io/leonasec/server/privatebackend/attestation/GooglePlayIntegrityTokenDecoder.java",
            r"https://www\.googleapis\.com/auth/playintegrity[\s\S]*https://playintegrity\.googleapis\.com[\s\S]*decodeIntegrityToken",
        ))
        checks.append(require_pattern(
            "handshake rejects unverified attestation by default",
            private_server_root / "ingestion-service/src/main/java/io/leonasec/server/ingestion/domain/SessionService.java",
            # The production constructor intentionally hard-codes the
            # fail-closed default.  Test-only constructors may still exercise
            # telemetry-only fixtures, but deployment configuration must not
            # silently turn missing attestation into an accepted handshake.
            r"identityResolver,\s*true\s*\)",
        ))
        checks.append(require_pattern(
            "server deployment template carries fail-closed attestation inputs and safe defaults",
            private_server_root / "deploy/prod-homeleona/.env.example",
            r"LEONA_HANDSHAKE_ATTESTATION_ENFORCE=(?:true|false)[\s\S]*LEONA_HANDSHAKE_ATTESTATION_TRUST_JWS_PAYLOAD_CLAIMS=false[\s\S]*LEONA_PLAY_INTEGRITY_PACKAGE_NAME=[\s\S]*LEONA_PLAY_INTEGRITY_CERTIFICATE_SHA256_DIGESTS=[\s\S]*LEONA_HANDSHAKE_ATTESTATION_OEM_TRUSTED_PROVIDERS=[\s\S]*LEONA_HANDSHAKE_ATTESTATION_OEM_PROVIDER_PUBLIC_KEYS=[\s\S]*LEONA_HANDSHAKE_ATTESTATION_OEM_PACKAGE_NAMES=",
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


def run_external_material_checks(target: str, private_server_root: Path) -> list[dict[str, str]]:
    blockers: list[dict[str, str]] = []
    if target == "huawei":
        # The public gate can validate only local support wiring.  Huawei
        # commercial admission is an external, exact-candidate ceremony; a
        # caller-provided flag or a locally fabricated receipt is not proof.
        return [
            blocker("huawei_oauth_account_session", "complete Huawei OAuth/account verification in a visible operator session"),
            blocker("huawei_appgallery_app_id", "obtain the AppGallery project/App ID assigned for the customer release"),
            blocker("huawei_final_candidate_signer", "rebuild the exact candidate with the customer final signing identity"),
            blocker("huawei_hms_same_session_token_context", "collect the HMS token/context from that exact candidate in the same authenticated session"),
            blocker("huawei_physical_oem_exact_candidate", "run the same final candidate on a physical Huawei/OEM device and retain hash-only evidence"),
        ]
    if target in {"both", "play_integrity"}:
        if not play_server_contract_available(private_server_root):
            blockers.append(blocker("play_integrity_server_verifier_contract", "mount the private Play Integrity server contract outside the public checkout"))
        dep_enabled = os.environ.get("LEONA_SAMPLE_ENABLE_REAL_PLAY_INTEGRITY_DEP", "").lower() == "true"
        cloud_project = (
            os.environ.get("LEONA_SAMPLE_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER")
            or os.environ.get("LEONA_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER")
            or ""
        ).strip()
        package_name = os.environ.get("LEONA_PLAY_INTEGRITY_PACKAGE_NAME", "").strip()
        certificate_digests = [
            item.strip()
            for item in os.environ.get("LEONA_PLAY_INTEGRITY_CERTIFICATE_SHA256_DIGESTS", "").split(",")
            if item.strip()
        ]
        if not dep_enabled:
            blockers.append(blocker("play_integrity_dependency", "set LEONA_SAMPLE_ENABLE_REAL_PLAY_INTEGRITY_DEP=true for the real sample lane"))
        if not cloud_project.isdigit() or int(cloud_project) <= 0:
            blockers.append(blocker("play_integrity_cloud_project", "provide a numeric Play Integrity cloud project number"))
        if not PACKAGE_NAME.fullmatch(package_name):
            blockers.append(blocker("play_integrity_package_name", "provide the dynamically configured Play package name"))
        if not certificate_digests or any(not CERTIFICATE_DIGEST.fullmatch(item) for item in certificate_digests):
            blockers.append(blocker("play_integrity_certificate_allowlist", "provide a valid SHA-256 signing certificate digest allowlist"))
        if not application_default_credentials_ready():
            blockers.append(blocker("play_integrity_application_default_credentials", "mount a private Application Default Credentials JSON file outside the repository"))
        if not private_token_artifact_ready():
            blockers.append(blocker("play_integrity_device_token_artifact", "provide a mode-0600 private token artifact generated by the real device bridge outside the repository"))

    if target in {"both", "oem"}:
        if not oem_server_contract_available(private_server_root):
            blockers.append(blocker("oem_server_verifier_contract", "mount the private OEM server contract outside the public checkout"))
        trusted = [item.strip() for item in os.environ.get("LEONA_HANDSHAKE_ATTESTATION_OEM_TRUSTED_PROVIDERS", "").split(",") if item.strip()]
        non_demo_trusted = [item for item in trusted if item != "sample_mainland_debug"]
        provider_keys_ready = oem_public_key_config_ready(non_demo_trusted)
        package_names = [
            item.strip()
            for item in os.environ.get("LEONA_HANDSHAKE_ATTESTATION_OEM_PACKAGE_NAMES", "").split(",")
            if item.strip()
        ]
        private_verifier_ready = os.environ.get("LEONA_OEM_ATTESTATION_PRIVATE_VERIFIER_READY") == "1"
        provider_namespace = os.environ.get("LEONA_OEM_ATTESTATION_PROVIDER_NAMESPACE", "").strip()
        bridge_ready = os.environ.get("LEONA_OEM_ATTESTATION_BRIDGE_READY") == "1"
        if not non_demo_trusted:
            blockers.append(blocker("oem_trusted_provider_allowlist", "configure at least one non-demo OEM trusted provider"))
        if not provider_keys_ready:
            blockers.append(blocker("oem_provider_public_keys", "configure out-of-band P-256 provider public keys for every trusted provider/key id"))
        if not package_names or any(not PACKAGE_NAME.fullmatch(item) for item in package_names):
            blockers.append(blocker("oem_package_name_allowlist", "configure at least one valid Android package name for the OEM lane"))
        if not private_verifier_ready:
            blockers.append(blocker("oem_private_verifier", "install private OEM verifier module on the server runtime classpath"))
        if not provider_namespace or provider_namespace not in non_demo_trusted:
            blockers.append(blocker("oem_provider_namespace", "provide the OEM provider namespace/channel for smoke attribution"))
        if not bridge_ready:
            blockers.append(blocker("oem_device_bridge", "install a host-app OEM bridge backed by a real OEM SDK"))
    return blockers


def attestation_server_root() -> Path:
    configured = os.environ.get("LEONA_ATTESTATION_SERVER_ROOT", "").strip()
    return Path(configured).expanduser() if configured else REPO_DIR / "leona-server"


def play_server_contract_available(root: Path) -> bool:
    return all(path.is_file() for path in (
        root / "ingestion-service/src/main/java/io/leonasec/server/ingestion/domain/PlayIntegrityAttestationVerifiers.java",
        root / "private/api-backend/src/main/java/io/leonasec/server/privatebackend/attestation/PrivatePlayIntegrityAttestationVerifier.java",
        root / "private/api-backend/src/main/java/io/leonasec/server/privatebackend/attestation/GooglePlayIntegrityTokenDecoder.java",
        root / "ingestion-service/src/main/java/io/leonasec/server/ingestion/domain/SessionService.java",
        root / "deploy/prod-homeleona/.env.example",
    ))


def oem_server_contract_available(root: Path) -> bool:
    return all(path.is_file() for path in (
        root / "ingestion-service/src/main/java/io/leonasec/server/ingestion/domain/OemAttestationVerifiers.java",
        root / "private/api-backend/src/main/java/io/leonasec/server/privatebackend/attestation/PrivateOemAttestationVerifier.java",
        root / "private/api-backend/src/main/java/io/leonasec/server/privatebackend/attestation/PrivateOemAttestationJwsVerifier.java",
        root / "private/api-backend/src/main/java/io/leonasec/server/privatebackend/attestation/PrivateOemAttestationToken.java",
    ))


def oem_public_key_config_ready(trusted_providers: list[str]) -> bool:
    raw = os.environ.get("LEONA_HANDSHAKE_ATTESTATION_OEM_PROVIDER_PUBLIC_KEYS", "").strip()
    if not raw or not trusted_providers:
        return False
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return False
    if not isinstance(payload, dict):
        return False
    for provider in trusted_providers:
        keys = payload.get(provider)
        if not isinstance(keys, dict) or not keys:
            return False
        for kid, encoded in keys.items():
            if not isinstance(kid, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", kid):
                return False
            if not isinstance(encoded, str) or not re.fullmatch(r"[A-Za-z0-9_-]{80,512}", encoded):
                return False
    return True


def server_contract_available(target: str, root: Path) -> bool:
    if target == "play_integrity":
        return play_server_contract_available(root)
    if target in {"oem", "huawei"}:
        return oem_server_contract_available(root)
    return play_server_contract_available(root) and oem_server_contract_available(root)


def application_default_credentials_ready() -> bool:
    raw_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "").strip()
    if not raw_path:
        return False
    path = Path(raw_path).expanduser()
    if not private_regular_file(path):
        return False
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    return isinstance(payload, dict) and payload.get("type") in ADC_TYPES


def private_token_artifact_ready() -> bool:
    raw_path = os.environ.get("LEONA_PLAY_INTEGRITY_DEVICE_TOKEN_ARTIFACT", "").strip()
    if not raw_path:
        return False
    path = Path(raw_path).expanduser()
    if not private_regular_file(path):
        return False
    try:
        return 16 <= path.stat().st_size <= 1024 * 1024
    except OSError:
        return False


def private_regular_file(path: Path) -> bool:
    try:
        resolved = path.resolve(strict=True)
        if not resolved.is_file() or is_within(resolved, REPO_DIR.resolve()):
            return False
        return (resolved.stat().st_mode & 0o077) == 0
    except OSError:
        return False


def is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def expected_blocker_codes(target: str) -> set[str]:
    if target == "both":
        return EXPECTED_BLOCKER_CODES["play_integrity"] | EXPECTED_BLOCKER_CODES["oem"]
    return set(EXPECTED_BLOCKER_CODES[target])


def admission_scope(target: str) -> str:
    if target == "huawei":
        return "local_support_only_huawei_exact_candidate_external_admission_required"
    return "local_preflight_only_real_provider_admission_external"


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
        f"- admission scope: {report['admissionScope']}",
        f"- commercial admission claimed: {str(report['commercialAdmissionClaimed']).lower()}",
        f"- exact-candidate Huawei admission satisfied: {str(report['exactCandidateHuaweiAdmissionSatisfied']).lower()}",
        f"- require real provider: {str(report['requireRealProvider']).lower()}",
        f"- local check count: {report['localCheckCount']}",
        f"- local pass count: {report['localPassCount']}",
        f"- local failure count: {report['localFailureCount']}",
        f"- provider replay status: {report['providerReplayStatus']}",
        f"- provider replay fixture count: {report['providerReplayFixtureCount']}",
        f"- provider replay pass count: {report['providerReplayPassCount']}",
        f"- provider replay failure count: {report['providerReplayFailureCount']}",
        f"- real provider contacted: {str(report['realProviderContacted']).lower()}",
        f"- private server contract available: {str(report['privateServerContractAvailable']).lower()}",
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
