#!/usr/bin/env python3
"""Verify a domestic direct/private Maven distribution bundle.

The verifier is intentionally offline with respect to publication: it consumes
an already prepared Maven repository directory and never uploads artifacts.  It
binds one coordinate to five publication artifacts, SHA-256 sidecars, detached
OpenPGP signatures, Gradle/POM metadata, the AAR public API payload, and an
independent consumer summary.  It never turns the SDK into a decision engine;
the SDK remains evidence-only and the customer backend owns business actions.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET  # nosemgrep: python.lang.security.use-defused-xml-parse.use-defused-xml-parse -- POM bytes are size-limited and DTD/entity declarations are rejected before parsing.
import zipfile
from pathlib import Path
from typing import Any


SHA256 = re.compile(r"^[0-9a-f]{64}$")
COORD_PART = re.compile(r"^[A-Za-z0-9_.-]+$")
PLAY_MARKERS = (
    "playintegrity",
    "play-integrity",
    "com.google.android.play:integrity",
    "com/google/android/play/integrity",
)
GOOGLE_MAVEN_GROUP_PREFIX = "com.google"
GOOGLE_RUNTIME_PREFIX = "com/google/"
REQUIRED_CLASS = "io/leonasec/leona/Leona.class"
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
MAX_POM_BYTES = 2 * 1024 * 1024


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-dir", required=True)
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--consumer-summary", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--group-id", default="io.leonasec")
    parser.add_argument("--artifact-id", default="leona-sdk-android")
    parser.add_argument("--version", default="0.4.0")
    parser.add_argument("--expected-aar-sha256", default="")
    return parser.parse_args()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def regular_file(failures: list[str], path: Path, label: str) -> bool:
    if path.is_symlink():
        failures.append(f"{label} must not be a symlink")
        return False
    if not path.is_file():
        failures.append(f"{label} missing: {path}")
        return False
    return True


def read_json(failures: list[str], path: Path, label: str) -> dict[str, Any]:
    if not regular_file(failures, path, label):
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - report parser failure without secrets.
        failures.append(f"{label} invalid JSON: {exc}")
        return {}
    if not isinstance(value, dict):
        failures.append(f"{label} must be a JSON object")
        return {}
    return value


def validate_coordinate(failures: list[str], group: str, artifact: str, version: str) -> None:
    if not group or any(not valid_coordinate_part(part) for part in group.split(".")):
        failures.append("group-id shape invalid")
    if not valid_coordinate_part(artifact):
        failures.append("artifact-id shape invalid")
    if not valid_coordinate_part(version):
        failures.append("version shape invalid")


def valid_coordinate_part(value: str) -> bool:
    return value not in {"", ".", ".."} and COORD_PART.fullmatch(value) is not None


def required_artifact_names(artifact: str, version: str) -> list[str]:
    base = f"{artifact}-{version}"
    return [
        f"{base}.aar",
        f"{base}.pom",
        f"{base}.module",
        f"{base}-sources.jar",
        f"{base}-javadoc.jar",
    ]


def validate_checksums(
    failures: list[str], coordinate_dir: Path, names: list[str]
) -> tuple[bool, dict[str, dict[str, Any]]]:
    manifest: dict[str, dict[str, Any]] = {}
    before = len(failures)
    for name in names:
        artifact = coordinate_dir / name
        sidecar = coordinate_dir / f"{name}.sha256"
        if not regular_file(failures, artifact, f"artifact {name}"):
            continue
        if not regular_file(failures, sidecar, f"checksum {name}"):
            continue
        actual = sha256(artifact)
        expected_line = f"{actual}  {name}"
        try:
            sidecar_text = sidecar.read_text(encoding="ascii").strip()
        except Exception as exc:  # noqa: BLE001
            failures.append(f"checksum {name} unreadable: {exc}")
            continue
        if sidecar_text != expected_line:
            failures.append(f"checksum {name} must equal exact sha256 and basename")
        manifest[name] = {
            "sha256": actual,
            "bytes": artifact.stat().st_size,
            "signature": f"{name}.asc",
            "signatureSha256": sha256(coordinate_dir / f"{name}.asc")
            if (coordinate_dir / f"{name}.asc").is_file()
            else "",
            "checksum": f"{name}.sha256",
            "checksumSha256": sha256(sidecar),
        }
    return len(failures) == before, manifest


def primary_fingerprints(gpg_home: Path) -> list[str]:
    result = subprocess.run(
        ["gpg", "--batch", "--homedir", str(gpg_home), "--with-colons", "--fingerprint"],
        check=True,
        capture_output=True,
        text=True,
    )
    fingerprints: list[str] = []
    waiting_for_primary = False
    for line in result.stdout.splitlines():
        fields = line.split(":")
        if fields[0] == "pub":
            waiting_for_primary = True
        elif waiting_for_primary and fields[0] == "fpr":
            fingerprints.append(fields[9])
            waiting_for_primary = False
    return fingerprints


def validate_signatures(
    failures: list[str], coordinate_dir: Path, names: list[str], public_key: Path
) -> tuple[bool, str]:
    before = len(failures)
    fingerprint_hash = ""
    if not regular_file(failures, public_key, "trusted public key"):
        return False, fingerprint_hash
    public_text = public_key.read_text(encoding="utf-8", errors="ignore")
    if "PRIVATE KEY BLOCK" in public_text or "SECRET KEY BLOCK" in public_text:
        failures.append("trusted public key file contains private key material")
        return False, fingerprint_hash
    if "BEGIN PGP PUBLIC KEY BLOCK" not in public_text:
        failures.append("trusted public key is not an armored OpenPGP public key")
        return False, fingerprint_hash
    try:
        with tempfile.TemporaryDirectory(prefix="leona-domestic-dist-gpg-") as temp:
            home = Path(temp)
            # GnuPG requires an owner-only home; 0700 is intentionally more
            # restrictive than the scanner's generic 0644 recommendation.
            os.chmod(home, 0o700)  # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
            subprocess.run(
                ["gpg", "--batch", "--homedir", str(home), "--import", str(public_key)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            secret_listing = subprocess.run(
                ["gpg", "--batch", "--homedir", str(home), "--with-colons", "--list-secret-keys"],
                check=True,
                capture_output=True,
                text=True,
            )
            if any(line.startswith("sec:") for line in secret_listing.stdout.splitlines()):
                failures.append("trusted keyring unexpectedly contains a secret key")
            fingerprints = primary_fingerprints(home)
            if len(fingerprints) != 1:
                raise ValueError("trusted public key must contain exactly one primary key")
            fingerprint = fingerprints[0]
            fingerprint_hash = hashlib.sha256(fingerprint.encode("ascii")).hexdigest()
            for name in names:
                artifact = coordinate_dir / name
                signature = coordinate_dir / f"{name}.asc"
                if not regular_file(failures, signature, f"signature {name}"):
                    continue
                if not artifact.is_file() or artifact.is_symlink():
                    continue
                verify = subprocess.run(
                    ["gpg", "--batch", "--homedir", str(home), "--verify", str(signature), str(artifact)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                if verify.returncode != 0:
                    failures.append(f"signature verification failed: {name}")
    except FileNotFoundError:
        failures.append("gpg executable unavailable")
    except (subprocess.CalledProcessError, ValueError) as exc:
        failures.append(f"trusted public key verification failed: {exc}")
    return len(failures) == before, fingerprint_hash


def xml_text(root: ET.Element, name: str) -> str:
    node = root.find(f"{{*}}{name}")
    return (node.text or "").strip() if node is not None else ""


def contains_play_marker(value: str) -> bool:
    lower = value.lower().replace("_", "-")
    return any(marker in lower for marker in PLAY_MARKERS)


def is_google_dependency(group: str, artifact: str) -> bool:
    normalized_group = group.strip().lower()
    return (
        normalized_group == GOOGLE_MAVEN_GROUP_PREFIX
        or normalized_group.startswith(f"{GOOGLE_MAVEN_GROUP_PREFIX}.")
        or contains_play_marker(f"{group}:{artifact}")
    )


def is_google_runtime_entry(value: str) -> bool:
    lower = value.lower().lstrip("/")
    return lower.startswith(GOOGLE_RUNTIME_PREFIX)


def validate_pom(
    failures: list[str], path: Path, group: str, artifact: str, version: str
) -> bool:
    before = len(failures)
    if not regular_file(failures, path, "POM"):
        return False
    if path.stat().st_size > MAX_POM_BYTES:
        failures.append("POM exceeds maximum size")
        return False
    try:
        xml_bytes = path.read_bytes()
        # Keep the declaration scan encoding-stable. Maven POMs are expected
        # to be UTF-8; accepting UTF-16 here would allow ASCII declaration
        # markers to be interleaved with NUL bytes before this check.
        decoded_xml = xml_bytes.decode("utf-8-sig")
        # Maven publication metadata never needs a DTD or custom entity.
        # Reject both before the standard-library parser sees untrusted XML;
        # the byte limit above also bounds non-entity expansion work.
        upper_xml = decoded_xml.upper()
        if "<!DOCTYPE" in upper_xml or "<!ENTITY" in upper_xml:
            raise ValueError("DTD/entity declarations are forbidden")
        root = ET.fromstring(xml_bytes)
    except Exception as exc:  # noqa: BLE001
        failures.append(f"POM parse failed: {exc}")
        return False
    expected = {"groupId": group, "artifactId": artifact, "version": version, "packaging": "aar"}
    for key, value in expected.items():
        if xml_text(root, key) != value:
            failures.append(f"POM {key} mismatch")
    dependencies = root.findall(".//{*}dependency")
    if not dependencies:
        failures.append("POM dependencies missing")
    for dependency in dependencies:
        dependency_group = xml_text(dependency, "groupId")
        dependency_artifact = xml_text(dependency, "artifactId")
        if is_google_dependency(dependency_group, dependency_artifact):
            failures.append("POM contains Google runtime dependency")
    return len(failures) == before


def validate_module(
    failures: list[str], path: Path, group: str, artifact: str, version: str, coordinate_dir: Path
) -> bool:
    before = len(failures)
    data = read_json(failures, path, "Gradle module metadata")
    component = data.get("component") if isinstance(data.get("component"), dict) else {}
    if component != {"group": group, "module": artifact, "version": version, "attributes": {"org.gradle.status": "release"}}:
        failures.append("Gradle module component mismatch")
    variants = data.get("variants")
    if not isinstance(variants, list) or not variants:
        failures.append("Gradle module variants missing")
        return False
    for variant in variants:
        if not isinstance(variant, dict):
            failures.append("Gradle module variant must be an object")
            continue
        for dependency in variant.get("dependencies") or []:
            if not isinstance(dependency, dict):
                failures.append("Gradle module dependency entry invalid")
                continue
            dependency_group = str(dependency.get("group") or "")
            dependency_module = str(dependency.get("module") or "")
            if is_google_dependency(dependency_group, dependency_module):
                failures.append("Gradle module contains Google runtime dependency")
        for file_item in variant.get("files") or []:
            if not isinstance(file_item, dict):
                failures.append("Gradle module file entry invalid")
                continue
            name = file_item.get("name")
            if name not in set(required_artifact_names(artifact, version)):
                failures.append(f"Gradle module references unexpected file: {name}")
                continue
            if file_item.get("url") != name:
                failures.append(f"Gradle module URL must equal artifact basename: {name}")
            target = coordinate_dir / str(name)
            if not target.is_file() or target.is_symlink():
                failures.append(f"Gradle module references missing file: {name}")
                continue
            if file_item.get("size") != target.stat().st_size:
                failures.append(f"Gradle module size mismatch: {name}")
            if file_item.get("sha256") != sha256(target):
                failures.append(f"Gradle module sha256 mismatch: {name}")
    return len(failures) == before


def validate_aar(failures: list[str], path: Path) -> tuple[bool, bool]:
    before = len(failures)
    required_class_present = False
    try:
        with zipfile.ZipFile(path) as aar:
            infos = aar.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                failures.append("AAR contains duplicate entries")
            if any(not safe_archive_name(name) for name in names):
                failures.append("AAR contains unsafe entry path")
            if sum(info.file_size for info in infos) > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                failures.append("AAR uncompressed payload exceeds verifier limit")
            if "classes.jar" not in names:
                failures.append("AAR classes.jar missing")
                return False, False
            if any(is_google_runtime_entry(name) for name in names):
                failures.append("AAR contains Google runtime entry")
            for jar_name in (name for name in names if name.endswith(".jar")):
                with zipfile.ZipFile(io.BytesIO(aar.read(jar_name))) as classes:
                    class_infos = classes.infolist()
                    class_names = [info.filename for info in class_infos]
                    if len(class_names) != len(set(class_names)):
                        failures.append(f"AAR nested jar contains duplicate entries: {jar_name}")
                    if any(not safe_archive_name(name) for name in class_names):
                        failures.append(f"AAR nested jar contains unsafe entry path: {jar_name}")
                    if sum(info.file_size for info in class_infos) > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                        failures.append(f"AAR nested jar exceeds verifier limit: {jar_name}")
                    if jar_name == "classes.jar":
                        required_class_present = REQUIRED_CLASS in class_names
                        if not required_class_present:
                            failures.append(f"AAR required public class missing: {REQUIRED_CLASS}")
                    if any(is_google_runtime_entry(name) for name in class_names):
                        failures.append(f"AAR classes contain Google runtime package: {jar_name}")
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        failures.append(f"AAR inspection failed: {exc}")
    return len(failures) == before, required_class_present


def safe_archive_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    return (
        bool(normalized)
        and not normalized.startswith("/")
        and not re.match(r"^[A-Za-z]:/", normalized)
        and all(part not in {"", ".", ".."} for part in normalized.rstrip("/").split("/"))
    )


def validate_consumer(
    failures: list[str], path: Path, coordinate: str, aar_sha: str
) -> bool:
    before = len(failures)
    data = read_json(failures, path, "consumer summary")
    expected = {
        "schemaVersion": 1,
        "status": "pass",
        "coordinate": coordinate,
        "repositoryArtifactAarSha256": aar_sha,
        "noGoogleRuntimeDependency": True,
        "sdkDecisionRole": "collect-and-report-evidence",
        "businessDecisionOwner": "customer-backend",
        "commercialAdmissionClaimed": False,
        "secretValuesPrinted": False,
    }
    for key, value in expected.items():
        if data.get(key) != value:
            failures.append(f"consumer summary {key} mismatch")
    if data.get("resolvedArtifactExtension") != "aar":
        failures.append("consumer summary resolvedArtifactExtension must be aar")
    transitives = data.get("requiredTransitives")
    if transitives != ["core-ktx", "kotlinx-coroutines-android", "okhttp"]:
        failures.append("consumer summary requiredTransitives mismatch")
    return len(failures) == before


def write_outputs(output_dir: Path, report: dict[str, Any], manifest: dict[str, Any]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "distribution-manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output_dir / "summary.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [
        "# Leona v0.4 Domestic Private Distribution Verification",
        "",
        f"- status: `{report['status']}`",
        f"- evidence class: `{report['evidenceClass']}`",
        f"- affects status: `{str(report['affectsStatus']).lower()}`",
        f"- market profile: `{report['marketProfile']}`",
        f"- distribution channel: `{report['distributionChannel']}`",
        f"- coordinate: `{report['coordinate']}`",
        f"- artifact/signature/checksum count: `{report['artifactCount']}/{report['signatureCount']}/{report['checksumCount']}`",
        f"- checksums verified: `{str(report['checksumsVerified']).lower()}`",
        f"- signatures verified: `{str(report['signaturesVerified']).lower()}`",
        f"- metadata verified: `{str(report['metadataVerified']).lower()}`",
        f"- consumer verified: `{str(report['consumerVerified']).lower()}`",
        f"- no Google runtime dependency: `{str(report['noGoogleRuntimeDependency']).lower()}`",
        f"- AAR SHA-256: `{report['aarSha256']}`",
        f"- signing fingerprint SHA-256: `{report['signingFingerprintSha256']}`",
        "- SDK role: `collect-and-report-evidence`",
        "- business decision owner: `customer-backend`",
        "- commercial admission claimed: `false`",
        "- secret values printed: `false`",
        "",
        "## Failures",
    ]
    lines.extend(f"- {failure}" for failure in report["failures"])
    if not report["failures"]:
        lines.append("- none")
    (output_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    repository = Path(args.repository_dir).resolve()
    public_key = Path(args.public_key)
    consumer_summary = Path(args.consumer_summary)
    output_dir = Path(args.output_dir)
    failures: list[str] = []
    validate_coordinate(failures, args.group_id, args.artifact_id, args.version)
    coordinate = f"{args.group_id}:{args.artifact_id}:{args.version}"
    coordinate_dir = repository.joinpath(*args.group_id.split("."), args.artifact_id, args.version)
    if coordinate_dir.is_symlink() or not coordinate_dir.is_dir():
        failures.append(f"coordinate directory missing or symlinked: {coordinate_dir}")
    names = required_artifact_names(args.artifact_id, args.version)
    expected_entries = {entry for name in names for entry in (name, f"{name}.asc", f"{name}.sha256")}
    actual_entries = {child.name for child in coordinate_dir.iterdir()} if coordinate_dir.is_dir() else set()
    if actual_entries != expected_entries:
        failures.append("coordinate directory must contain the exact artifact/signature/checksum set")
    for child in coordinate_dir.iterdir() if coordinate_dir.is_dir() else []:
        if child.is_symlink():
            failures.append(f"coordinate entry must not be a symlink: {child.name}")
    checksums_verified, artifact_manifest = validate_checksums(failures, coordinate_dir, names)
    signatures_verified, fingerprint_sha = validate_signatures(failures, coordinate_dir, names, public_key)
    aar_path = coordinate_dir / f"{args.artifact_id}-{args.version}.aar"
    pom_path = coordinate_dir / f"{args.artifact_id}-{args.version}.pom"
    module_path = coordinate_dir / f"{args.artifact_id}-{args.version}.module"
    aar_sha = sha256(aar_path) if aar_path.is_file() and not aar_path.is_symlink() else ""
    if args.expected_aar_sha256:
        if not SHA256.fullmatch(args.expected_aar_sha256):
            failures.append("expected AAR SHA-256 shape invalid")
        elif args.expected_aar_sha256 != aar_sha:
            failures.append("expected AAR SHA-256 mismatch")
    pom_ok = validate_pom(failures, pom_path, args.group_id, args.artifact_id, args.version) if pom_path.is_file() else False
    module_ok = validate_module(failures, module_path, args.group_id, args.artifact_id, args.version, coordinate_dir) if module_path.is_file() else False
    aar_ok, required_class_present = validate_aar(failures, aar_path) if aar_path.is_file() else (False, False)
    consumer_ok = validate_consumer(failures, consumer_summary, coordinate, aar_sha)
    metadata_verified = pom_ok and module_ok and aar_ok and required_class_present
    no_google = metadata_verified
    status = "pass" if not failures else "failed"
    manifest = {
        "schemaVersion": 1,
        "coordinate": coordinate,
        "artifacts": artifact_manifest,
        "artifactCount": len(artifact_manifest),
        "repositoryPathSha256": hashlib.sha256(str(repository).encode("utf-8")).hexdigest(),
        "secretValuesPrinted": False,
    }
    report = {
        "schemaVersion": 1,
        "status": status,
        "evidenceClass": "support",
        "affectsStatus": False,
        "marketProfile": "domestic",
        "distributionChannel": "direct-private-maven",
        "coordinate": coordinate,
        "artifactCount": len(artifact_manifest),
        "signatureCount": sum((coordinate_dir / f"{name}.asc").is_file() for name in names),
        "checksumCount": sum((coordinate_dir / f"{name}.sha256").is_file() for name in names),
        "checksumsVerified": checksums_verified,
        "signaturesVerified": signatures_verified,
        "metadataVerified": metadata_verified,
        "consumerVerified": consumer_ok,
        "noGoogleRuntimeDependency": no_google,
        "requiredPublicClassPresent": required_class_present,
        "aarSha256": aar_sha,
        "signingFingerprintSha256": fingerprint_sha,
        "publicKeySha256": sha256(public_key) if public_key.is_file() else "",
        "consumerSummarySha256": sha256(consumer_summary) if consumer_summary.is_file() else "",
        "sdkDecisionRole": "collect-and-report-evidence",
        "businessDecisionOwner": "customer-backend",
        "commercialAdmissionClaimed": False,
        "secretValuesPrinted": False,
        "rawIdentifiersPrinted": False,
        "privateKeyMaterialIncluded": False,
        "failures": failures,
    }
    write_outputs(output_dir, report, manifest)
    print(f"[domestic-private-distribution] summary: {output_dir / 'summary.md'}")
    return 0 if status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
