#!/usr/bin/env python3
"""Run the project-owned JNI smoke on one AVD per Android API (23..36).

This runner deliberately does not call the public reporting API.  It installs
the exact sample/test APKs, invokes the SDK androidTest smoke, records only
bounded hashes and status, and tears each temporary emulator down.  Leo
provider/runtime and network acceptance are outside this evidence lane.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


API_LEVELS = tuple(range(23, 37))
ABI_ALLOWLIST = ("arm64-v8a", "armeabi-v7a", "x86_64")
ABI_PRIORITY = ("arm64-v8a", "x86_64", "armeabi-v7a")
TEST_PACKAGE = "io.leonasec.leona.test"
SAMPLE_PACKAGE = "io.leonasec.leona.sample"
INSTRUMENTATION = f"{TEST_PACKAGE}/androidx.test.runner.AndroidJUnitRunner"
TEST_CLASS = "io.leonasec.leona.internal.runtime.NativeRuntimeSmokeTest#packagedNativeRuntimeLoadsInitializesAndCollects"
MARKER_RE = re.compile(
    r"LEONA_NATIVE_SMOKE_RESULT api=(?P<api>\d+) abi=(?P<abi>[A-Za-z0-9_-]+) "
    r"pageSizeBytes=(?P<page>\d+) payloadBytes=(?P<size>\d+) payloadSha256=(?P<digest>[0-9a-f]{64})"
)
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
OUTPUT_MARKER = ".leona-native-runtime-matrix-v1"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def write_private(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)


def prepare_output_directory(output: Path) -> None:
    """Require a new or marker-owned directory and remove stale cell files safely."""
    if output.exists():
        if output.is_symlink() or not output.is_dir():
            raise SystemExit("unsafe-output-directory")
        marker = output / OUTPUT_MARKER
        children = list(output.iterdir())
        if children and (not marker.is_file() or marker.is_symlink()):
            raise SystemExit("output-directory-not-empty-or-marker-missing")
        for child in children:
            if child == marker:
                continue
            if child.is_symlink() or child.is_file():
                child.unlink()
            elif child.is_dir():
                shutil.rmtree(child)
        output.chmod(0o700)
    else:
        output.mkdir(parents=True, exist_ok=False)
        output.chmod(0o700)
    marker = output / OUTPUT_MARKER
    marker.write_text("leona-project-native-runtime-matrix-v1\n", encoding="ascii")
    marker.chmod(0o600)


def run_command(command: list[str], *, timeout: int, stdout: Path | None = None) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )
    if stdout is not None:
        write_private(stdout, (completed.stdout or "") + (completed.stderr or ""))
    return completed


def adb_command(adb: str, serial: str, args: list[str], *, timeout: int, output: Path | None = None) -> subprocess.CompletedProcess[str]:
    return run_command([adb, "-s", serial, *args], timeout=timeout, stdout=output)


def discover_avds(emulator: str) -> list[str]:
    result = run_command([emulator, "-list-avds"], timeout=20)
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def choose_avd(avds: list[str], api: int) -> str | None:
    exact = f"leona-aosp-api{api}"
    if exact in avds:
        return exact
    candidates = [name for name in avds if re.search(rf"(?:api|android)[-_]?{api}(?:$|[-_])", name, re.I)]
    return sorted(candidates)[0] if candidates else None


def choose_avd_with_abi(avds: list[str], api: int) -> tuple[str, str] | None:
    """Select an API-matching AVD whose configured ABI is actually supported."""
    exact = f"leona-aosp-api{api}"
    candidates = [
        name for name in avds if name == exact or re.search(rf"(?:api|android)[-_]?{api}(?:$|[-_])", name, re.I)
    ]
    ranked: list[tuple[int, str, str]] = []
    for name in sorted(set(candidates)):
        abi = config_abi(name)
        if abi in ABI_ALLOWLIST:
            ranked.append((ABI_PRIORITY.index(abi), name, abi))
    if not ranked:
        return None
    _, name, abi = sorted(ranked)[0]
    return name, abi


def config_abi(avd: str) -> str:
    config = Path.home() / ".android" / "avd" / f"{avd}.avd" / "config.ini"
    if not config.is_file():
        return ""
    for line in config.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip().startswith("abi.type"):
            return line.split("=", 1)[1].strip()
    return ""


def port_available(port: int) -> bool:
    """Probe the host TCP port; adb's device list is not a port reservation."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def free_port(adb: str, base: int) -> int:
    del adb  # retained in the signature for callers from older runner versions
    for port in range(base, base + 80, 2):
        if port_available(port) and port_available(port + 1):
            return port
    raise RuntimeError("no-free-emulator-port")


def running_emulator_serial(avd: str) -> str | None:
    """Return a serial for an already running matching AVD, if any."""
    result = subprocess.run(
        ["ps", "axo", "command="], check=False, capture_output=True, text=True, timeout=10
    )
    pattern = re.compile(rf"-avd\s+{re.escape(avd)}(?:\s|$)")
    for command in result.stdout.splitlines():
        if not pattern.search(command):
            continue
        match = re.search(r"-port\s+(\d+)", command)
        if match:
            return f"emulator-{match.group(1)}"
    return None


def avd_is_busy(avd: str) -> bool:
    """Busy AVDs are never mutated by this runner."""
    return running_emulator_serial(avd) is not None


def wait_for_boot(adb: str, serial: str, timeout: int) -> tuple[bool, str, str, str]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = run_command([adb, "-s", serial, "get-state"], timeout=10)
        if state.returncode == 0:
            sdk = adb_command(adb, serial, ["shell", "getprop", "ro.build.version.sdk"], timeout=10)
            boot = adb_command(adb, serial, ["shell", "getprop", "sys.boot_completed"], timeout=10)
            abi = adb_command(adb, serial, ["shell", "getprop", "ro.product.cpu.abilist"], timeout=10)
            sdk_value = sdk.stdout.strip()
            abi_value = abi.stdout.strip()
            if boot.stdout.strip() == "1":
                return True, sdk_value, abi_value, ""
        time.sleep(1)
    return False, "", "", "boot-timeout"


def parse_marker(text: str) -> dict[str, Any] | None:
    match = MARKER_RE.search(text)
    if match is None:
        return None
    return {
        "apiLevel": int(match.group("api")),
        "abi": match.group("abi"),
        "pageSizeBytes": int(match.group("page")),
        "payloadBytes": int(match.group("size")),
        "payloadSha256": match.group("digest"),
    }


def sanitize_runtime_text(text: str, *, limit: int = 65_536) -> str:
    """Reconstruct bounded marker/category records; never persist raw logcat lines."""
    lines: list[str] = []
    for line in text.splitlines():
        marker = parse_marker(line)
        if marker is not None:
            lines.append(
                "LEONA_NATIVE_SMOKE_RESULT "
                f"api={marker['apiLevel']} abi={marker['abi']} pageSizeBytes={marker['pageSizeBytes']} "
                f"payloadBytes={marker['payloadBytes']} payloadSha256={marker['payloadSha256']}"
            )
            continue
        for token, category in (
            ("UnsatisfiedLinkError", "UNSATISFIED_LINK_ERROR"),
            ("FATAL EXCEPTION", "FATAL_EXCEPTION"),
            ("SIGSEGV", "SIGSEGV"),
            ("tombstone", "TOMBSTONE"),
        ):
            if token in line:
                lines.append(f"NATIVE_RUNTIME_FAILURE {category}")
                break
        else:
            status = re.search(r"INSTRUMENTATION_STATUS_CODE\s*:?\s*(-?\d+)", line)
            if status:
                lines.append(f"INSTRUMENTATION_STATUS_CODE {status.group(1)}")
    return "\n".join(lines)[:limit]


def parse_api_selection(raw: str) -> tuple[int, ...]:
    values = tuple(int(value.strip()) for value in raw.split(",") if value.strip())
    if len(values) != len(set(values)):
        raise ValueError("duplicate-api-selection")
    if any(api not in API_LEVELS for api in values):
        raise ValueError("api-selection-out-of-range")
    return values


def derive_source_identity(source_root: Path) -> tuple[str, str, str]:
    """Derive git identity from the checked-out source, never caller-provided text."""
    try:
        commit = subprocess.run(
            ["git", "-C", str(source_root), "rev-parse", "HEAD"],
            check=False, capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        tree = subprocess.run(
            ["git", "-C", str(source_root), "rev-parse", "HEAD^{tree}"],
            check=False, capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        cleanliness = subprocess.run(
            ["git", "-C", str(source_root), "status", "--porcelain", "--untracked-files=all"],
            check=False, capture_output=True, text=True, timeout=10,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return "", "", "UNVERIFIED"
    if HEX40_RE.fullmatch(commit) and HEX40_RE.fullmatch(tree) and not cleanliness.strip():
        return commit, tree, "DERIVED_FROM_CLEAN_WORKTREE"
    if HEX40_RE.fullmatch(commit) and HEX40_RE.fullmatch(tree):
        return commit, tree, "DIRTY_WORKTREE"
    return "", "", "UNVERIFIED"


def locate_aapt(explicit: str) -> str:
    if explicit:
        return explicit
    for name in ("aapt2", "aapt"):
        found = shutil.which(name)
        if found:
            return found
    sdk = os.environ.get("ANDROID_HOME", "") or os.environ.get("ANDROID_SDK_ROOT", "")
    if sdk:
        candidates = sorted(Path(sdk).glob("build-tools/*/aapt2"), reverse=True)
        if candidates:
            return str(candidates[0])
        candidates = sorted(Path(sdk).glob("build-tools/*/aapt"), reverse=True)
        if candidates:
            return str(candidates[0])
    return ""


def inspect_apk_identity(aapt: str, apk: Path) -> dict[str, str]:
    if not aapt:
        return {"package": "", "instrumentationName": "", "instrumentationTarget": ""}
    result = run_command([aapt, "dump", "badging", str(apk)], timeout=30)
    package = re.search(r"^package: name='([^']+)'", result.stdout, re.MULTILINE)
    instrumentation = re.search(
        r"^instrumentation: name='([^']+)' targetPackage='([^']+)'", result.stdout, re.MULTILINE
    )
    instrumentation_name = instrumentation.group(1) if instrumentation else ""
    instrumentation_target = instrumentation.group(2) if instrumentation else ""
    if not instrumentation:
        tree = run_command(
            [aapt, "dump", "xmltree", "--file", "AndroidManifest.xml", str(apk)], timeout=30
        )
        block_match = re.search(r"(?ms)^\s*E: instrumentation.*?(?=^\s*E: |\Z)", tree.stdout)
        block = block_match.group(0) if block_match else ""
        name_match = re.search(r"android:name\([^)]*\)=\"([^\"]+)\"", block)
        target_match = re.search(r"android:targetPackage\([^)]*\)=\"([^\"]+)\"", block)
        instrumentation_name = name_match.group(1) if name_match else ""
        instrumentation_target = target_match.group(1) if target_match else ""
    return {
        "package": package.group(1) if package else "",
        "instrumentationName": instrumentation_name,
        "instrumentationTarget": instrumentation_target,
    }


def validate_package_contract(sample: dict[str, str], test: dict[str, str]) -> tuple[bool, str]:
    if sample.get("package") != SAMPLE_PACKAGE:
        return False, "sample-package-mismatch"
    if test.get("package") != TEST_PACKAGE:
        return False, "test-package-mismatch"
    if test.get("instrumentationTarget") not in {SAMPLE_PACKAGE, TEST_PACKAGE}:
        return False, "instrumentation-target-mismatch"
    if not test.get("instrumentationName"):
        return False, "instrumentation-metadata-missing"
    return True, "package-contract-valid"


def runtime_page_size(adb: str, serial: str) -> int | None:
    for command in (("shell", "getconf", "PAGESIZE"), ("shell", "getprop", "ro.boot.page_size")):
        result = adb_command(adb, serial, list(command), timeout=10)
        match = re.search(r"(?m)^\s*(\d+)\s*$", result.stdout)
        if match:
            value = int(match.group(1))
            if 1024 <= value <= 1_048_576 and value & (value - 1) == 0:
                return value
    return None


def preclean_package(adb: str, serial: str, package: str) -> dict[str, Any]:
    """Uninstall only when present; absent packages are a successful clean state."""
    probe = adb_command(adb, serial, ["shell", "pm", "path", package], timeout=30)
    result: dict[str, Any] = {"probeRc": probe.returncode, "presentBefore": False, "uninstallRc": 0}
    if probe.returncode != 0:
        probe_text = ((probe.stdout or "") + (probe.stderr or "")).lower()
        absent_markers = ("unable to find package", "not found", "unknown package", "does not exist", "no package")
        if not any(marker in probe_text for marker in absent_markers) and "package:" not in probe_text:
            result["uninstallRc"] = probe.returncode
        return result
    result["presentBefore"] = "package:" in (probe.stdout or "")
    if result["presentBefore"]:
        removed = adb_command(adb, serial, ["shell", "pm", "uninstall", package], timeout=30)
        result["uninstallRc"] = removed.returncode
    return result


def validate_smoke_marker(marker: dict[str, Any] | None, *, api: int, abi: str, apk_sha256: str, text: str) -> tuple[bool, str]:
    """Pure admission guard used by the runner and contract tests."""
    if not HEX64_RE.fullmatch(apk_sha256):
        return False, "candidate-apk-sha256-invalid"
    if marker is None:
        if any(token in text for token in ("UnsatisfiedLinkError", "FATAL EXCEPTION", "SIGSEGV", "tombstone")):
            return False, "native-load-or-crash-marker"
        return False, "native-smoke-marker-missing"
    if marker["apiLevel"] != api:
        return False, "api-mismatch"
    if marker["abi"] != abi:
        return False, "abi-mismatch"
    page_size = marker.get("pageSizeBytes")
    if not isinstance(page_size, int) or page_size < 1_024 or page_size > 1_048_576 or page_size & (page_size - 1):
        return False, "page-size-invalid"
    if marker["payloadBytes"] < 0 or marker["payloadBytes"] > 131_072:
        return False, "payload-bound-invalid"
    if not HEX64_RE.fullmatch(marker["payloadSha256"]):
        return False, "payload-sha256-invalid"
    return True, "native-load-init-collect"


def validate_matrix_candidate(rows: list[dict[str, Any]]) -> tuple[bool, str]:
    """Reject mixed APK candidates and unredacted runtime identity material."""
    hashes = {
        str(row.get("artifactHashes", {}).get("sampleApkSha256") or "")
        for row in rows
        if row.get("status") == "PASS"
    }
    if any(not HEX64_RE.fullmatch(value) for value in hashes):
        return False, "candidate-apk-sha256-invalid"
    if len(hashes) > 1:
        return False, "mixed-candidate"
    for row in rows:
        for value in (
            row.get("serial"),
            row.get("boxId"),
            row.get("token"),
            row.get("avd"),
            row.get("buildFingerprint"),
            row.get("rawLogcat"),
        ):
            if value:
                return False, "raw-identifier-present"
    return True, "candidate-consistent-redacted"


def finalize_matrix_status(rows: list[dict[str, Any]]) -> tuple[str, dict[str, Any]]:
    """Apply candidate/redaction validation before a summary can claim PASS."""
    candidate_ok, candidate_reason = validate_matrix_candidate(rows)
    if not rows:
        status = "NOT_RUN"
    elif not candidate_ok:
        status = "FAIL"
    elif all(row.get("status") == "PASS" for row in rows):
        status = "PASS"
    else:
        status = "PARTIAL"
    return status, {"ok": candidate_ok, "reason": candidate_reason}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", required=True, type=Path, help="exact sample debug APK")
    parser.add_argument("--test-apk", required=True, type=Path, help="exact SDK androidTest APK")
    parser.add_argument("--aar", required=True, type=Path, help="exact SDK AAR used for candidate identity")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--emulator", default="emulator")
    parser.add_argument("--apis", default=",".join(map(str, API_LEVELS)))
    parser.add_argument("--source-root", type=Path, default=None, help="checked-out source root used for git identity")
    parser.add_argument("--aapt", default="", help="aapt/aapt2 used to verify package metadata")
    parser.add_argument("--source-commit", default="")
    parser.add_argument("--source-tree", default="")
    parser.add_argument("--boot-timeout", type=int, default=180)
    parser.add_argument("--keep-emulators", action="store_true", help="do not stop temporary emulators (debug only)")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    requested_output = args.output_dir.expanduser()
    if requested_output.is_symlink():
        raise SystemExit("unsafe-output-directory")
    output = requested_output.resolve()
    prepare_output_directory(output)
    for artifact in (args.apk, args.test_apk, args.aar):
        if not artifact.is_file():
            raise SystemExit(f"artifact missing: {artifact}")
    try:
        apis = parse_api_selection(args.apis)
    except ValueError as error:
        raise SystemExit(f"--apis invalid: {error}") from error
    adb = shutil.which(args.adb) or args.adb
    emulator = shutil.which(args.emulator) or args.emulator
    aapt = locate_aapt(args.aapt)
    source_root = (args.source_root or Path(__file__).resolve().parents[2]).expanduser().resolve()
    source_commit, source_tree, source_identity = derive_source_identity(source_root)
    if source_identity != "DERIVED_FROM_CLEAN_WORKTREE":
        raise SystemExit("source-identity-unverified")
    if args.source_commit and args.source_commit != source_commit:
        raise SystemExit("caller-source-commit-mismatch")
    if args.source_tree and args.source_tree != source_tree:
        raise SystemExit("caller-source-tree-mismatch")
    sample_identity = inspect_apk_identity(aapt, args.apk)
    test_identity = inspect_apk_identity(aapt, args.test_apk)
    package_ok, package_reason = validate_package_contract(sample_identity, test_identity)
    if not package_ok:
        raise SystemExit(package_reason)
    avds = discover_avds(emulator)
    artifact_hashes = {
        "sampleApkSha256": sha256_file(args.apk),
        "androidTestApkSha256": sha256_file(args.test_apk),
        "aarSha256": sha256_file(args.aar),
    }
    summary: dict[str, Any] = {
        "schema": "leona-project-native-runtime-matrix-v1",
        "status": "PASS" if apis else "NOT_RUN",
        "sourceCommit": source_commit,
        "sourceTree": source_tree,
        "sourceIdentity": source_identity,
        "packageContract": {
            "samplePackage": sample_identity["package"],
            "testPackage": test_identity["package"],
            "instrumentationName": test_identity["instrumentationName"],
            "instrumentationTarget": test_identity["instrumentationTarget"],
        },
        "artifactHashes": artifact_hashes,
        "providerStatus": "LEO_PROVIDER_RUNTIME_NOT_RUN",
        "evidenceClass": "PROJECT_NATIVE_RUNTIME",
        "rawIdentifiersPrinted": False,
        "secretValuesPrinted": False,
        "cells": [],
        "abiSummary": {},
    }
    rows: list[dict[str, Any]] = []
    for index, api in enumerate(apis):
        selected = choose_avd_with_abi(avds, api)
        avd, selected_abi = selected if selected else (None, "")
        row: dict[str, Any] = {
            "apiLevel": api,
            "avdNameSha256": sha256_text(avd) if avd else "",
            "abi": selected_abi,
            "targetSdk": 36,
            "artifactHashes": artifact_hashes,
            "status": "NOT_RUN",
            "reason": "avd-missing" if not avd else "not-started",
            "installRc": None,
            "testInstallRc": None,
            "instrumentationRc": None,
            "cleanup": {},
            "redacted": True,
        }
        if not avd:
            rows.append(row)
            continue
        configured_abi = config_abi(avd)
        if configured_abi not in ABI_ALLOWLIST:
            row["status"] = "NOT_RUN"
            row["reason"] = "unsupported-avd-abi"
            rows.append(row)
            continue
        row["configuredAbi"] = configured_abi
        if avd_is_busy(avd):
            row["status"] = "NOT_RUN"
            row["reason"] = "avd-busy-existing-instance"
            rows.append(row)
            continue
        owned_emulator = True
        try:
            port = free_port(adb, 5570 + (index * 2))
        except RuntimeError as error:
            row["reason"] = str(error)
            rows.append(row)
            continue
        serial = f"emulator-{port}"
        cell = output / f"api{api}"
        cell.mkdir(parents=True, exist_ok=True)
        cell.chmod(0o700)
        emulator_log = cell / "emulator.log"
        if not owned_emulator:
            emulator_log.touch()
        emulator_log_handle = emulator_log.open("w", encoding="utf-8") if owned_emulator else None
        proc = (
            subprocess.Popen(
                [emulator, "-avd", avd, "-port", str(port), "-no-window", "-no-audio", "-no-boot-anim", "-no-snapshot"],
                stdout=emulator_log_handle,
                stderr=subprocess.STDOUT,
                text=True,
            )
            if owned_emulator
            else None
        )
        try:
            ready, sdk, abi_list, boot_reason = wait_for_boot(adb, serial, args.boot_timeout)
            row["runtimeSdk"] = int(sdk) if sdk.isdigit() else None
            row["runtimeAbi"] = abi_list.split(",")[0] if abi_list else ""
            if not ready:
                row["reason"] = boot_reason
                with emulator_log.open("a", encoding="utf-8") as handle:
                    handle.write("boot did not reach sys.boot_completed\n")
                continue
            if sdk != str(api):
                row["status"] = "FAIL"
                row["reason"] = "api-mismatch"
                continue
            if configured_abi not in abi_list.split(","):
                row["status"] = "FAIL"
                row["reason"] = "configured-abi-missing"
                continue
            shell_page_size = runtime_page_size(adb, serial)
            if shell_page_size is not None:
                row["shellPageSizeBytes"] = shell_page_size
            row["preClean"] = {
                SAMPLE_PACKAGE: preclean_package(adb, serial, SAMPLE_PACKAGE),
                TEST_PACKAGE: preclean_package(adb, serial, TEST_PACKAGE),
            }
            if any(item["uninstallRc"] != 0 for item in row["preClean"].values()):
                row["status"] = "FAIL"
                row["reason"] = "pre-clean-failed"
                continue
            install = adb_command(adb, serial, ["install", "-r", "-d", str(args.apk)], timeout=120, output=cell / "sample-install.log")
            test_install = adb_command(adb, serial, ["install", "-r", "-d", str(args.test_apk)], timeout=120, output=cell / "test-install.log")
            row["installRc"] = install.returncode
            row["testInstallRc"] = test_install.returncode
            if install.returncode != 0 or test_install.returncode != 0:
                row["status"] = "FAIL"
                row["reason"] = "apk-install-failed"
                continue
            clear_logcat = adb_command(adb, serial, ["logcat", "-c"], timeout=30)
            if clear_logcat.returncode != 0:
                row["status"] = "FAIL"
                row["reason"] = "logcat-clear-failed"
                continue
            instrument = adb_command(
                adb,
                serial,
                ["shell", "am", "instrument", "-w", "-r", "-e", "class", TEST_CLASS, INSTRUMENTATION],
                timeout=120,
                output=None,
            )
            row["instrumentationRc"] = instrument.returncode
            write_private(cell / "instrumentation.log", sanitize_runtime_text((instrument.stdout or "") + (instrument.stderr or "")))
            logcat_path = cell / "logcat.log"
            logcat = adb_command(adb, serial, ["logcat", "-d", "-v", "brief"], timeout=60, output=None)
            write_private(logcat_path, sanitize_runtime_text((logcat.stdout or "") + (logcat.stderr or "")))
            combined = (cell / "instrumentation.log").read_text(encoding="utf-8", errors="replace")
            combined += "\n" + logcat_path.read_text(encoding="utf-8", errors="replace")
            marker = parse_marker(combined)
            if marker is not None:
                row["pageSizeBytes"] = marker.get("pageSizeBytes")
            valid, reason = validate_smoke_marker(marker, api=api, abi=configured_abi, apk_sha256=artifact_hashes["sampleApkSha256"], text=combined)
            row["marker"] = marker
            row["status"] = "PASS" if instrument.returncode == 0 and valid else "FAIL"
            row["reason"] = reason if valid else reason
            if instrument.returncode != 0 and row["status"] == "PASS":
                row["status"] = "FAIL"
                row["reason"] = "instrumentation-failed"
        except subprocess.TimeoutExpired:
            row["status"] = "NOT_RUN"
            row["reason"] = "command-timeout"
        finally:
            if row.get("installRc") == 0 or row.get("testInstallRc") == 0:
                for package in (SAMPLE_PACKAGE, TEST_PACKAGE):
                    removed = adb_command(adb, serial, ["shell", "pm", "uninstall", package], timeout=30)
                    row["cleanup"][f"uninstall_{package}"] = removed.returncode
            if owned_emulator and not args.keep_emulators:
                killed = adb_command(adb, serial, ["emu", "kill"], timeout=30, output=cell / "emulator-kill.log")
                row["cleanup"]["emulatorKillRc"] = killed.returncode
            if proc is not None and not args.keep_emulators:
                try:
                    proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=10)
                row["cleanup"]["emulatorProcessRc"] = proc.returncode
            if emulator_log_handle is not None:
                emulator_log_handle.close()
            if emulator_log.is_file():
                write_private(
                    emulator_log,
                    sanitize_runtime_text(emulator_log.read_text(encoding="utf-8", errors="replace")),
                )
            cleanup_values = [value for value in row.get("cleanup", {}).values() if isinstance(value, int)]
            if row.get("status") == "PASS" and any(value != 0 for value in cleanup_values):
                row["status"] = "FAIL"
                row["reason"] = "cleanup-failed"
            rows.append(row)

    summary["cells"] = rows
    summary["status"], summary["candidateValidation"] = finalize_matrix_status(rows)
    summary["abiSummary"] = {}
    for abi in ABI_ALLOWLIST:
        abi_rows = [row for row in rows if row.get("abi") == abi]
        if any(row.get("status") == "PASS" for row in abi_rows):
            summary["abiSummary"][abi] = {"status": "PASS"}
        elif abi_rows:
            summary["abiSummary"][abi] = {"status": "PARTIAL", "reason": "no-passing-cell"}
        else:
            summary["abiSummary"][abi] = {"status": "NOT_RUN", "reason": "no-executable-avd-selected"}
    write_private(output / "summary.json", json.dumps(summary, indent=2, sort_keys=True) + "\n")
    lines = [
        "# Project Native Runtime Matrix",
        "",
        f"- status: {summary['status']}",
        "- evidence class: PROJECT_NATIVE_RUNTIME",
        "- provider status: LEO_PROVIDER_RUNTIME_NOT_RUN",
        f"- cells: {sum(row['status'] == 'PASS' for row in rows)}/{len(rows)} PASS",
        f"- candidate validation: {summary.get('candidateValidation', {}).get('reason', 'not-run')}",
        f"- sample APK SHA-256: {artifact_hashes['sampleApkSha256']}",
        f"- SDK androidTest APK SHA-256: {artifact_hashes['androidTestApkSha256']}",
        f"- SDK AAR SHA-256: {artifact_hashes['aarSha256']}",
        "- raw identifiers printed: false",
        "- secret values printed: false",
        "",
    ]
    for row in rows:
        lines.append(
            f"- API {row['apiLevel']}: {row['status']} ({row['reason']}); "
            f"ABI={row.get('runtimeAbi', row['abi']) or 'unknown'}; "
            f"pageSizeBytes={row.get('pageSizeBytes', 'unknown')}"
        )
    write_private(output / "summary.md", "\n".join(lines) + "\n")
    sums = []
    for path in sorted(output.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            sums.append(f"{sha256_file(path)}  {path.relative_to(output)}")
    write_private(output / "SHA256SUMS", "\n".join(sums) + "\n")
    return 0 if summary["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
