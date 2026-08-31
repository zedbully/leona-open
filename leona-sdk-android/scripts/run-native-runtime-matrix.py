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
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


API_LEVELS = tuple(range(23, 37))
ABI_ALLOWLIST = ("arm64-v8a", "armeabi-v7a", "x86_64")
TEST_PACKAGE = "io.leonasec.leona.test"
SAMPLE_PACKAGE = "io.leonasec.leona.sample"
INSTRUMENTATION = f"{TEST_PACKAGE}/androidx.test.runner.AndroidJUnitRunner"
TEST_CLASS = "io.leonasec.leona.internal.runtime.NativeRuntimeSmokeTest#packagedNativeRuntimeLoadsInitializesAndCollects"
MARKER_RE = re.compile(
    r"LEONA_NATIVE_SMOKE_RESULT api=(?P<api>\d+) abi=(?P<abi>[A-Za-z0-9_-]+) "
    r"payloadBytes=(?P<size>\d+) payloadSha256=(?P<digest>[0-9a-f]{64})"
)
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


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


def config_abi(avd: str) -> str:
    config = Path.home() / ".android" / "avd" / f"{avd}.avd" / "config.ini"
    if not config.is_file():
        return ""
    for line in config.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip().startswith("abi.type"):
            return line.split("=", 1)[1].strip()
    return ""


def free_port(adb: str, base: int) -> int:
    connected = run_command([adb, "devices"], timeout=10).stdout
    used = set(re.findall(r"emulator-(\d+)", connected))
    for port in range(base, base + 80, 2):
        if str(port) not in used:
            return port
    return base


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
        "payloadBytes": int(match.group("size")),
        "payloadSha256": match.group("digest"),
    }


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
        for value in (row.get("serial"), row.get("boxId"), row.get("token")):
            if value:
                return False, "raw-identifier-present"
    return True, "candidate-consistent-redacted"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", required=True, type=Path, help="exact sample debug APK")
    parser.add_argument("--test-apk", required=True, type=Path, help="exact SDK androidTest APK")
    parser.add_argument("--aar", required=True, type=Path, help="exact SDK AAR used for candidate identity")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--emulator", default="emulator")
    parser.add_argument("--apis", default=",".join(map(str, API_LEVELS)))
    parser.add_argument("--source-commit", default="")
    parser.add_argument("--source-tree", default="")
    parser.add_argument("--boot-timeout", type=int, default=180)
    parser.add_argument("--keep-emulators", action="store_true", help="do not stop temporary emulators (debug only)")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    output = args.output_dir.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    output.chmod(0o700)
    for artifact in (args.apk, args.test_apk, args.aar):
        if not artifact.is_file():
            raise SystemExit(f"artifact missing: {artifact}")
    apis = tuple(int(value) for value in args.apis.split(",") if value.strip())
    if any(api not in API_LEVELS for api in apis):
        raise SystemExit("--apis must be a comma-separated subset of 23..36")
    adb = shutil.which(args.adb) or args.adb
    emulator = shutil.which(args.emulator) or args.emulator
    avds = discover_avds(emulator)
    artifact_hashes = {
        "sampleApkSha256": sha256_file(args.apk),
        "androidTestApkSha256": sha256_file(args.test_apk),
        "aarSha256": sha256_file(args.aar),
    }
    summary: dict[str, Any] = {
        "schema": "leona-project-native-runtime-matrix-v1",
        "status": "PASS" if apis else "NOT_RUN",
        "sourceCommit": args.source_commit,
        "sourceTree": args.source_tree,
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
        avd = choose_avd(avds, api)
        row: dict[str, Any] = {
            "apiLevel": api,
            "avd": avd or "",
            "avdNameSha256": sha256_text(avd) if avd else "",
            "abi": "arm64-v8a",
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
        if configured_abi and configured_abi != "arm64-v8a":
            row["status"] = "NOT_RUN"
            row["reason"] = "unsupported-avd-abi"
            row["configuredAbi"] = configured_abi
            rows.append(row)
            continue
        existing_serial = running_emulator_serial(avd)
        owned_emulator = existing_serial is None
        port = free_port(adb, 5570 + (index * 2)) if owned_emulator else int(existing_serial.rsplit("-", 1)[1])
        serial = existing_serial or f"emulator-{port}"
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
            if "arm64-v8a" not in abi_list.split(","):
                row["status"] = "FAIL"
                row["reason"] = "arm64-abi-missing"
                continue
            install = adb_command(adb, serial, ["install", "-r", "-d", str(args.apk)], timeout=120, output=cell / "sample-install.log")
            test_install = adb_command(adb, serial, ["install", "-r", "-d", str(args.test_apk)], timeout=120, output=cell / "test-install.log")
            row["installRc"] = install.returncode
            row["testInstallRc"] = test_install.returncode
            if install.returncode != 0 or test_install.returncode != 0:
                row["status"] = "FAIL"
                row["reason"] = "apk-install-failed"
                continue
            instrument = adb_command(
                adb,
                serial,
                ["shell", "am", "instrument", "-w", "-r", "-e", "class", TEST_CLASS, INSTRUMENTATION],
                timeout=120,
                output=cell / "instrumentation.log",
            )
            row["instrumentationRc"] = instrument.returncode
            logcat_path = cell / "logcat.log"
            logcat = adb_command(adb, serial, ["logcat", "-d", "-v", "brief"], timeout=60, output=logcat_path)
            combined = (cell / "instrumentation.log").read_text(encoding="utf-8", errors="replace")
            combined += "\n" + logcat_path.read_text(encoding="utf-8", errors="replace")
            marker = parse_marker(combined)
            valid, reason = validate_smoke_marker(marker, api=api, abi="arm64-v8a", apk_sha256=artifact_hashes["sampleApkSha256"], text=combined)
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
            if emulator_log_handle is not None:
                emulator_log_handle.close()
            emulator_log.chmod(0o600)
            rows.append(row)

    summary["cells"] = rows
    summary["status"] = "PASS" if rows and all(row["status"] == "PASS" for row in rows) else "PARTIAL" if rows else "NOT_RUN"
    summary["abiSummary"] = {
        "arm64-v8a": {"status": "PASS" if any(row["status"] == "PASS" and row.get("abi") == "arm64-v8a" for row in rows) else "NOT_RUN"},
        "armeabi-v7a": {"status": "NOT_RUN", "reason": "no-executable-32-bit-AVD-selected"},
        "x86_64": {"status": "NOT_RUN", "reason": "no-executable-x86_64-AVD-selected"},
    }
    write_private(output / "summary.json", json.dumps(summary, indent=2, sort_keys=True) + "\n")
    lines = [
        "# Project Native Runtime Matrix",
        "",
        f"- status: {summary['status']}",
        "- evidence class: PROJECT_NATIVE_RUNTIME",
        "- provider status: LEO_PROVIDER_RUNTIME_NOT_RUN",
        f"- cells: {sum(row['status'] == 'PASS' for row in rows)}/{len(rows)} PASS",
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
            f"ABI={row.get('runtimeAbi', row['abi']) or 'unknown'}"
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
