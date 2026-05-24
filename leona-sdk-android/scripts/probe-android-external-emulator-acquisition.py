#!/usr/bin/env python3
"""Probe external Android emulator acquisition options.

This helper is intentionally read-only. It records which external emulator
families are already installed or realistically acquireable on the current Mac
without printing raw ADB serials, credentials, or device identifiers.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import plistlib
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


TARGETS = {
    "BlueStacks": {
        "tokens": ("bluestacks",),
        "brewCask": "bluestacks",
        "notes": "arm64 cask is available, but pkg install normally requires administrator authorization",
    },
    "Genymotion": {
        "tokens": ("genymotion",),
        "brewCask": "genymotion",
        "notes": "Intel cask; requires Rosetta on Apple Silicon and may require GUI login/license",
    },
    "Nox": {
        "tokens": ("nox",),
        "brewCask": "noxappplayer",
        "notes": "Intel cask; Homebrew currently marks it deprecated for Gatekeeper failure",
    },
    "LDPlayer": {
        "tokens": ("ldplayer", "ld player"),
        "brewCask": "",
        "notes": "No Homebrew cask found in the current local tap set",
    },
}

RAW_SERIALISH = re.compile(r"\b[A-Za-z0-9_.:-]{8,}\b")
SECRETISH = re.compile(
    r"(?i)(ghp_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"LEONA_[A-Z0-9_]*(SECRET|TOKEN|KEY)[A-Z0-9_]*=[^\s]+|"
    r"(secret|token|credential)[=:]\s*[A-Za-z0-9._~+/=-]{16,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        default="/tmp/leona-android-external-emulator-acquisition-active",
        help="Output directory for the probe report",
    )
    parser.add_argument(
        "--record-install-attempt",
        action="append",
        default=[],
        metavar="TARGET=RESULT",
        help="Record a non-sensitive install attempt result, for example BlueStacks=installer-ready-admin-verified",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    attempts = parse_attempts(args.record_install_attempt)
    installed_apps = installed_emulator_apps()
    running = running_emulator_processes()
    adb = adb_devices()
    genymotion_tooling = genymotion_cli_state()
    genymotion_devices = genymotion_virtual_devices(genymotion_tooling)
    brew = brew_state()
    rosetta = rosetta_state()
    arch = run_capture(["uname", "-m"]).strip() or "unknown"

    targets = []
    for name, target in TARGETS.items():
        apps = [app for app in installed_apps if app["vendor"] == name]
        processes = [proc for proc in running if proc["vendor"] == name]
        cask = target["brewCask"]
        cask_info = brew_cask_info(cask) if cask and brew["present"] else {"available": False}
        attempt_result = attempts.get(name.lower(), "")
        status = classify_target(
            name,
            apps,
            processes,
            cask_info,
            attempt_result,
            arch,
            rosetta,
            genymotion_devices,
            genymotion_tooling,
        )
        targets.append(
            {
                "name": name,
                "status": status,
                "installedApps": apps,
                "runningProcessCount": len(processes),
                "brewCask": cask,
                "brewCaskAvailable": cask_info.get("available") is True,
                "brewInfoHash": cask_info.get("infoHash", ""),
                "installAttempt": attempt_result,
                "downloadBlockerReason": download_blocker_reason(attempt_result) if status == "blocked-download" else "",
                "virtualDeviceReady": genymotion_devices["ready"] if name == "Genymotion" else None,
                "virtualDeviceCount": genymotion_devices["createdDeviceCount"] if name == "Genymotion" else None,
                "runningVirtualDeviceCount": genymotion_devices["runningDeviceCount"] if name == "Genymotion" else None,
                "cliTemplateAccess": genymotion_tooling["templateAccess"] if name == "Genymotion" else None,
                "licenseType": genymotion_tooling["licenseType"] if name == "Genymotion" else None,
                "notes": target["notes"],
            }
        )

    acquireable = [
        target["name"]
        for target in targets
        if target["status"] in {"installed", "running", "installable-with-admin", "installed-no-virtual-device"}
    ]
    sample_ready = [target["name"] for target in targets if target["status"] == "running"]
    missing = [
        target["name"]
        for target in targets
        if target["status"] in {"not-found", "blocked-unsupported", "blocked-artifact-integrity", "blocked-download"}
    ]
    report = {
        "status": "ready-with-admin-action" if acquireable else "external-emulator-acquisition-blocked",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "outputDir": str(output_dir),
        "host": {
            "arch": arch,
            "rosettaInstalled": rosetta["installed"],
            "homebrewPresent": brew["present"],
        },
        "adb": adb,
        "genymotion": {
            "virtualDevices": genymotion_devices,
            "cli": genymotion_tooling,
        },
        "targets": targets,
        "targetCount": len(targets),
        "acquireableTargets": acquireable,
        "acquireableTargetCount": len(acquireable),
        "sampleReadyTargets": sample_ready,
        "sampleReadyTargetCount": len(sample_ready),
        "missingTargets": missing,
        "secretValuesPrinted": False,
        "rawIdentifiersPrinted": False,
        "startsPaidDevices": False,
        "installsSoftware": False,
    }
    write_report(output_dir, report)
    reject_sensitive_output(output_dir)
    print(f"[android-external-emulator-acquisition] {report['status']}: {output_dir / 'summary.md'}")
    return 0


def parse_attempts(items: list[str]) -> dict[str, str]:
    attempts: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            continue
        name, result = item.split("=", 1)
        attempts[name.strip().lower()] = result.strip()[:96]
    return attempts


def classify_target(
    name: str,
    apps: list[dict[str, str]],
    processes: list[dict[str, str]],
    cask_info: dict[str, Any],
    attempt_result: str,
    arch: str,
    rosetta: dict[str, Any],
    genymotion_devices: dict[str, Any],
    genymotion_tooling: dict[str, Any],
) -> str:
    if name == "Genymotion" and processes and not genymotion_devices["ready"]:
        return "running-no-virtual-device"
    if processes:
        return "running"
    if name == "Genymotion" and apps and not genymotion_tooling["templateAccess"]:
        return "installed-license-limited"
    if name == "Genymotion" and apps and not genymotion_devices["ready"]:
        return "installed-no-virtual-device"
    if apps:
        return "installed"
    if attempt_result.startswith("failed-checksum"):
        return "blocked-artifact-integrity"
    if attempt_result.startswith("failed-download"):
        return "blocked-download"
    if attempt_result.startswith(("installer-ready-admin", "download-verified", "verified-installer")):
        return "installable-with-admin"
    if attempt_result.startswith("failed-sudo"):
        return "installable-with-admin"
    if name in {"Genymotion", "Nox"} and arch == "arm64" and not rosetta["installed"]:
        return "blocked-unsupported"
    if cask_info.get("available"):
        return "installable-with-admin" if name == "BlueStacks" else "installable"
    return "not-found"


def download_blocker_reason(attempt_result: str) -> str:
    if not attempt_result.startswith("failed-download"):
        return ""
    lowered = attempt_result.lower()
    if "edgeone" in lowered or "restricted" in lowered or "http-567" in lowered or "http567" in lowered:
        return "edgeone-restricted"
    if "timeout" in lowered:
        return "timeout"
    if "checksum" in lowered or "integrity" in lowered:
        return "artifact-integrity"
    if "network" in lowered or "connection" in lowered or "dns" in lowered:
        return "network"
    return "download-failed"


def genymotion_cli_state() -> dict[str, Any]:
    gmtool = Path("/Applications/Genymotion.app/Contents/MacOS/gmtool")
    if not gmtool.exists():
        return {
            "available": False,
            "versionHash": "",
            "licenseType": "",
            "templateAccess": False,
            "hwprofilesAccessible": False,
            "osimagesAccessible": False,
            "blocker": "gmtool-not-found",
        }

    version = run([str(gmtool), "version"], timeout=12)
    license_info = run([str(gmtool), "license", "info"], timeout=12)
    hwprofiles = run([str(gmtool), "admin", "hwprofiles", "--format", "json"], timeout=20)
    osimages = run([str(gmtool), "admin", "osimages", "--format", "json"], timeout=20)

    hw_ok = hwprofiles["ok"]
    os_ok = osimages["ok"]
    blocker = ""
    if not hw_ok or not os_ok:
        blocker_text = "\n".join(
            line.strip()
            for line in (hwprofiles["stdout"] + hwprofiles["stderr"] + "\n" + osimages["stdout"] + osimages["stderr"]).splitlines()
            if line.strip()
        )
        blocker = sanitize_message(blocker_text.splitlines()[0] if blocker_text else "template-list-unavailable")

    return {
        "available": True,
        "versionHash": short_hash(version["stdout"] + version["stderr"]),
        "licenseType": parse_genymotion_license_type(license_info["stdout"] + license_info["stderr"]),
        "templateAccess": hw_ok and os_ok,
        "hwprofilesAccessible": hw_ok,
        "osimagesAccessible": os_ok,
        "blocker": blocker,
        "rawOutputRedacted": True,
    }


def parse_genymotion_license_type(text: str) -> str:
    for line in text.splitlines():
        if "License Type" in line and ":" in line:
            value = line.split(":", 1)[1].strip()
            return sanitize_message(value)[:48]
    return ""


def sanitize_message(value: str) -> str:
    value = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "<redacted-email>", value)
    value = re.sub(r"(?i)(password|token|key|secret|credential|license)\s*[:=]\s*\S+", r"\1=<redacted>", value)
    return value[:160]


def genymotion_virtual_devices(tooling: dict[str, Any]) -> dict[str, Any]:
    genyshell = shutil.which("genyshell") or "/opt/homebrew/bin/genyshell"
    shell_result = (
        run([genyshell, "-q", "-c", "devices list"], timeout=12)
        if Path(genyshell).exists()
        else {"ok": False, "stdout": "", "stderr": "genyshell-not-found"}
    )
    shell_text = shell_result["stdout"] + shell_result["stderr"]
    no_running_devices = "No devices available" in shell_text or "No Genymotion virtual device running found" in shell_text
    running_device_lines = [
        line
        for line in shell_result["stdout"].splitlines()
        if line.strip() and not line.startswith("|") and "No devices" not in line
    ]

    created_device_count = 0
    list_ok = False
    gmtool = Path("/Applications/Genymotion.app/Contents/MacOS/gmtool")
    if gmtool.exists():
        list_result = run([str(gmtool), "--format", "json", "admin", "list"], timeout=20)
        list_ok = list_result["ok"]
        if list_result["ok"]:
            created_device_count = count_genymotion_instances(list_result["stdout"])

    return {
        "available": Path(genyshell).exists() or tooling.get("available") is True,
        "ok": shell_result["ok"] or list_ok,
        "ready": bool(created_device_count) or (shell_result["ok"] and not no_running_devices and bool(running_device_lines)),
        "createdDeviceCount": created_device_count,
        "runningDeviceCount": len(running_device_lines) if shell_result["ok"] and not no_running_devices else 0,
        "outputHash": short_hash(shell_text),
        "rawOutputRedacted": True,
    }


def count_genymotion_instances(text: str) -> int:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return 0
    instances = payload.get("instances")
    return len(instances) if isinstance(instances, list) else 0


def installed_emulator_apps() -> list[dict[str, str]]:
    apps_dirs = [Path("/Applications"), Path.home() / "Applications"]
    found: list[dict[str, str]] = []
    for apps_dir in apps_dirs:
        if not apps_dir.exists():
            continue
        for app in apps_dir.glob("*.app"):
            lower_name = app.name.lower()
            bundle = app_bundle_id(app).lower()
            haystack = f"{lower_name} {bundle}"
            for vendor, target in TARGETS.items():
                if any(token in haystack for token in target["tokens"]):
                    found.append(
                        {
                            "vendor": vendor,
                            "appName": app.name,
                            "pathHint": str(app.parent),
                            "bundleIdHash": short_hash(bundle),
                        }
                    )
                    break
    return found


def app_bundle_id(app_path: Path) -> str:
    plist_path = app_path / "Contents" / "Info.plist"
    if not plist_path.exists():
        return ""
    try:
        with plist_path.open("rb") as handle:
            info = plistlib.load(handle)
        return str(info.get("CFBundleIdentifier", ""))
    except Exception:
        return ""


def running_emulator_processes() -> list[dict[str, str]]:
    result = run(["ps", "axo", "comm="], timeout=10)
    found: list[dict[str, str]] = []
    if not result["ok"]:
        return found
    for command in result["stdout"].splitlines():
        lower = command.lower()
        for vendor, target in TARGETS.items():
            if any(token in lower for token in target["tokens"]):
                found.append({"vendor": vendor, "processHash": short_hash(command)})
                break
    return found


def adb_devices() -> dict[str, Any]:
    adb = shutil.which("adb")
    if not adb:
        return {"available": False, "readyDeviceCount": 0, "devices": [], "rawOutputRedacted": True}
    result = run([adb, "devices", "-l"], timeout=12)
    devices = []
    for line in result["stdout"].splitlines()[1:]:
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split()
        serial = parts[0]
        state = parts[1] if len(parts) > 1 else "unknown"
        details = " ".join(parts[2:])
        devices.append(
            {
                "serialHash": short_hash(serial),
                "state": state,
                "isLikelyEmulator": serial.startswith("emulator-") or serial.startswith("127.0.0.1:"),
                "detailHash": short_hash(details),
            }
        )
    return {
        "available": True,
        "ok": result["ok"],
        "readyDeviceCount": sum(1 for device in devices if device["state"] == "device"),
        "devices": devices,
        "rawOutputRedacted": True,
    }


def brew_state() -> dict[str, Any]:
    brew = shutil.which("brew")
    return {"present": bool(brew), "pathHint": str(Path(brew).parent) if brew else ""}


def brew_cask_info(cask: str) -> dict[str, Any]:
    result = run(["brew", "info", "--cask", cask], timeout=20)
    text = result["stdout"] + result["stderr"]
    return {
        "available": result["ok"] and ("Not installed" in text or "Installed" in text),
        "exitCode": result["exitCode"],
        "infoHash": short_hash(text) if text else "",
    }


def rosetta_state() -> dict[str, Any]:
    result = run(["pkgutil", "--pkg-info", "com.apple.pkg.RosettaUpdateAuto"], timeout=10)
    return {"installed": result["ok"], "infoHash": short_hash(result["stdout"] + result["stderr"])}


def run_capture(cmd: list[str]) -> str:
    return run(cmd, timeout=10)["stdout"]


def run(cmd: list[str], timeout: int = 10) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            cmd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        return {
            "ok": completed.returncode == 0,
            "exitCode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
    except FileNotFoundError:
        return {"ok": False, "exitCode": 127, "stdout": "", "stderr": "not found"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "exitCode": 124, "stdout": "", "stderr": "timeout"}


def short_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16] if value else ""


def write_report(output_dir: Path, report: dict[str, Any]) -> None:
    (output_dir / "summary.json").write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "# Android External Emulator Acquisition Probe",
        "",
        f"- status: {report['status']}",
        f"- host arch: {report['host']['arch']}",
        f"- rosetta installed: {str(report['host']['rosettaInstalled']).lower()}",
        f"- adb ready devices: {report['adb']['readyDeviceCount']}",
        "- installs software: false",
        "- starts paid devices: false",
        "- secret values printed: false",
        "- raw identifiers printed: false",
        "",
        "## Targets",
        "",
    ]
    for target in report["targets"]:
        lines.append(
            "- "
            f"{target['name']}: {target['status']} "
            f"(brewCask={target['brewCask'] or 'none'}, "
            f"installedApps={len(target['installedApps'])}, "
            f"runningProcesses={target['runningProcessCount']})"
        )
        if target["installAttempt"]:
            lines.append(f"  - installAttempt: {target['installAttempt']}")
        if target["downloadBlockerReason"]:
            lines.append(f"  - downloadBlockerReason: {target['downloadBlockerReason']}")
        if target["name"] == "Genymotion":
            lines.append(f"  - virtualDeviceReady: {str(target['virtualDeviceReady']).lower()}")
            lines.append(f"  - virtualDeviceCount: {target['virtualDeviceCount']}")
            lines.append(f"  - runningVirtualDeviceCount: {target['runningVirtualDeviceCount']}")
            lines.append(f"  - cliTemplateAccess: {str(target['cliTemplateAccess']).lower()}")
            if target["licenseType"]:
                lines.append(f"  - licenseType: {target['licenseType']}")
        lines.append(f"  - notes: {target['notes']}")
    lines.extend(
        [
            "",
            "## Next Actions",
            "",
            "- If a target is `running` or `installed`, launch/connect it through ADB and run the existing matrix bootstrap/import flow.",
            "- For Genymotion, `installed` is not enough: `virtualDeviceReady` must be true before sample collection can start.",
            "- If Genymotion is `installed-license-limited`, complete GUI account/license/template setup before creating a virtual device.",
            "- If a target is `blocked-artifact-integrity`, do not launch it; refresh the distribution source or use a different vetted provider.",
            "- If a target is `blocked-download`, inspect `downloadBlockerReason`, refresh the network/download source, and rerun the fetch before attempting install.",
            "- If `downloadBlockerReason` is `edgeone-restricted`, retry only through a browser/session/network path that can complete the full artifact download and verify checksum/Gatekeeper.",
            "- If `installAttempt` starts with `installer-ready-admin`, the installer has already passed local integrity checks; complete only the administrator install step before sampling.",
            "- If a target is `installable-with-admin`, complete the OS installer in an administrator session, then rerun this probe.",
            "- Keep full BoxIds and raw ADB serials inside private `/tmp` collection artifacts only.",
            "",
        ]
    )
    (output_dir / "summary.md").write_text("\n".join(lines), encoding="utf-8")


def reject_sensitive_output(output_dir: Path) -> None:
    hits: list[str] = []
    for path in output_dir.rglob("*"):
        if not path.is_file() or path.suffix not in {".md", ".json", ".jsonl", ".txt"}:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if SECRETISH.search(text):
            hits.append(str(path))
        for line in text.splitlines():
            lower_line = line.lower()
            if (
                "serialHash" in line
                or "raw identifiers printed" in lower_line
                or "raw adb serials" in lower_line
                or "outputdir" in lower_line
                or "summary" in lower_line
            ):
                continue
            if "127.0.0.1:" in line or re.search(r"\bemulator-\d+\b", line):
                hits.append(str(path))
                break
            if "ADB serial" in line and RAW_SERIALISH.search(line):
                hits.append(str(path))
                break
    if hits:
        raise SystemExit("sensitive values found in acquisition output: " + ", ".join(sorted(set(hits))))


if __name__ == "__main__":
    raise SystemExit(main())
