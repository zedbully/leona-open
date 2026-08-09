#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${LEONA_ANDROID_MATRIX_DISCOVERY_OUT:-$(mktemp -d /tmp/leona-android-matrix-discovery.XXXXXX)}"
mkdir -p "${OUT_DIR}"

python3 - "${OUT_DIR}" <<'PY'
import hashlib
import json
import os
import plistlib
import shutil
import subprocess
import sys
from pathlib import Path

out_dir = Path(sys.argv[1])

def sha256_hint(value: str) -> str:
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]

def run(cmd, timeout=10):
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

def command_path(name: str):
    found = shutil.which(name)
    return found if found else ""

def existing_path(path: str):
    expanded = Path(path).expanduser()
    return str(expanded) if expanded.exists() else ""

def android_sdk_candidates():
    candidates = []
    for env_name in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        value = os.environ.get(env_name, "")
        if value:
            candidates.append({"source": env_name, "path": value, "exists": Path(value).expanduser().exists()})
    for source, path in (
        ("default-home", "~/Library/Android/sdk"),
        ("homebrew-commandlinetools", "/opt/homebrew/share/android-commandlinetools"),
        ("usr-local-commandlinetools", "/usr/local/share/android-commandlinetools"),
        ("opt-android-sdk", "/opt/android-sdk"),
        ("usr-local-android-sdk", "/usr/local/share/android-sdk"),
    ):
        expanded = Path(path).expanduser()
        candidates.append({"source": source, "path": str(expanded), "exists": expanded.exists()})
    deduped = []
    seen = set()
    for item in candidates:
        key = item["path"]
        if key not in seen:
            deduped.append(item)
            seen.add(key)
    return deduped

def adb_devices(adb_path: str):
    if not adb_path:
        return {"available": False, "devices": [], "rawOutputRedacted": True}
    result = run([adb_path, "devices", "-l"], timeout=12)
    devices = []
    for line in result["stdout"].splitlines()[1:]:
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split()
        serial = parts[0]
        state = parts[1] if len(parts) > 1 else "unknown"
        details = " ".join(parts[2:])
        devices.append({
            "serialHash": sha256_hint(serial),
            "state": state,
            "isLikelyEmulator": serial.startswith("emulator-") or serial.startswith("127.0.0.1:"),
            "detailHash": sha256_hint(details),
        })
    return {
        "available": True,
        "ok": result["ok"],
        "exitCode": result["exitCode"],
        "devices": devices,
        "rawOutputRedacted": True,
    }

def avd_list(emulator_path: str):
    if not emulator_path:
        return {"available": False, "avds": []}
    result = run([emulator_path, "-list-avds"], timeout=10)
    avds = [line.strip() for line in result["stdout"].splitlines() if line.strip()]
    return {"available": True, "ok": result["ok"], "exitCode": result["exitCode"], "avds": avds}

def app_bundle_id(app_path: Path):
    plist_path = app_path / "Contents" / "Info.plist"
    if not plist_path.exists():
        return ""
    try:
        with plist_path.open("rb") as handle:
            info = plistlib.load(handle)
        return str(info.get("CFBundleIdentifier", ""))
    except Exception:
        return ""

def installed_emulator_apps():
    targets = {
        "Genymotion": ("genymotion",),
        "BlueStacks": ("bluestacks", "blue stacks"),
        "Nox": ("nox",),
        "LDPlayer": ("ldplayer", "ld player"),
        "MuMu": ("mumu", "nemu"),
        "Android Studio": ("android studio",),
    }
    apps_dirs = [Path("/Applications"), Path.home() / "Applications"]
    found = []
    for apps_dir in apps_dirs:
        if not apps_dir.exists():
            continue
        for app in apps_dir.glob("*.app"):
            lower_name = app.name.lower()
            bundle = app_bundle_id(app).lower()
            haystack = f"{lower_name} {bundle}"
            for vendor, tokens in targets.items():
                if any(token in haystack for token in tokens):
                    found.append({
                        "vendor": vendor,
                        "appName": app.name,
                        "pathHint": str(app.parent),
                        "bundleIdHash": sha256_hint(bundle),
                    })
                    break
    return found

def running_emulator_processes():
    result = run(["ps", "axo", "pid=,comm="], timeout=10)
    vendors = {
        "Genymotion": ("genymotion",),
        "BlueStacks": ("bluestacks",),
        "Nox": ("nox",),
        "LDPlayer": ("ldplayer",),
        "MuMu": ("mumu", "nemu"),
        "Android Emulator": ("emulator", "qemu-system"),
    }
    found = []
    if not result["ok"]:
        return found
    for line in result["stdout"].splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split(maxsplit=1)
        command = parts[1] if len(parts) > 1 else parts[0]
        lower = command.lower()
        for vendor, tokens in vendors.items():
            if any(token in lower for token in tokens):
                found.append({"vendor": vendor, "processHash": sha256_hint(command)})
                break
    return found

def wetest_env_presence():
    relevant = [
        key for key in os.environ
        if key.startswith("WETEST_")
        or key.startswith("LEONA_WETEST_")
        or key in {"WDB_TOKEN", "WDB_SERIAL", "WDB_URL"}
    ]
    return [{"name": key, "present": True} for key in sorted(relevant)]

def compatibility_system_images(candidates):
    sdk_root = next(
        (Path(item["path"]).expanduser() for item in candidates if item["exists"]),
        None,
    )
    rows = []
    for api in range(23, 37):
        image_dir = (
            sdk_root / "system-images" / f"android-{api}" / "google_apis" / "arm64-v8a"
            if sdk_root else None
        )
        system_image = image_dir / "system.img" if image_dir else None
        ramdisk = image_dir / "ramdisk.img" if image_dir else None
        complete = bool(
            system_image and ramdisk
            and system_image.is_file() and system_image.stat().st_size > 100_000_000
            and ramdisk.is_file() and ramdisk.stat().st_size > 100_000
        )
        rows.append({
            "apiLevel": api,
            "package": f"system-images;android-{api};google_apis;arm64-v8a",
            "metadataPresent": bool(image_dir and image_dir.is_dir()),
            "complete": complete,
            "systemImageBytes": system_image.stat().st_size if system_image and system_image.is_file() else 0,
            "ramdiskBytes": ramdisk.stat().st_size if ramdisk and ramdisk.is_file() else 0,
        })
    return rows

sdk_candidates = android_sdk_candidates()
adb = command_path("adb")
emulator = command_path("emulator")
avdmanager = command_path("avdmanager")

if not adb:
    for candidate in sdk_candidates:
        candidate_adb = Path(candidate["path"]).expanduser() / "platform-tools" / "adb"
        if candidate_adb.exists():
            adb = str(candidate_adb)
            break

if not emulator:
    for candidate in sdk_candidates:
        candidate_emulator = Path(candidate["path"]).expanduser() / "emulator" / "emulator"
        if candidate_emulator.exists():
            emulator = str(candidate_emulator)
            break

if not avdmanager:
    for candidate in sdk_candidates:
        candidate_avdmanager = Path(candidate["path"]).expanduser() / "cmdline-tools" / "latest" / "bin" / "avdmanager"
        if candidate_avdmanager.exists():
            avdmanager = str(candidate_avdmanager)
            break

devices = adb_devices(adb)
avds = avd_list(emulator)
apps = installed_emulator_apps()
processes = running_emulator_processes()
wetest_env = wetest_env_presence()
compatibility_images = compatibility_system_images(sdk_candidates)

collection_candidates = []
for device in devices.get("devices", []):
    if device["state"] == "device":
        collection_candidates.append({
            "type": "adb-device",
            "serialHash": device["serialHash"],
            "isLikelyEmulator": device["isLikelyEmulator"],
            "nextAction": "Run collect-device-posture.sh and run-installed-sample-logcat-smoke.sh with explicit ADB_SERIAL in a private shell; record only hashes/hints.",
        })

for avd in avds.get("avds", []):
    collection_candidates.append({
        "type": "avd",
        "name": avd,
        "nextAction": "Start this AVD if not running, install sample app, then collect emulator-matrix evidence.",
    })

for app in apps:
    collection_candidates.append({
        "type": "installed-emulator-app",
        "vendor": app["vendor"],
        "appName": app["appName"],
        "nextAction": "Launch manually or via vendor CLI if available, then connect through ADB and collect matrix evidence.",
    })

status = "blocked-no-local-android-environment"
if collection_candidates:
    status = "ready-for-assisted-collection"
elif any(candidate["exists"] for candidate in sdk_candidates) or adb or emulator:
    status = "tooling-present-no-sample-target"

summary = {
    "status": status,
    "reportDir": str(out_dir),
    "secretValuesPrinted": False,
    "rawSerialsPrinted": False,
    "androidSdkCandidates": sdk_candidates,
    "tools": {
        "adb": {"present": bool(adb), "pathHint": str(Path(adb).parent) if adb else ""},
        "emulator": {"present": bool(emulator), "pathHint": str(Path(emulator).parent) if emulator else ""},
        "avdmanager": {"present": bool(avdmanager), "pathHint": str(Path(avdmanager).parent) if avdmanager else ""},
    },
    "adb": devices,
    "avds": avds,
    "installedEmulatorApps": apps,
    "runningEmulatorProcesses": processes,
    "wetestEnvPresence": wetest_env,
    "android6To16SystemImages": compatibility_images,
    "collectionCandidates": collection_candidates,
}

(out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

lines = [
    "# Leona Android Matrix Environment Discovery",
    "",
    f"- status: {status}",
    f"- reportDir: `{out_dir}`",
    "- secret values printed: no",
    "- raw ADB serials printed: no",
    "",
    "## Tooling",
    "",
]
for name, info in summary["tools"].items():
    lines.append(f"- {name}: {'present' if info['present'] else 'missing'}")
for candidate in sdk_candidates:
    if candidate["exists"]:
        lines.append(f"- Android SDK candidate: {candidate['source']} present")

lines.extend(["", "## Targets", ""])
lines.append(f"- ADB ready devices: {sum(1 for d in devices.get('devices', []) if d.get('state') == 'device')}")
lines.append(f"- AVD definitions: {len(avds.get('avds', []))}")
lines.append(f"- Installed emulator apps: {len(apps)}")
lines.append(f"- Running emulator-like processes: {len(processes)}")
lines.append(f"- WeTest/WDB env names present: {len(wetest_env)}")
complete_apis = [row["apiLevel"] for row in compatibility_images if row["complete"]]
incomplete_apis = [row["apiLevel"] for row in compatibility_images if not row["complete"]]
lines.append(f"- Android 6-16 complete Google APIs arm64 images: {len(complete_apis)}/14")
lines.append(f"- Complete image APIs: {', '.join(map(str, complete_apis)) or 'none'}")
lines.append(f"- Missing/incomplete image APIs: {', '.join(map(str, incomplete_apis)) or 'none'}")

if collection_candidates:
    lines.extend(["", "## Collection Candidates", ""])
    for candidate in collection_candidates:
        label = candidate["type"]
        if "vendor" in candidate:
            label += f" / {candidate['vendor']}"
        if "name" in candidate:
            label += f" / {candidate['name']}"
        if "serialHash" in candidate:
            label += f" / serialHash={candidate['serialHash']}"
        lines.append(f"- {label}: {candidate['nextAction']}")
else:
    lines.extend([
        "",
        "## Next Action",
        "",
        "- Install or launch one Android target: Android Studio AVD, MuMu, Genymotion, BlueStacks, Nox, LDPlayer, USB Android device, or WeTest/WDB session.",
        "- Rerun this discovery script, then collect posture/logcat evidence with existing matrix scripts.",
    ])

(out_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"[android-matrix-discovery] {status}: {out_dir / 'summary.md'}")
PY
