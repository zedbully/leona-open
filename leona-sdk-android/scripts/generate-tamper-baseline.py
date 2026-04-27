#!/usr/bin/env python3
#
# Copyright 2026 Leona Contributors.
# Licensed under the Apache License, Version 2.0.
"""Generate a Leona handshake tamper baseline from an APK.

The output is a JSON object that can be used as the server-side
`tamperBaseline` payload for /v1/handshake.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import zipfile
from pathlib import Path
from typing import Iterable


APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
APK_SIG_BLOCK_FOOTER_SIZE = 24
ZIP_EOCD_MIN_SIZE = 22
ZIP_EOCD_MAX_SEARCH = ZIP_EOCD_MIN_SIZE + 65535
ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD = 16
ZIP_EOCD_COMMENT_LENGTH_FIELD = 20
DEX_HEADER_SIZE = 0x70
DEX_MAP_OFFSET_FIELD = 0x34
DEX_FILE_SIZE_FIELD = 0x20
DEX_SECTION_NAMES = {
    0x0000: "header",
    0x0001: "string_ids",
    0x0002: "type_ids",
    0x0003: "proto_ids",
    0x0004: "field_ids",
    0x0005: "method_ids",
    0x0006: "class_defs",
    0x0007: "call_site_ids",
    0x0008: "method_handles",
    0x1000: "map_list",
    0x1001: "type_list",
    0x1002: "annotation_set_ref_list",
    0x1003: "annotation_set_item",
    0x2000: "class_data_item",
    0x2001: "code_item",
    0x2002: "string_data_item",
    0x2003: "debug_info_item",
    0x2004: "annotation_item",
    0x2005: "encoded_array_item",
    0x2006: "annotations_directory_item",
    0xF000: "hiddenapi_class_data_item",
}


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def dex_section_name(section_type: int) -> str:
    return DEX_SECTION_NAMES.get(section_type, f"type_0x{section_type:x}")


def dex_fixed_section_length(section_type: int, count: int) -> int:
    if section_type == 0x0000:
        return DEX_HEADER_SIZE
    if section_type in (0x0001, 0x0002, 0x0007):
        return count * 4
    if section_type in (0x0003,):
        return count * 12
    if section_type in (0x0004, 0x0005, 0x0008):
        return count * 8
    if section_type == 0x0006:
        return count * 32
    if section_type == 0x1000:
        return 4 + count * 12
    if section_type == 0xF000:
        return count
    return -1


def dex_map_items(dex_bytes: bytes) -> list[tuple[int, str, int, int]]:
    if len(dex_bytes) < DEX_HEADER_SIZE or dex_bytes[:3] != b"dex":
        return []
    file_size = struct.unpack_from("<I", dex_bytes, DEX_FILE_SIZE_FIELD)[0]
    map_offset = struct.unpack_from("<I", dex_bytes, DEX_MAP_OFFSET_FIELD)[0]
    if file_size <= 0 or file_size > len(dex_bytes) or map_offset <= 0 or map_offset + 4 > len(dex_bytes):
        return []

    map_count = struct.unpack_from("<I", dex_bytes, map_offset)[0]
    cursor = map_offset + 4
    items: list[tuple[int, str, int, int]] = []
    for _ in range(map_count):
        if cursor + 12 > len(dex_bytes):
            break
        section_type = struct.unpack_from("<H", dex_bytes, cursor)[0]
        count = struct.unpack_from("<I", dex_bytes, cursor + 4)[0]
        offset = struct.unpack_from("<I", dex_bytes, cursor + 8)[0]
        items.append((section_type, dex_section_name(section_type), count, offset))
        cursor += 12
    return items


def dex_section_hashes(dex_bytes: bytes, requested_sections: Iterable[str]) -> dict[str, str]:
    requested = set(requested_sections)
    if not requested:
        return {}
    items = dex_map_items(dex_bytes)
    if not items:
        return {}

    file_size = struct.unpack_from("<I", dex_bytes, DEX_FILE_SIZE_FIELD)[0]
    sorted_offsets = sorted({offset for _, _, _, offset in items if 0 <= offset < file_size})
    result: dict[str, str] = {}
    for section_type, name, count, offset in items:
        if name not in requested:
            continue
        fixed_length = dex_fixed_section_length(section_type, count)
        next_offsets = [candidate for candidate in sorted_offsets if candidate > offset]
        next_offset = next_offsets[0] if next_offsets else file_size
        length = fixed_length if fixed_length > 0 else next_offset - offset
        if offset < 0 or length <= 0 or offset + length > file_size or offset + length > len(dex_bytes):
            result[name] = ""
            continue
        result[name] = sha256_hex(dex_bytes[offset : offset + length])
    return result


def parse_dex_section_request(value: str) -> tuple[str, str]:
    if "#" not in value:
        raise argparse.ArgumentTypeError(
            "DEX section must use ENTRY#SECTION, for example classes.dex#code_item",
        )
    entry, section = (part.strip() for part in value.split("#", 1))
    if not entry or not section:
        raise argparse.ArgumentTypeError(
            "DEX section must use ENTRY#SECTION, for example classes.dex#code_item",
        )
    return entry, section


def zip_entry_hashes(apk: Path, entries: Iterable[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    with zipfile.ZipFile(apk) as archive:
        names = set(archive.namelist())
        for entry in sorted(set(entries)):
            if entry not in names:
                result[entry] = ""
                continue
            result[entry] = sha256_hex(archive.read(entry))
    return result


def resource_inventory_hash(apk: Path) -> str:
    with zipfile.ZipFile(apk) as archive:
        names = sorted(
            name
            for name in archive.namelist()
            if name == "resources.arsc"
            or name.startswith("res/")
            or name.startswith("assets/")
        )
    return sha256_hex("\n".join(names).encode("utf-8")) if names else ""


def find_zip_eocd_offset(data: bytes) -> int | None:
    tail_size = min(len(data), ZIP_EOCD_MAX_SEARCH)
    tail = data[-tail_size:]
    tail_offset = len(data) - tail_size
    for index in range(tail_size - ZIP_EOCD_MIN_SIZE, -1, -1):
        if tail[index : index + 4] != b"PK\x05\x06":
            continue
        comment_length = struct.unpack_from("<H", tail, index + ZIP_EOCD_COMMENT_LENGTH_FIELD)[0]
        if index + ZIP_EOCD_MIN_SIZE + comment_length == tail_size:
            return tail_offset + index
    return None


def read_apk_signing_block(apk: Path) -> bytes | None:
    data = apk.read_bytes()
    eocd_offset = find_zip_eocd_offset(data)
    if eocd_offset is None:
        return None
    central_dir_offset = struct.unpack_from(
        "<I",
        data,
        eocd_offset + ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD,
    )[0]
    if central_dir_offset < APK_SIG_BLOCK_FOOTER_SIZE or central_dir_offset > len(data):
        return None

    footer_offset = central_dir_offset - APK_SIG_BLOCK_FOOTER_SIZE
    if data[footer_offset + 8 : footer_offset + 24] != APK_SIG_BLOCK_MAGIC:
        return None

    block_size = struct.unpack_from("<Q", data, footer_offset)[0]
    total_size = block_size + 8
    block_start = central_dir_offset - total_size
    if block_start < 0 or total_size > len(data):
        return None

    block = data[block_start:central_dir_offset]
    if len(block) != total_size:
        return None
    header_size = struct.unpack_from("<Q", block, 0)[0]
    if header_size != block_size:
        return None
    return block


def signing_block_id_hashes(block: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    cursor = 8
    payload_end = len(block) - APK_SIG_BLOCK_FOOTER_SIZE
    while cursor + 8 <= payload_end:
        pair_size = struct.unpack_from("<Q", block, cursor)[0]
        cursor += 8
        if pair_size < 4 or pair_size > payload_end - cursor:
            break
        signing_block_id = struct.unpack_from("<I", block, cursor)[0]
        value_start = cursor + 4
        value_end = cursor + pair_size
        result[f"0x{signing_block_id:08x}"] = sha256_hex(block[value_start:value_end])
        cursor = value_end
    return dict(sorted(result.items()))


def collect_baseline(args: argparse.Namespace) -> dict[str, object]:
    apk = Path(args.apk).expanduser().resolve()
    if not apk.is_file():
        raise SystemExit(f"APK does not exist: {apk}")

    baseline: dict[str, object] = {}
    if args.package_name:
        baseline["expectedPackageName"] = args.package_name.strip()

    baseline["expectedApkSha256"] = sha256_file(apk)

    signing_block = read_apk_signing_block(apk)
    if signing_block is not None:
        baseline["expectedApkSigningBlockSha256"] = sha256_hex(signing_block)
        id_hashes = signing_block_id_hashes(signing_block)
        if id_hashes:
            baseline["expectedApkSigningBlockIdSha256"] = id_hashes

    with zipfile.ZipFile(apk) as archive:
        names = set(archive.namelist())
        classes_dex = sorted(
            name
            for name in names
            if name.startswith("classes") and name.endswith(".dex")
        )
        resource_entries = sorted(args.resource_entry)
        if args.all_resource_entries:
            resource_entries = sorted(
                name
                for name in names
                if name.startswith("res/") or name.startswith("assets/")
            )

        dex_sections_by_entry: dict[str, set[str]] = {}
        for entry, section in args.dex_section:
            dex_sections_by_entry.setdefault(entry, set()).add(section)
        if args.all_dex_sections:
            for entry in classes_dex:
                for _, section, _, _ in dex_map_items(archive.read(entry)):
                    dex_sections_by_entry.setdefault(entry, set()).add(section)

    entry_hashes = zip_entry_hashes(
        apk,
        ["AndroidManifest.xml", "resources.arsc", *classes_dex, *resource_entries],
    )
    if "AndroidManifest.xml" in entry_hashes:
        baseline["expectedManifestEntrySha256"] = entry_hashes["AndroidManifest.xml"]
    if "resources.arsc" in entry_hashes:
        baseline["expectedResourcesArscSha256"] = entry_hashes["resources.arsc"]

    inventory_hash = resource_inventory_hash(apk)
    if inventory_hash:
        baseline["expectedResourceInventorySha256"] = inventory_hash

    dex_hashes = {
        name: digest
        for name, digest in entry_hashes.items()
        if name.startswith("classes") and name.endswith(".dex") and digest
    }
    if dex_hashes:
        baseline["expectedDexSha256"] = dex_hashes

    dex_section_hashes_by_key: dict[str, str] = {}
    if dex_sections_by_entry:
        with zipfile.ZipFile(apk) as archive:
            for entry_name in sorted(dex_sections_by_entry):
                if entry_name not in archive.namelist():
                    continue
                hashes = dex_section_hashes(
                    archive.read(entry_name),
                    dex_sections_by_entry[entry_name],
                )
                for section_name in sorted(dex_sections_by_entry[entry_name]):
                    digest = hashes.get(section_name, "")
                    if digest:
                        dex_section_hashes_by_key[f"{entry_name}#{section_name}"] = digest
    if dex_section_hashes_by_key:
        baseline["expectedDexSectionSha256"] = dex_section_hashes_by_key

    resource_hashes = {
        name: digest
        for name, digest in entry_hashes.items()
        if (name.startswith("res/") or name.startswith("assets/")) and digest
    }
    if resource_hashes:
        baseline["expectedResourceEntrySha256"] = resource_hashes

    return baseline


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a Leona tamperBaseline JSON object from an APK.",
    )
    parser.add_argument("apk", help="Path to the APK to fingerprint.")
    parser.add_argument(
        "--package-name",
        help="Optional expected package name to include in the baseline.",
    )
    parser.add_argument(
        "--resource-entry",
        action="append",
        default=[],
        help="Specific res/... or assets/... zip entry to include. May be repeated.",
    )
    parser.add_argument(
        "--all-resource-entries",
        action="store_true",
        help="Include hashes for every res/... and assets/... zip entry.",
    )
    parser.add_argument(
        "--dex-section",
        action="append",
        default=[],
        type=parse_dex_section_request,
        help=(
            "Specific DEX section to include as ENTRY#SECTION, for example "
            "classes.dex#code_item. May be repeated."
        ),
    )
    parser.add_argument(
        "--all-dex-sections",
        action="store_true",
        help="Include hashes for every section listed in every classes*.dex map.",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Emit compact single-line JSON.",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    baseline = collect_baseline(args)
    if args.compact:
        print(json.dumps(baseline, sort_keys=True, separators=(",", ":")))
    else:
        print(json.dumps(baseline, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
