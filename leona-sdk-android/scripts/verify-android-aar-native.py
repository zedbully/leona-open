#!/usr/bin/env python3
"""Fail-closed inventory verifier for the public Android SDK AAR native payload.

The verifier is deliberately an inventory gate, not a release or device-admission
decision. It consumes an already-built AAR, validates its ZIP and ELF structure,
and emits only content hashes, sizes, ABI names, JNI exports, and dependencies.
Leo provider artifacts are intentionally not part of this public AAR.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ALLOWED_ABIS = {"arm64-v8a", "armeabi-v7a", "x86_64"}
EXPECTED_JNI_EXPORTS = {
    "Java_io_leonasec_leona_internal_runtime_OssNativeRuntime_collect",
    "Java_io_leonasec_leona_internal_runtime_OssNativeRuntime_decoyCheck",
    "Java_io_leonasec_leona_internal_runtime_OssNativeRuntime_honeypotFakeKey",
    "Java_io_leonasec_leona_internal_runtime_OssNativeRuntime_honeypotFakeToken",
    "Java_io_leonasec_leona_internal_runtime_OssNativeRuntime_init",
    "Java_io_leonasec_leona_internal_runtime_OssNativeRuntime_updateTamperContext",
}
ALLOWED_NEEDED = {"libc.so", "libdl.so", "liblog.so", "libm.so"}
MAX_ENTRY_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_ELF_BYTES = 8 * 1024 * 1024
PROVIDER_STATUS = "PROVIDER_ARTIFACT_NOT_INCLUDED"
ABSOLUTE_PATH_RE = re.compile(rb"(?:^|[\x00\s])/(?:Users|home|private|var|tmp)/")
WINDOWS_PATH_RE = re.compile(rb"(?:^|[\x00\s])[A-Za-z]:[\\/]")
SECRET_MARKER_RE = re.compile(
    rb"(?i)(?:-----BEGIN\s+(?:RSA|EC|OPENSSH|DSA|PRIVATE)\s+KEY-----|"
    rb"\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}|"
    rb"\b(?:api[_-]?key|access[_-]?token|secret[_-]?key)\s*[:=]\s*[A-Za-z0-9._~+/=-]{16,})"
)


class InventoryError(ValueError):
    """A malformed or unadmitted archive/native artifact."""


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_c_string(data: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(data):
        raise InventoryError("ELF string offset out of bounds")
    end = data.find(b"\0", offset)
    if end < 0:
        raise InventoryError("unterminated ELF string")
    try:
        return data[offset:end].decode("ascii")
    except UnicodeDecodeError as error:
        raise InventoryError("non-ASCII ELF string") from error


@dataclass(frozen=True)
class ProgramHeader:
    kind: int
    flags: int
    offset: int
    virtual_address: int
    file_size: int


@dataclass(frozen=True)
class Section:
    name: str
    kind: int
    offset: int
    size: int
    entry_size: int
    link: int


@dataclass(frozen=True)
class ElfInventory:
    elf_class: int
    machine: int
    needed: tuple[str, ...]
    soname: str | None
    jni_exports: tuple[str, ...]
    has_debug_symbols: bool
    has_rpath: bool
    has_runpath: bool
    has_textrel: bool
    has_exec_stack: bool


def _unpack(fmt: str, data: bytes, offset: int) -> tuple[int, ...]:
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise InventoryError("ELF structure out of bounds")
    return struct.unpack_from(fmt, data, offset)


def _parse_elf(data: bytes) -> ElfInventory:
    if len(data) < 20 or data[:4] != b"\x7fELF":
        raise InventoryError("not an ELF shared object")
    elf_class, endian = data[4], data[5]
    if elf_class not in (1, 2) or endian != 1:
        raise InventoryError("ELF must be little-endian ELF32 or ELF64")
    if elf_class == 1:
        header = _unpack("<16sHHIIIIIHHHHHH", data, 0)
        _, elf_type, machine, _, _, phoff, shoff, _, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = header
        ph_fmt, sh_fmt = "<IIIIIIII", "<IIIIIIIIII"
    else:
        header = _unpack("<16sHHIQQQIHHHHHH", data, 0)
        _, elf_type, machine, _, _, phoff, shoff, _, ehsize, phentsize, phnum, shentsize, shnum, shstrndx = header
        ph_fmt, sh_fmt = "<IIQQQQQQ", "<IIQQQQIIQQ"
    if elf_type != 3:
        raise InventoryError("ELF is not a shared object")
    if phnum > 128 or shnum > 4096:
        raise InventoryError("ELF header table count exceeds bound")

    phdrs: list[ProgramHeader] = []
    for index in range(phnum):
        fields = _unpack(ph_fmt, data, phoff + index * phentsize)
        if elf_class == 1:
            kind, offset, vaddr, _, filesz, _, flags, _ = fields
        else:
            kind, flags, offset, vaddr, _, filesz, _, _ = fields
        if offset + filesz > len(data):
            raise InventoryError("ELF program segment exceeds file")
        phdrs.append(ProgramHeader(kind, flags, offset, vaddr, filesz))

    def virtual_to_file(address: int) -> int:
        for segment in phdrs:
            if segment.kind == 1 and segment.virtual_address <= address < segment.virtual_address + segment.file_size:
                return segment.offset + address - segment.virtual_address
        raise InventoryError("ELF virtual address is not file-backed")

    sections: list[Section] = []
    raw_sections: list[tuple[int, ...]] = []
    for index in range(shnum):
        fields = _unpack(sh_fmt, data, shoff + index * shentsize)
        raw_sections.append(fields)
    if shstrndx >= len(raw_sections):
        raise InventoryError("invalid ELF section-name table")
    name_section = raw_sections[shstrndx]
    if elf_class == 1:
        name_offset, _, _, _, name_file_offset, name_size, _, _, _, _ = name_section
    else:
        name_offset, _, _, _, name_file_offset, name_size, _, _, _, _ = name_section
    del name_offset
    if name_file_offset + name_size > len(data):
        raise InventoryError("ELF section-name table exceeds file")
    names = data[name_file_offset : name_file_offset + name_size]
    for fields in raw_sections:
        if elf_class == 1:
            name_index, kind, _, _, offset, size, link, _, _, entry_size = fields
        else:
            name_index, kind, _, _, offset, size, link, _, _, entry_size = fields
        if offset + size > len(data) and kind != 8:  # SHT_NOBITS has no file bytes.
            raise InventoryError("ELF section exceeds file")
        section_name = _read_c_string(names, name_index) if name_index < len(names) else ""
        sections.append(Section(section_name, kind, offset, size, entry_size, link))

    dynamic_tags: dict[int, list[int]] = {}
    for segment in phdrs:
        if segment.kind != 2:
            continue
        entry_fmt = "<II" if elf_class == 1 else "<QQ"
        entry_size = struct.calcsize(entry_fmt)
        if segment.file_size % entry_size:
            raise InventoryError("ELF dynamic segment has a partial entry")
        for offset in range(segment.offset, segment.offset + segment.file_size, entry_size):
            tag, value = _unpack(entry_fmt, data, offset)
            dynamic_tags.setdefault(tag, []).append(value)
            if tag == 0:
                break

    dynstr_address = dynamic_tags.get(5, [None])[0]
    dynstr = b""
    if dynstr_address is not None:
        dynstr_offset = virtual_to_file(dynstr_address)
        dynstr_size = dynamic_tags.get(10, [len(data) - dynstr_offset])[0]
        if dynstr_size > MAX_ENTRY_BYTES or dynstr_offset + dynstr_size > len(data):
            raise InventoryError("ELF dynamic string table exceeds bound")
        dynstr = data[dynstr_offset : dynstr_offset + dynstr_size]

    def dynamic_string(tag: int) -> str | None:
        values = dynamic_tags.get(tag, [])
        if not values:
            return None
        return _read_c_string(dynstr, values[0])

    needed = tuple(_read_c_string(dynstr, value) for value in dynamic_tags.get(1, []))
    dynsym = next((section for section in sections if section.kind == 11), None)
    jni_exports: list[str] = []
    if dynsym is not None:
        if dynsym.entry_size == 0:
            raise InventoryError("ELF dynamic symbol table has no entry size")
        linked_strtab = sections[dynsym.link] if dynsym.link < len(sections) else None
        if linked_strtab is None or linked_strtab.kind != 3:
            raise InventoryError("ELF dynamic symbol table has no string table")
        strtab = data[linked_strtab.offset : linked_strtab.offset + linked_strtab.size]
        for offset in range(dynsym.offset, dynsym.offset + dynsym.size, dynsym.entry_size):
            if offset + dynsym.entry_size > len(data):
                raise InventoryError("ELF dynamic symbol exceeds file")
            if elf_class == 1:
                name_index, _, _, info, other, section_index, *_ = _unpack("<IIIBBH", data, offset)
            else:
                name_index, info, other, section_index, *_ = _unpack("<IBBHQQ", data, offset)
            if section_index == 0 or (info >> 4) not in (1, 2) or (other & 3) != 0 or name_index >= len(strtab):
                continue
            name = _read_c_string(strtab, name_index)
            if name.startswith("Java_"):
                jni_exports.append(name)

    debug_symbols = any(section.name.startswith(".debug") or section.name in {".symtab", ".strtab"} for section in sections)
    return ElfInventory(
        elf_class=elf_class,
        machine=machine,
        needed=tuple(sorted(needed)),
        soname=dynamic_string(14),
        jni_exports=tuple(sorted(jni_exports)),
        has_debug_symbols=debug_symbols,
        has_rpath=15 in dynamic_tags,
        has_runpath=29 in dynamic_tags,
        has_textrel=22 in dynamic_tags,
        has_exec_stack=any(segment.kind == 0x6474E551 and (segment.flags & 1) != 0 for segment in phdrs),
    )


def _tool(path: str | None, name: str) -> str:
    if path:
        return path
    ndk = os.environ.get("ANDROID_NDK_ROOT") or os.environ.get("ANDROID_NDK_HOME")
    if not ndk:
        android_home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
        if android_home:
            candidates = sorted(Path(android_home, "ndk").glob("*/toolchains/llvm/prebuilt/*/bin"))
            if candidates:
                ndk = str(candidates[-1].parent.parent.parent.parent)
    if ndk:
        candidates = sorted(Path(ndk).glob("toolchains/llvm/prebuilt/*/bin/" + name))
        if candidates:
            return str(candidates[-1])
        direct = Path(ndk, "toolchains/llvm/prebuilt/darwin-x86_64/bin", name)
        if direct.is_file():
            return str(direct)
    resolved = shutil.which(name)
    if resolved:
        return resolved
    raise InventoryError(f"required native inspection tool unavailable: {name}")


def _authority_check(so_path: Path, info: ElfInventory, readelf: str, nm: str) -> None:
    try:
        read = subprocess.run(
            [readelf, "-h", "-l", "-d", "-S", so_path.as_posix()],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        symbols = subprocess.run(
            [nm, "-D", "--defined-only", so_path.as_posix()],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise InventoryError("native inspection tool failed") from error
    if read.returncode != 0 or symbols.returncode != 0:
        raise InventoryError("native inspection tool rejected ELF")
    text = read.stdout + read.stderr
    if "(RPATH)" in text or "(RUNPATH)" in text or "(TEXTREL)" in text or re.search(r"GNU_STACK\s+.*RWE", text):
        raise InventoryError("ELF contains forbidden dynamic hardening state")
    authority_exports = sorted(
        line.split()[-1]
        for line in symbols.stdout.splitlines()
        if len(line.split()) >= 3 and line.split()[-1].startswith("Java_")
    )
    if authority_exports != list(info.jni_exports):
        raise InventoryError("ELF JNI export inventory disagrees with llvm-nm")


def _validate_zip_name(name: str) -> None:
    if not name or "\x00" in name or "\\" in name or name.startswith("/"):
        raise InventoryError("unsafe AAR ZIP path")
    parts = name.rstrip("/").split("/")
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise InventoryError("non-canonical AAR ZIP path")


def verify_aar(aar: Path, *, llvm_readelf: str | None = None, llvm_nm: str | None = None) -> dict:
    if not aar.is_file() or aar.stat().st_size > MAX_ARCHIVE_BYTES:
        raise InventoryError("AAR is missing or exceeds archive bound")
    try:
        archive_data = aar.read_bytes()
        with zipfile.ZipFile(aar) as archive:
            entries = archive.infolist()
            seen: set[str] = set()
            total_uncompressed = 0
            for entry in entries:
                _validate_zip_name(entry.filename)
                if entry.filename in seen:
                    raise InventoryError("duplicate AAR ZIP entry")
                seen.add(entry.filename)
                mode = (entry.external_attr >> 16) & 0o170000
                if mode == 0o120000:
                    raise InventoryError("symlink AAR ZIP entry")
                if entry.file_size > MAX_ENTRY_BYTES or entry.compress_size > MAX_ENTRY_BYTES:
                    raise InventoryError("AAR ZIP entry exceeds stored/extracted bound")
                total_uncompressed += entry.file_size
                if total_uncompressed > MAX_ARCHIVE_BYTES:
                    raise InventoryError("AAR extracted size exceeds bound")
            native_entries = [
                entry for entry in entries if entry.filename.startswith("jni/") and not entry.filename.endswith("/")
            ]
            expected_paths = {f"jni/{abi}/libleona.so" for abi in ALLOWED_ABIS}
            actual_paths = {entry.filename for entry in native_entries}
            if actual_paths != expected_paths:
                raise InventoryError("AAR ABI/native entry set is not exact")
            readelf = _tool(llvm_readelf, "llvm-readelf")
            nm = _tool(llvm_nm, "llvm-nm")
            inventories: list[dict] = []
            for abi in sorted(ALLOWED_ABIS):
                path = f"jni/{abi}/libleona.so"
                data = archive.read(path)
                if len(data) > MAX_ELF_BYTES:
                    raise InventoryError("native ELF exceeds bound")
                if ABSOLUTE_PATH_RE.search(data) or WINDOWS_PATH_RE.search(data) or SECRET_MARKER_RE.search(data):
                    raise InventoryError("native ELF contains path or secret material")
                info = _parse_elf(data)
                expected_class_machine = {
                    "arm64-v8a": (2, 183),
                    "armeabi-v7a": (1, 40),
                    "x86_64": (2, 62),
                }[abi]
                if (info.elf_class, info.machine) != expected_class_machine:
                    raise InventoryError(f"{abi} ELF class/machine mismatch")
                if info.soname != "libleona.so":
                    raise InventoryError(f"{abi} SONAME mismatch")
                if set(info.needed) - ALLOWED_NEEDED or len(info.needed) != len(set(info.needed)):
                    raise InventoryError(f"{abi} DT_NEEDED is not allowlisted")
                if set(info.jni_exports) != EXPECTED_JNI_EXPORTS:
                    raise InventoryError(f"{abi} JNI export allowlist mismatch")
                if info.has_debug_symbols or info.has_rpath or info.has_runpath or info.has_textrel or info.has_exec_stack:
                    raise InventoryError(f"{abi} ELF hardening/debug check failed")
                # llvm-readelf/nm are the authority for built artifacts; the pure
                # parser above gives deterministic fixture coverage and a second
                # independent structural check.
                with tempfile.NamedTemporaryFile(prefix="leona-native-", suffix=".so") as temp_file:
                    temp_file.write(data)
                    temp_file.flush()
                    _authority_check(Path(temp_file.name), info, readelf, nm)
                inventories.append(
                    {
                        "abi": abi,
                        "sha256": _sha256(data),
                        "size": len(data),
                        "exports": list(info.jni_exports),
                        "needed": list(info.needed),
                    }
                )
    except (OSError, zipfile.BadZipFile, KeyError) as error:
        raise InventoryError("AAR ZIP cannot be safely inspected") from error
    return {
        "schemaVersion": 1,
        "aarSha256": _sha256(archive_data),
        "aarSize": len(archive_data),
        "providerStatus": PROVIDER_STATUS,
        "abis": inventories,
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("aar", type=Path)
    parser.add_argument("--llvm-readelf")
    parser.add_argument("--llvm-nm")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        inventory = verify_aar(args.aar, llvm_readelf=args.llvm_readelf, llvm_nm=args.llvm_nm)
    except InventoryError as error:
        print(f"native AAR verification failed: {error}", file=sys.stderr)
        return 1
    rendered = json.dumps(inventory, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
