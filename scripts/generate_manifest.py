#!/usr/bin/env python3
"""Generate a minimal NaCC startup manifest from an entry ELF."""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

EI_NIDENT = 16
ELF_MAGIC = b"\x7fELF"
ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1
ELFDATA2MSB = 2
ET_NAMES = {
    0: "ET_NONE",
    1: "ET_REL",
    2: "ET_EXEC",
    3: "ET_DYN",
    4: "ET_CORE",
}
EM_NAMES = {
    3: "EM_386",
    40: "EM_ARM",
    62: "EM_X86_64",
    183: "EM_AARCH64",
    243: "EM_RISCV",
}
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_STRSZ = 10
PF_X = 0x1
PF_W = 0x2
PF_R = 0x4
OBJECT_ID_ENTRY = 1
OBJECT_ID_INTERP = 2
OBJECT_ID_DSO_BASE = 16


class ManifestError(RuntimeError):
    """Raised when the input ELF cannot be converted into the MVP manifest."""


@dataclass(frozen=True)
class LoadSegment:
    index: int
    offset: int
    vaddr: int
    filesz: int
    memsz: int
    align: int
    flags: int

    def to_dict(self) -> dict[str, object]:
        return {
            "program_header_index": self.index,
            "offset": self.offset,
            "vaddr": self.vaddr,
            "filesz": self.filesz,
            "memsz": self.memsz,
            "align": self.align,
            "flags": {
                "raw": self.flags,
                "perm": "".join(
                    [
                        "r" if self.flags & PF_R else "-",
                        "w" if self.flags & PF_W else "-",
                        "x" if self.flags & PF_X else "-",
                    ]
                ),
                "read": bool(self.flags & PF_R),
                "write": bool(self.flags & PF_W),
                "execute": bool(self.flags & PF_X),
            },
        }


@dataclass(frozen=True)
class ElfInfo:
    elf_class: str
    endianness: str
    elf_type: int
    machine: int
    entry: int
    program_header_count: int
    interp_path: str | None
    needed: list[str]
    loads: list[LoadSegment]

    def to_dict(self) -> dict[str, object]:
        return {
            "class": self.elf_class,
            "endianness": self.endianness,
            "type": {
                "id": self.elf_type,
                "name": ET_NAMES.get(self.elf_type, f"ET_{self.elf_type}"),
            },
            "machine": {
                "id": self.machine,
                "name": EM_NAMES.get(self.machine, f"EM_{self.machine}"),
            },
            "entry": self.entry,
            "program_header_count": self.program_header_count,
            "interp_path": self.interp_path,
            "needed": self.needed,
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate a minimal manifest.json for the chosen entry ELF plus its "
            "PT_INTERP-resolved interpreter object when present."
        )
    )
    parser.add_argument("entry", help="Path to the entry ELF to inspect")
    parser.add_argument(
        "-o",
        "--output",
        default="manifest.json",
        help="Manifest output path, or '-' for stdout (default: manifest.json)",
    )
    parser.add_argument(
        "--search-root",
        action="append",
        default=[],
        help=(
            "Directory used to resolve absolute PT_INTERP paths. "
            "May be repeated."
        ),
    )
    return parser.parse_args()


def read_c_string(blob: bytes) -> str:
    return blob.split(b"\0", 1)[0].decode("utf-8")


def parse_elf(path: Path) -> ElfInfo:
    data = path.read_bytes()
    if len(data) < EI_NIDENT:
        raise ManifestError(f"{path}: file is too small to be an ELF")

    ident = data[:EI_NIDENT]
    if ident[:4] != ELF_MAGIC:
        raise ManifestError(f"{path}: not an ELF file")

    elf_class_id = ident[4]
    data_encoding = ident[5]

    if elf_class_id == ELFCLASS64:
        elf_class = "ELF64"
        header_fmt = "HHIQQQIHHHHHH"
        phdr_fmt = "IIQQQQQQ"
    elif elf_class_id == ELFCLASS32:
        elf_class = "ELF32"
        header_fmt = "HHIIIIIHHHHHH"
        phdr_fmt = "IIIIIIII"
    else:
        raise ManifestError(f"{path}: unsupported ELF class {elf_class_id}")

    if data_encoding == ELFDATA2LSB:
        endianness = "little"
        endian_prefix = "<"
    elif data_encoding == ELFDATA2MSB:
        endianness = "big"
        endian_prefix = ">"
    else:
        raise ManifestError(f"{path}: unsupported ELF data encoding {data_encoding}")

    header_size = struct.calcsize(endian_prefix + header_fmt)
    if len(data) < EI_NIDENT + header_size:
        raise ManifestError(f"{path}: truncated ELF header")

    header = struct.unpack_from(endian_prefix + header_fmt, data, EI_NIDENT)
    e_type = header[0]
    e_machine = header[1]
    e_entry = header[3]
    e_phoff = header[4]
    e_phentsize = header[8]
    e_phnum = header[9]

    if e_phnum == 0:
        raise ManifestError(f"{path}: ELF has no program headers")

    phdr_size = struct.calcsize(endian_prefix + phdr_fmt)
    if e_phentsize < phdr_size:
        raise ManifestError(
            f"{path}: program header entry size {e_phentsize} is smaller than expected {phdr_size}"
        )

    loads: list[LoadSegment] = []
    dynamics: list[tuple[int, int]] = []
    interp_path: str | None = None

    for index in range(e_phnum):
        phdr_offset = e_phoff + index * e_phentsize
        if phdr_offset + phdr_size > len(data):
            raise ManifestError(f"{path}: truncated program header table")

        phdr = struct.unpack_from(endian_prefix + phdr_fmt, data, phdr_offset)
        if elf_class_id == ELFCLASS64:
            p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_align = phdr
        else:
            p_type, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_flags, p_align = phdr

        if p_type == PT_INTERP:
            if interp_path is not None:
                raise ManifestError(f"{path}: multiple PT_INTERP headers are not supported")
            interp_end = p_offset + p_filesz
            if interp_end > len(data):
                raise ManifestError(f"{path}: PT_INTERP points past the end of file")
            interp_path = read_c_string(data[p_offset:interp_end])

        if p_type == PT_DYNAMIC:
            dynamics.append((p_offset, p_filesz))

        if p_type == PT_LOAD:
            loads.append(
                LoadSegment(
                    index=index,
                    offset=p_offset,
                    vaddr=p_vaddr,
                    filesz=p_filesz,
                    memsz=p_memsz,
                    align=p_align,
                    flags=p_flags,
                )
            )

    if not loads:
        raise ManifestError(f"{path}: ELF has no PT_LOAD headers")

    needed = parse_dynamic_needed(path, data, elf_class_id, endian_prefix, loads, dynamics)

    return ElfInfo(
        elf_class=elf_class,
        endianness=endianness,
        elf_type=e_type,
        machine=e_machine,
        entry=e_entry,
        program_header_count=e_phnum,
        interp_path=interp_path,
        needed=needed,
        loads=loads,
    )


def vaddr_to_file_offset(loads: list[LoadSegment], vaddr: int) -> int | None:
    for load in loads:
        start = load.vaddr
        end = load.vaddr + load.filesz
        if start <= vaddr < end:
            return load.offset + (vaddr - start)
    return None


def read_dyn_c_string(data: bytes, offset: int, limit: int) -> str:
    if offset < 0 or offset >= len(data) or offset >= limit:
        raise ManifestError("dynamic string offset is outside the ELF image")
    end = data.find(b"\0", offset, limit)
    if end < 0:
        raise ManifestError("unterminated dynamic string")
    return data[offset:end].decode("utf-8")


def parse_dynamic_needed(
    path: Path,
    data: bytes,
    elf_class_id: int,
    endian_prefix: str,
    loads: list[LoadSegment],
    dynamics: list[tuple[int, int]],
) -> list[str]:
    if not dynamics:
        return []
    if len(dynamics) > 1:
        raise ManifestError(f"{path}: multiple PT_DYNAMIC headers are not supported")

    if elf_class_id == ELFCLASS64:
        dyn_fmt = "QQ"
    else:
        dyn_fmt = "II"
    dyn_size = struct.calcsize(endian_prefix + dyn_fmt)
    dyn_offset, dyn_filesz = dynamics[0]
    dyn_end = dyn_offset + dyn_filesz
    if dyn_end > len(data):
        raise ManifestError(f"{path}: PT_DYNAMIC points past the end of file")

    needed_offsets: list[int] = []
    strtab_vaddr: int | None = None
    strtab_size: int | None = None

    for offset in range(dyn_offset, dyn_end, dyn_size):
        if offset + dyn_size > dyn_end:
            raise ManifestError(f"{path}: truncated PT_DYNAMIC entry")
        tag, val = struct.unpack_from(endian_prefix + dyn_fmt, data, offset)
        if tag == DT_NULL:
            break
        if tag == DT_NEEDED:
            needed_offsets.append(val)
        elif tag == DT_STRTAB:
            strtab_vaddr = val
        elif tag == DT_STRSZ:
            strtab_size = val

    if not needed_offsets:
        return []
    if strtab_vaddr is None or strtab_size is None:
        raise ManifestError(f"{path}: DT_NEEDED entries require DT_STRTAB and DT_STRSZ")

    strtab_file_offset = vaddr_to_file_offset(loads, strtab_vaddr)
    if strtab_file_offset is None:
        raise ManifestError(f"{path}: DT_STRTAB virtual address is not file-backed")
    if strtab_file_offset + strtab_size > len(data):
        raise ManifestError(f"{path}: dynamic string table points past the end of file")

    return [
        read_dyn_c_string(data, strtab_file_offset + needed, strtab_file_offset + strtab_size)
        for needed in needed_offsets
    ]


def resolve_existing_file(path_str: str, purpose: str) -> Path:
    path = Path(path_str)
    if not path.exists():
        raise ManifestError(f"{purpose}: {path} does not exist")
    if not path.is_file():
        raise ManifestError(f"{purpose}: {path} is not a regular file")
    return path.resolve()


def resolve_search_roots(search_roots: list[str]) -> list[Path]:
    resolved: list[Path] = []
    for root_str in search_roots:
        root = Path(root_str)
        if not root.exists():
            raise ManifestError(f"search root does not exist: {root}")
        if not root.is_dir():
            raise ManifestError(f"search root is not a directory: {root}")
        resolved.append(root.resolve())
    return resolved


def resolve_interp_path(
    interp_path: str,
    entry_path: Path,
    search_roots: list[Path],
) -> Path:
    candidates: list[Path] = []
    seen: set[Path] = set()

    def add_candidate(candidate: Path) -> None:
        if candidate in seen:
            return
        seen.add(candidate)
        candidates.append(candidate)

    if os.path.isabs(interp_path):
        if not search_roots:
            raise ManifestError(
                "absolute PT_INTERP path "
                f"{interp_path!r} from entry {entry_path} requires at least one explicit "
                "--search-root"
            )
        for root in search_roots:
            add_candidate(root / interp_path.lstrip("/"))
    else:
        add_candidate(entry_path.parent / interp_path)
        for root in search_roots:
            add_candidate(root / interp_path)

    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()

    candidate_text = ", ".join(str(candidate) for candidate in candidates) or "<none>"
    raise ManifestError(
        "failed to resolve PT_INTERP path "
        f"{interp_path!r} from entry {entry_path}; tried: {candidate_text}"
    )


def resolve_needed_path(name: str, entry_path: Path, search_roots: list[Path]) -> Path:
    candidates: list[Path] = []
    seen: set[Path] = set()
    lib_dirs = (
        "",
        "lib",
        "usr/lib",
        "lib64",
        "usr/lib64",
        "lib/riscv64-linux-gnu",
        "usr/lib/riscv64-linux-gnu",
        "lib/x86_64-linux-gnu",
        "usr/lib/x86_64-linux-gnu",
    )

    def add_candidate(candidate: Path) -> None:
        if candidate in seen:
            return
        seen.add(candidate)
        candidates.append(candidate)

    if os.path.isabs(name):
        if not search_roots:
            raise ManifestError(
                f"absolute DT_NEEDED path {name!r} requires at least one explicit --search-root"
            )
        for root in search_roots:
            add_candidate(root / name.lstrip("/"))
    else:
        add_candidate(entry_path.parent / name)
        for root in search_roots:
            for lib_dir in lib_dirs:
                add_candidate(root / lib_dir / name)

    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()

    candidate_text = ", ".join(str(candidate) for candidate in candidates) or "<none>"
    raise ManifestError(f"failed to resolve DT_NEEDED {name!r}; tried: {candidate_text}")


def build_object(
    role: str, object_id: int, requested_path: str, resolved_path: Path
) -> dict[str, object]:
    elf_info = parse_elf(resolved_path)
    return {
        "role": role,
        "object_id": object_id,
        "requested_path": requested_path,
        "resolved_path": str(resolved_path),
        "elf": elf_info.to_dict(),
        "pt_loads": [segment.to_dict() for segment in elf_info.loads],
    }


def render_manifest(entry_arg: str, entry_path: Path, search_roots: list[Path]) -> dict[str, object]:
    entry_elf = parse_elf(entry_path)

    objects = [build_object("entry", OBJECT_ID_ENTRY, entry_arg, entry_path)]
    seen_paths = {entry_path}
    interp_resolved_path: Path | None = None

    if entry_elf.interp_path is not None:
        interp_resolved_path = resolve_interp_path(entry_elf.interp_path, entry_path, search_roots)
        objects.append(
            build_object("interp", OBJECT_ID_INTERP, entry_elf.interp_path, interp_resolved_path)
        )
        seen_paths.add(interp_resolved_path)

    dso_objects = []
    for needed_index, needed in enumerate(entry_elf.needed):
        resolved = resolve_needed_path(needed, entry_path, search_roots)
        if resolved in seen_paths:
            continue
        seen_paths.add(resolved)
        dso_objects.append(
            build_object("dso", OBJECT_ID_DSO_BASE + needed_index, needed, resolved)
        )
    objects.extend(dso_objects)

    return {
        "schema": "nacc-manifest-v1alpha1",
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "generator": "scripts/generate_manifest.py",
        "resolution_roots": [str(root) for root in search_roots],
        "entry": {
            "input_path": entry_arg,
            "resolved_path": str(entry_path),
            "interp_path": entry_elf.interp_path,
            "interp_resolved_path": str(interp_resolved_path) if interp_resolved_path else None,
            "initial_dso_count": len(dso_objects),
        },
        "objects": objects,
    }


def write_manifest(output_path: str, manifest: dict[str, object]) -> None:
    payload = json.dumps(manifest, indent=2, sort_keys=True)
    if output_path == "-":
        sys.stdout.write(payload)
        sys.stdout.write("\n")
        return

    output = Path(output_path)
    if output.parent != Path("."):
        output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(payload + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()

    try:
        search_roots = resolve_search_roots(args.search_root)
        entry_path = resolve_existing_file(args.entry, "entry ELF")
        manifest = render_manifest(args.entry, entry_path, search_roots)
        write_manifest(args.output, manifest)
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
