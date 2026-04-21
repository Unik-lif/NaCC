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
PT_INTERP = 3
PF_X = 0x1
PF_W = 0x2
PF_R = 0x4


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

    return ElfInfo(
        elf_class=elf_class,
        endianness=endianness,
        elf_type=e_type,
        machine=e_machine,
        entry=e_entry,
        program_header_count=e_phnum,
        interp_path=interp_path,
        loads=loads,
    )


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
        if search_roots:
            for root in search_roots:
                add_candidate(root / interp_path.lstrip("/"))
        else:
            add_candidate(Path(interp_path))
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


def build_object(role: str, requested_path: str, resolved_path: Path) -> dict[str, object]:
    elf_info = parse_elf(resolved_path)
    return {
        "role": role,
        "requested_path": requested_path,
        "resolved_path": str(resolved_path),
        "elf": elf_info.to_dict(),
        "pt_loads": [segment.to_dict() for segment in elf_info.loads],
    }


def render_manifest(entry_arg: str, entry_path: Path, search_roots: list[Path]) -> dict[str, object]:
    entry_elf = parse_elf(entry_path)

    objects = [build_object("entry", entry_arg, entry_path)]
    interp_resolved_path: Path | None = None

    if entry_elf.interp_path is not None:
        interp_resolved_path = resolve_interp_path(entry_elf.interp_path, entry_path, search_roots)
        objects.append(build_object("interp", entry_elf.interp_path, interp_resolved_path))

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
