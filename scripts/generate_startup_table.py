#!/usr/bin/env python3
"""Derive a compact NaCC startup table from manifest.json."""

from __future__ import annotations

import argparse
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

PAGE_SIZE = 4096
TABLE_MAGIC = b"NSTRTBL1"
TABLE_VERSION = 1
ROLE_IDS = {
    "entry": 1,
    "interp": 2,
}


class StartupTableError(RuntimeError):
    """Raised when the manifest cannot be translated into a startup table."""


@dataclass(frozen=True)
class StartupRecord:
    role_name: str
    role_id: int
    program_header_index: int
    page_offset: int
    page_size: int
    flags_raw: int

    def pack(self) -> bytes:
        return struct.pack(
            "<IIQQII",
            self.role_id,
            self.program_header_index,
            self.page_offset,
            self.page_size,
            self.flags_raw,
            0,
        )


def align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Translate a PR1-style NaCC manifest.json into a compact startup-only "
            "table for the current entry/interp PT_LOAD set."
        )
    )
    parser.add_argument("manifest", help="Path to the manifest.json to translate")
    parser.add_argument(
        "-o",
        "--output",
        default="startup_table.bin",
        help="Startup table output path (default: startup_table.bin)",
    )
    return parser.parse_args()


def resolve_existing_file(path: Path, purpose: str) -> Path:
    if not path.exists():
        raise StartupTableError(f"{purpose} does not exist: {path}")
    if not path.is_file():
        raise StartupTableError(f"{purpose} is not a regular file: {path}")
    return path.resolve()


def require_int(value: object, field: str) -> int:
    if not isinstance(value, int):
        raise StartupTableError(f"{field} must be an integer, got {type(value).__name__}")
    return value


def load_manifest(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise StartupTableError(f"failed to parse manifest JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise StartupTableError("manifest root must be a JSON object")
    return payload


def translate_segment(role_name: str, segment: object) -> StartupRecord:
    if not isinstance(segment, dict):
        raise StartupTableError(f"{role_name} PT_LOAD entry must be an object")

    program_header_index = require_int(
        segment.get("program_header_index"), f"{role_name}.program_header_index"
    )
    vaddr = require_int(segment.get("vaddr"), f"{role_name}.vaddr")
    memsz = require_int(segment.get("memsz"), f"{role_name}.memsz")
    if memsz <= 0:
        raise StartupTableError(f"{role_name}.memsz must be positive, got {memsz}")

    flags = segment.get("flags")
    if not isinstance(flags, dict):
        raise StartupTableError(f"{role_name}.flags must be an object")
    flags_raw = require_int(flags.get("raw"), f"{role_name}.flags.raw")

    page_offset = vaddr & ~(PAGE_SIZE - 1)
    page_end = align_up(vaddr + memsz, PAGE_SIZE)
    page_size = page_end - page_offset
    if page_size <= 0:
        raise StartupTableError(
            f"{role_name} PT_LOAD {program_header_index} produced non-positive page size"
        )

    return StartupRecord(
        role_name=role_name,
        role_id=ROLE_IDS[role_name],
        program_header_index=program_header_index,
        page_offset=page_offset,
        page_size=page_size,
        flags_raw=flags_raw,
    )


def render_startup_table(manifest: dict[str, object]) -> list[StartupRecord]:
    schema = manifest.get("schema")
    if schema != "nacc-manifest-v1alpha1":
        raise StartupTableError(
            f"unsupported manifest schema {schema!r}; expected 'nacc-manifest-v1alpha1'"
        )

    objects = manifest.get("objects")
    if not isinstance(objects, list):
        raise StartupTableError("manifest objects must be a list")

    seen_roles: set[str] = set()
    records: list[StartupRecord] = []

    for obj in objects:
        if not isinstance(obj, dict):
            raise StartupTableError("manifest object entries must be JSON objects")

        role_name = obj.get("role")
        if role_name not in ROLE_IDS:
            raise StartupTableError(
                f"unsupported manifest object role {role_name!r}; PR4 only accepts entry/interp"
            )
        if role_name in seen_roles:
            raise StartupTableError(f"duplicate manifest object role {role_name!r}")
        seen_roles.add(role_name)

        pt_loads = obj.get("pt_loads")
        if not isinstance(pt_loads, list):
            raise StartupTableError(f"{role_name}.pt_loads must be a list")
        if not pt_loads:
            raise StartupTableError(f"{role_name}.pt_loads must not be empty")

        for segment in pt_loads:
            records.append(translate_segment(role_name, segment))

    if "entry" not in seen_roles:
        raise StartupTableError("manifest must contain an 'entry' object")

    return records


def write_startup_table(path: Path, records: list[StartupRecord]) -> None:
    header = struct.pack("<8sII", TABLE_MAGIC, TABLE_VERSION, len(records))
    payload = b"".join(record.pack() for record in records)

    if path.parent != Path("."):
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(header + payload)


def main() -> int:
    args = parse_args()

    try:
        manifest_path = resolve_existing_file(Path(args.manifest), "manifest")
        manifest = load_manifest(manifest_path)
        records = render_startup_table(manifest)
        output_path = Path(args.output)
        write_startup_table(output_path, records)
    except StartupTableError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"wrote {output_path} records={len(records)}")
    for index, record in enumerate(records):
        print(
            "record[{index}] role={role} phdr={phdr} page_offset=0x{offset:x} "
            "page_size=0x{size:x} flags_raw=0x{flags:x}".format(
                index=index,
                role=record.role_name,
                phdr=record.program_header_index,
                offset=record.page_offset,
                size=record.page_size,
                flags=record.flags_raw,
            )
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
