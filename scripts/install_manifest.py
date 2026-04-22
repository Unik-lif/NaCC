#!/usr/bin/env python3
"""Install manifest artifacts and an optional probe root into NaCC.qcow2."""

from __future__ import annotations

import argparse
import hashlib
import os
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

GUEST_MANIFEST_PATH = Path("/etc/nacc/manifest.json")
GUEST_STARTUP_TABLE_PATH = Path("/etc/nacc/startup_table.bin")
GUEST_INTERP_PATH = Path("/lib/ld-linux-riscv64-lp64d.so.1")
NBD_DEVICE = "/dev/nbd0"
NBD_PARTITION = "/dev/nbd0p1"
QEMU_SYSTEM_NAME = "qemu-system-riscv64"


class InstallError(RuntimeError):
    """Raised when the manifest cannot be installed safely."""


@dataclass(frozen=True)
class ProbeSpec:
    """Validation-only staged probe-root layout inside the guest image."""

    guest_root: Path
    entry_source: Path
    entry_inner_path: Path
    interp_source: Path
    interp_inner_path: Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Install manifest artifacts and an optional validation-only probe "
            "root into NaCC.qcow2 using the repo's pre-boot qemu-nbd + "
            "mounted-rootfs workflow. Override the root helper prefix with "
            "ROOT_SUDO if the default 'sudo -n' is not correct."
        )
    )
    parser.add_argument(
        "manifest",
        nargs="?",
        help="Host path to the manifest.json to copy into the guest image unchanged",
    )
    parser.add_argument(
        "--startup-table",
        help=(
            "Optional host path to a compact startup table to install at "
            "/etc/nacc/startup_table.bin alongside the manifest"
        ),
    )
    parser.add_argument(
        "--probe-root",
        help=(
            "Optional absolute guest path for a disposable probe root that "
            "stages the exact manifest entry/interpreter pair for later "
            "root-relative exec validation"
        ),
    )
    parser.add_argument(
        "--probe-entry",
        help=(
            "Optional host path to the exact entry ELF to stage at "
            "/tmp/<basename> inside the probe root"
        ),
    )
    parser.add_argument(
        "--probe-interp",
        help=(
            "Optional host path to the exact interpreter bytes to stage at "
            "/lib/ld-linux-riscv64-lp64d.so.1 inside the probe root"
        ),
    )
    return parser.parse_args()


def resolve_existing_file(path: Path, purpose: str) -> Path:
    if not path.exists():
        raise InstallError(f"{purpose} does not exist: {path}")
    if not path.is_file():
        raise InstallError(f"{purpose} is not a regular file: {path}")
    return path.resolve()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_command(
    command: list[str],
    *,
    capture_output: bool = True,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(command, text=True, capture_output=capture_output)
    if check and completed.returncode != 0:
        detail = (completed.stderr or "").strip() or (completed.stdout or "").strip()
        if not detail:
            detail = f"exit {completed.returncode}"
        raise InstallError(f"{format_command(command)} failed: {detail}")
    return completed


def format_command(command: list[str]) -> str:
    return " ".join(command)


def root_command_prefix() -> list[str]:
    value = os.environ.get("ROOT_SUDO", "sudo -n")
    try:
        prefix = shlex.split(value)
    except ValueError as exc:
        raise InstallError(f"invalid ROOT_SUDO value: {value!r}: {exc}") from exc
    if not prefix:
        raise InstallError("ROOT_SUDO must not be empty")
    return prefix


def require_absolute_guest_path(path_text: str, purpose: str) -> Path:
    path = Path(path_text)
    if not path.is_absolute():
        raise InstallError(f"{purpose} must be an absolute guest path: {path_text}")
    if any(part == ".." for part in path.parts):
        raise InstallError(f"{purpose} must not contain '..': {path_text}")
    return path


def require_disposable_probe_root(path_text: str) -> Path:
    path = require_absolute_guest_path(path_text, "probe root")
    if path == Path("/"):
        raise InstallError("probe root must not be '/'")

    guest_parts = [part for part in path.parts if part != "/"]
    if len(guest_parts) < 2:
        raise InstallError(
            "probe root must include at least two guest path components "
            "(for example /tmp/nacc_manifest_probe_root)"
        )
    return path


def executable_install_mode(source: Path, purpose: str) -> str:
    mode = source.stat().st_mode & 0o777
    if mode & 0o111 == 0:
        raise InstallError(f"{purpose} must be executable: {source}")
    return f"{mode:04o}"


def mounted_guest_path(mount_dir: Path, guest_path: Path) -> Path:
    return mount_dir / guest_path.relative_to("/")


def mounted_probe_path(mount_dir: Path, spec: ProbeSpec, inner_guest_path: Path) -> Path:
    return mount_dir / spec.guest_root.relative_to("/") / inner_guest_path.relative_to("/")


def build_probe_spec(args: argparse.Namespace) -> ProbeSpec | None:
    probe_args_present = any(
        getattr(args, field) is not None
        for field in ("probe_root", "probe_entry", "probe_interp")
    )
    if not probe_args_present:
        return None

    if not all(
        getattr(args, field) is not None
        for field in ("probe_root", "probe_entry", "probe_interp")
    ):
        raise InstallError(
            "--probe-root, --probe-entry, and --probe-interp must be supplied together"
        )

    guest_root = require_disposable_probe_root(args.probe_root)
    entry_source = resolve_existing_file(Path(args.probe_entry), "probe entry")
    interp_source = resolve_existing_file(Path(args.probe_interp), "probe interp")
    return ProbeSpec(
        guest_root=guest_root,
        entry_source=entry_source,
        entry_inner_path=Path("/tmp") / entry_source.name,
        interp_source=interp_source,
        interp_inner_path=GUEST_INTERP_PATH,
    )


def read_proc_cmdline(pid: int) -> list[str] | None:
    try:
        data = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return None

    if not data:
        return None

    return [
        field.decode("utf-8", "surrogateescape")
        for field in data.split(b"\0")
        if field
    ]


def read_proc_exe_name(pid: int) -> str | None:
    try:
        target = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return None

    clean_target = target.split(" (deleted)", 1)[0]
    return Path(clean_target).name


def find_qemu_owner(disk_path: Path, repo_root: Path) -> tuple[int, str] | None:
    for proc_entry in Path("/proc").iterdir():
        if not proc_entry.name.isdigit():
            continue

        pid = int(proc_entry.name)
        argv = read_proc_cmdline(pid)
        if not argv:
            continue

        if read_proc_exe_name(pid) != QEMU_SYSTEM_NAME:
            continue

        args = format_command(argv)
        if any(str(disk_path) in arg for arg in argv[1:]):
            return pid, args

        if not any(disk_path.name in arg for arg in argv[1:]):
            continue

        try:
            cwd = Path(f"/proc/{pid}/cwd").resolve()
        except OSError:
            continue

        if cwd == repo_root or cwd == disk_path.parent:
            return pid, args

    return None


def is_mountpoint(path: Path) -> bool:
    mount_target = str(path.resolve())
    with Path("/proc/mounts").open("r", encoding="utf-8") as mounts:
        for line in mounts:
            fields = line.split()
            if len(fields) < 2:
                continue
            if fields[1] == mount_target:
                return True
    return False


def cleanup(mount_dir: Path, qemu_nbd: Path, *, mounted: bool, attached: bool) -> list[str]:
    root_prefix = root_command_prefix()
    errors: list[str] = []
    if mounted:
        try:
            run_command(root_prefix + ["umount", str(mount_dir)])
        except InstallError as exc:
            errors.append(str(exc))
    if attached:
        try:
            run_command(root_prefix + [str(qemu_nbd), "-d", NBD_DEVICE])
        except InstallError as exc:
            errors.append(str(exc))
    return errors


def install_manifest(
    manifest_path: Path | None,
    startup_table_path: Path | None = None,
    probe_spec: ProbeSpec | None = None,
) -> tuple[list[tuple[Path, Path, str]], str | None]:
    repo_root = Path(__file__).resolve().parent.parent
    disk_path = resolve_existing_file(repo_root / "NaCC.qcow2", "disk image")
    qemu_nbd = resolve_existing_file(repo_root / "riscv-qemu" / "bin" / "qemu-nbd", "qemu-nbd")
    manifest = None
    if manifest_path is not None:
        manifest = resolve_existing_file(manifest_path, "manifest")
    startup_table = None
    if startup_table_path is not None:
        if manifest is None:
            raise InstallError("--startup-table requires a manifest path")
        startup_table = resolve_existing_file(startup_table_path, "startup table")
    if manifest is None and probe_spec is None:
        raise InstallError(
            "nothing to install: supply a manifest path and/or the full probe-root staging arguments"
        )
    mount_dir = repo_root / "rootfs"
    guest_artifacts: list[tuple[Path, Path, str]] = []
    if manifest is not None:
        guest_artifacts.append(
            (manifest, mounted_guest_path(mount_dir, GUEST_MANIFEST_PATH), "0644")
        )
    if startup_table is not None:
        guest_artifacts.append(
            (
                startup_table,
                mounted_guest_path(mount_dir, GUEST_STARTUP_TABLE_PATH),
                "0644",
            )
        )
    if probe_spec is not None:
        guest_artifacts.append(
            (
                probe_spec.entry_source,
                mounted_probe_path(mount_dir, probe_spec, probe_spec.entry_inner_path),
                executable_install_mode(probe_spec.entry_source, "probe entry"),
            )
        )
        guest_artifacts.append(
            (
                probe_spec.interp_source,
                mounted_probe_path(mount_dir, probe_spec, probe_spec.interp_inner_path),
                executable_install_mode(probe_spec.interp_source, "probe interp"),
            )
        )

    owner = find_qemu_owner(disk_path, repo_root)
    if owner is not None:
        pid, args = owner
        raise InstallError(
            f"{disk_path.name} appears to be in use by qemu pid {pid}; "
            f"shut the guest down before mutating the image\ncommand: {args}"
        )

    if is_mountpoint(mount_dir):
        raise InstallError(
            f"{mount_dir} is already mounted; unmount it before installing the manifest"
        )

    mount_dir.mkdir(exist_ok=True)
    mounted = False
    attached = False
    error: BaseException | None = None
    root_prefix = root_command_prefix()
    installed_artifacts: list[tuple[Path, Path, str]] = []
    guest_global_interp_hash: str | None = None

    try:
        run_command(root_prefix + ["modprobe", "nbd", "max_part=16"])
        run_command(root_prefix + [str(qemu_nbd), "-c", NBD_DEVICE, str(disk_path)])
        attached = True
        time.sleep(2)
        run_command(root_prefix + ["mount", NBD_PARTITION, str(mount_dir)])
        mounted = True
        if probe_spec is not None:
            probe_root_mount = mounted_guest_path(mount_dir, probe_spec.guest_root)
            guest_global_interp = mounted_guest_path(mount_dir, GUEST_INTERP_PATH)
            guest_global_interp_hash = sha256_file(guest_global_interp)
            run_command(root_prefix + ["rm", "-rf", str(probe_root_mount)])

        for source, guest_path, mode in guest_artifacts:
            source_hash = sha256_file(source)
            run_command(root_prefix + ["mkdir", "-p", str(guest_path.parent)])
            run_command(root_prefix + ["install", "-m", mode, str(source), str(guest_path)])

            installed_hash = sha256_file(guest_path)
            if installed_hash != source_hash:
                raise InstallError(
                    f"installed guest file hash does not match the source for {guest_path}"
                )
            installed_artifacts.append((source, guest_path.relative_to(mount_dir), installed_hash))

        if probe_spec is not None:
            guest_global_interp_after = sha256_file(mounted_guest_path(mount_dir, GUEST_INTERP_PATH))
            if guest_global_interp_after != guest_global_interp_hash:
                raise InstallError(
                    "probe-root staging mutated the guest-global interpreter; "
                    "refusing to continue"
                )

        return installed_artifacts, guest_global_interp_hash
    except BaseException as exc:
        error = exc
    finally:
        cleanup_errors = cleanup(mount_dir, qemu_nbd, mounted=mounted, attached=attached)
        if cleanup_errors:
            detail = "; ".join(cleanup_errors)
            if error is None:
                error = InstallError(f"cleanup failed: {detail}")
            else:
                print(f"warning: cleanup failed: {detail}", file=sys.stderr)

    if error is not None:
        raise error

    raise InstallError("manifest installation did not complete")


def main() -> int:
    args = parse_args()
    probe_spec = build_probe_spec(args)
    installed_artifacts, guest_global_interp_hash = install_manifest(
        Path(args.manifest) if args.manifest else None,
        Path(args.startup_table) if args.startup_table else None,
        probe_spec,
    )
    for index, (source, guest_path, digest) in enumerate(installed_artifacts):
        print(f"installed {source} -> /{guest_path}")
        if index == 0:
            print(f"sha256={digest}")
        else:
            print(f"sha256[{guest_path.name}]={digest}")
    if probe_spec is not None:
        probe_entry_guest = probe_spec.guest_root / probe_spec.entry_inner_path.relative_to("/")
        probe_interp_guest = probe_spec.guest_root / probe_spec.interp_inner_path.relative_to("/")
        print(f"probe_root={probe_spec.guest_root}")
        print(f"probe_entry={probe_entry_guest}")
        print(f"probe_interp={probe_interp_guest}")
        print(f"probe_chroot_exec=chroot {probe_spec.guest_root} {probe_spec.entry_inner_path}")
        print("guest_global_interp_unchanged=yes")
        if guest_global_interp_hash is not None:
            print(f"guest_global_interp_sha256={guest_global_interp_hash}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except InstallError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
