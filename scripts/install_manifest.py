#!/usr/bin/env python3
"""Install a caller-supplied manifest.json into NaCC.qcow2."""

from __future__ import annotations

import argparse
import hashlib
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

GUEST_MANIFEST_PATH = Path("/etc/nacc/manifest.json")
NBD_DEVICE = "/dev/nbd0"
NBD_PARTITION = "/dev/nbd0p1"


class InstallError(RuntimeError):
    """Raised when the manifest cannot be installed safely."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Install a caller-supplied manifest.json into NaCC.qcow2 at "
            "/etc/nacc/manifest.json using the repo's pre-boot qemu-nbd + "
            "mounted-rootfs workflow. Override the root helper prefix with "
            "ROOT_SUDO if the default 'sudo -n' is not correct."
        )
    )
    parser.add_argument(
        "manifest",
        help="Host path to the manifest.json to copy into the guest image unchanged",
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


def find_qemu_owner(disk_path: Path, repo_root: Path) -> tuple[int, str] | None:
    completed = run_command(["ps", "-eo", "pid=,args="], capture_output=True)
    for line in completed.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        pid_str, args = parts
        if "qemu-system-riscv64" not in args:
            continue

        try:
            pid = int(pid_str)
        except ValueError:
            continue

        if str(disk_path) in args:
            return pid, args

        if disk_path.name not in args:
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


def install_manifest(manifest_path: Path) -> tuple[Path, str]:
    repo_root = Path(__file__).resolve().parent.parent
    disk_path = resolve_existing_file(repo_root / "NaCC.qcow2", "disk image")
    qemu_nbd = resolve_existing_file(repo_root / "riscv-qemu" / "bin" / "qemu-nbd", "qemu-nbd")
    manifest = resolve_existing_file(manifest_path, "manifest")
    mount_dir = repo_root / "rootfs"
    guest_manifest = mount_dir / GUEST_MANIFEST_PATH.relative_to("/")

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
    source_hash = sha256_file(manifest)
    error: BaseException | None = None
    root_prefix = root_command_prefix()

    try:
        run_command(root_prefix + ["modprobe", "nbd", "max_part=16"])
        run_command(root_prefix + [str(qemu_nbd), "-c", NBD_DEVICE, str(disk_path)])
        attached = True
        time.sleep(2)
        run_command(root_prefix + ["mount", NBD_PARTITION, str(mount_dir)])
        mounted = True
        run_command(root_prefix + ["mkdir", "-p", str(guest_manifest.parent)])
        run_command(
            root_prefix + ["install", "-m", "0644", str(manifest), str(guest_manifest)]
        )

        installed_hash = sha256_file(guest_manifest)
        if installed_hash != source_hash:
            raise InstallError(
                "installed guest manifest hash does not match the source manifest"
            )

        return manifest, installed_hash
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
    manifest, digest = install_manifest(Path(args.manifest))
    print(f"installed {manifest} -> {GUEST_MANIFEST_PATH}")
    print(f"sha256={digest}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except InstallError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
