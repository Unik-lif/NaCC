#!/usr/bin/env python3
"""Stage the manifest's fixed entry/interp pair into a guest-local probe root."""

from __future__ import annotations

import argparse
import json
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import install_manifest


@dataclass(frozen=True)
class StageArtifact:
    role: str
    source_path: Path
    guest_path: PurePosixPath
    mode: int


@dataclass(frozen=True)
class GuestPathSnapshot:
    exists: bool
    sha256: str | None
    mode: int | None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Stage the fixed manifest entry/interp pair into a disposable guest-local "
            "probe root inside NaCC.qcow2 while leaving the guest-global interpreter "
            "untouched. Override the root helper prefix with ROOT_SUDO if the default "
            "'sudo -n' is not correct."
        )
    )
    parser.add_argument(
        "manifest",
        help="Host path to the manifest.json that defines the fixed entry/interp pair",
    )
    parser.add_argument(
        "--probe-root",
        required=True,
        help=(
            "Absolute guest path of the disposable probe root, for example "
            "/tmp/nacc-manifest-probe-root"
        ),
    )
    return parser.parse_args()


def normalize_guest_path(path_str: str, purpose: str) -> PurePosixPath:
    path = PurePosixPath(path_str)
    if not path.is_absolute():
        raise install_manifest.InstallError(f"{purpose} must be an absolute guest path: {path_str}")
    if any(part == ".." for part in path.parts):
        raise install_manifest.InstallError(
            f"{purpose} must not contain '..' segments: {path_str}"
        )
    if path == PurePosixPath("/"):
        raise install_manifest.InstallError(f"{purpose} must not be '/': {path_str}")
    return path


def host_path_for_guest_path(mount_dir: Path, guest_path: PurePosixPath) -> Path:
    return mount_dir / guest_path.relative_to("/")


def load_manifest_artifacts(manifest_path: Path) -> list[StageArtifact]:
    manifest = install_manifest.resolve_existing_file(manifest_path, "manifest")
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise install_manifest.InstallError(f"failed to parse manifest JSON: {exc}") from exc

    objects = payload.get("objects")
    if not isinstance(objects, list):
        raise install_manifest.InstallError("manifest is missing objects[]")

    artifacts_by_role: dict[str, StageArtifact] = {}
    for index, raw_object in enumerate(objects):
        if not isinstance(raw_object, dict):
            raise install_manifest.InstallError(f"manifest object[{index}] is not an object")

        role = raw_object.get("role")
        if role not in {"entry", "interp"}:
            raise install_manifest.InstallError(
                f"probe-root staging supports only entry/interp roles, found {role!r}"
            )
        if role in artifacts_by_role:
            raise install_manifest.InstallError(f"manifest contains duplicate {role!r} objects")

        resolved_path = raw_object.get("resolved_path")
        requested_path = raw_object.get("requested_path")
        if not isinstance(resolved_path, str) or not resolved_path:
            raise install_manifest.InstallError(
                f"manifest object[{index}] role={role!r} is missing resolved_path"
            )
        if not isinstance(requested_path, str) or not requested_path:
            raise install_manifest.InstallError(
                f"manifest object[{index}] role={role!r} is missing requested_path"
            )

        source_path = install_manifest.resolve_existing_file(
            Path(resolved_path), f"manifest {role} source"
        )
        guest_path = normalize_guest_path(requested_path, f"manifest {role} guest path")
        mode = stat.S_IMODE(source_path.stat().st_mode)
        artifacts_by_role[role] = StageArtifact(
            role=role,
            source_path=source_path,
            guest_path=guest_path,
            mode=mode,
        )

    entry = artifacts_by_role.get("entry")
    if entry is None:
        raise install_manifest.InstallError("manifest is missing the required entry object")

    ordered = [entry]
    interp = artifacts_by_role.get("interp")
    if interp is not None:
        ordered.append(interp)
    return ordered


def snapshot_guest_path(path: Path) -> GuestPathSnapshot:
    if not path.exists():
        return GuestPathSnapshot(exists=False, sha256=None, mode=None)
    if not path.is_file():
        raise install_manifest.InstallError(f"expected a regular file at {path}")
    return GuestPathSnapshot(
        exists=True,
        sha256=install_manifest.sha256_file(path),
        mode=stat.S_IMODE(path.stat().st_mode),
    )


def compare_snapshot(path: Path, before: GuestPathSnapshot, after: GuestPathSnapshot, purpose: str) -> None:
    if before != after:
        raise install_manifest.InstallError(
            f"{purpose} changed unexpectedly at {path}: before={before} after={after}"
        )


def stage_probe_root(
    manifest_path: Path, probe_root_str: str
) -> tuple[
    PurePosixPath,
    list[tuple[StageArtifact, PurePosixPath, str]],
    PurePosixPath,
    list[tuple[PurePosixPath, GuestPathSnapshot]],
]:
    artifacts = load_manifest_artifacts(manifest_path)
    probe_root = normalize_guest_path(probe_root_str, "probe root")

    repo_root = Path(__file__).resolve().parent.parent
    disk_path = install_manifest.resolve_existing_file(repo_root / "NaCC.qcow2", "disk image")
    qemu_nbd = install_manifest.resolve_existing_file(
        repo_root / "riscv-qemu" / "bin" / "qemu-nbd", "qemu-nbd"
    )
    mount_dir = repo_root / "rootfs"
    probe_root_host = host_path_for_guest_path(mount_dir, probe_root)

    owner = install_manifest.find_qemu_owner(disk_path, repo_root)
    if owner is not None:
        pid, args = owner
        raise install_manifest.InstallError(
            f"{disk_path.name} appears to be in use by qemu pid {pid}; "
            f"shut the guest down before mutating the image\ncommand: {args}"
        )

    if install_manifest.is_mountpoint(mount_dir):
        raise install_manifest.InstallError(
            f"{mount_dir} is already mounted; unmount it before staging the probe root"
        )

    mount_dir.mkdir(exist_ok=True)
    mounted = False
    attached = False
    error: BaseException | None = None
    root_prefix = install_manifest.root_command_prefix()
    staged: list[tuple[StageArtifact, PurePosixPath, str]] = []
    preserved_paths = {
        artifact.guest_path: host_path_for_guest_path(mount_dir, artifact.guest_path)
        for artifact in artifacts
    }
    try:
        install_manifest.run_command(root_prefix + ["modprobe", "nbd", "max_part=16"])
        install_manifest.run_command(
            root_prefix + [str(qemu_nbd), "-c", install_manifest.NBD_DEVICE, str(disk_path)]
        )
        attached = True
        time.sleep(2)
        install_manifest.run_command(
            root_prefix + ["mount", install_manifest.NBD_PARTITION, str(mount_dir)]
        )
        mounted = True

        before_snapshots = {
            guest_path: snapshot_guest_path(host_path)
            for guest_path, host_path in preserved_paths.items()
        }

        install_manifest.run_command(root_prefix + ["rm", "-rf", str(probe_root_host)])
        for artifact in artifacts:
            staged_guest_path = probe_root / artifact.guest_path.relative_to("/")
            staged_host_path = host_path_for_guest_path(mount_dir, staged_guest_path)
            install_manifest.run_command(
                root_prefix
                + [
                    "install",
                    "-D",
                    "-m",
                    f"{artifact.mode:04o}",
                    str(artifact.source_path),
                    str(staged_host_path),
                ]
            )
            staged_hash = install_manifest.sha256_file(staged_host_path)
            source_hash = install_manifest.sha256_file(artifact.source_path)
            if staged_hash != source_hash:
                raise install_manifest.InstallError(
                    f"staged probe-root file hash does not match the source for {staged_guest_path}"
                )
            staged.append((artifact, staged_guest_path, staged_hash))

        for guest_path, host_path in preserved_paths.items():
            after_snapshot = snapshot_guest_path(host_path)
            compare_snapshot(
                host_path,
                before_snapshots[guest_path],
                after_snapshot,
                "guest-global manifest target",
            )

        entry_exec_path = next(
            artifact.guest_path
            for artifact, _staged_guest_path, _digest in staged
            if artifact.role == "entry"
        )
        preserved = [
            (guest_path, before_snapshots[guest_path])
            for guest_path in sorted(preserved_paths, key=str)
        ]
        return probe_root, staged, entry_exec_path, preserved
    except BaseException as exc:
        error = exc
    finally:
        cleanup_errors = install_manifest.cleanup(
            mount_dir, qemu_nbd, mounted=mounted, attached=attached
        )
        if cleanup_errors:
            detail = "; ".join(cleanup_errors)
            if error is None:
                error = install_manifest.InstallError(f"cleanup failed: {detail}")
            else:
                print(f"warning: cleanup failed: {detail}", file=sys.stderr)

    if error is not None:
        raise error

    raise install_manifest.InstallError("probe-root staging did not complete")


def main() -> int:
    args = parse_args()
    probe_root, staged, entry_exec_path, preserved = stage_probe_root(
        Path(args.manifest), args.probe_root
    )
    print(f"probe_root={probe_root}")
    for artifact, staged_guest_path, digest in staged:
        print(
            f"staged role={artifact.role} source={artifact.source_path} "
            f"guest={staged_guest_path} sha256={digest} mode={artifact.mode:04o}"
        )
    for guest_path, snapshot in preserved:
        if snapshot.exists:
            print(
                f"preserved guest={guest_path} sha256={snapshot.sha256} mode={snapshot.mode:04o}"
            )
        else:
            print(f"preserved guest={guest_path} exists=no")
    print(f"suggested_exec=chroot {probe_root} {entry_exec_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except install_manifest.InstallError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
