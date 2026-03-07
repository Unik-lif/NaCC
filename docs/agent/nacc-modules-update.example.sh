#!/usr/bin/env bash
set -euo pipefail

# Use absolute paths to avoid PATH/tool lookup issues.
REPO="/home/link/NaCC"
QEMU_NBD_BIN="${REPO}/riscv-qemu/bin/qemu-nbd"
DISK="${REPO}/NaCC.qcow2"
ROOTFS_DIR="${REPO}/rootfs"
MODULE_TAR="${REPO}/kernel-modules.tar.gz"

cd "${REPO}"

umount "${ROOTFS_DIR}" 2>/dev/null || true
"${QEMU_NBD_BIN}" -d /dev/nbd0 2>/dev/null || true
modprobe nbd max_part=16
"${QEMU_NBD_BIN}" -c /dev/nbd0 "${DISK}"
sleep 2
mount /dev/nbd0p1 "${ROOTFS_DIR}"
rm -rf "${ROOTFS_DIR}/lib/modules"
mkdir -p "${ROOTFS_DIR}/lib/modules"
tar zxvf "${MODULE_TAR}" -C "${ROOTFS_DIR}/lib/modules"
umount "${ROOTFS_DIR}"
"${QEMU_NBD_BIN}" -d /dev/nbd0
