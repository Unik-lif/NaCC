#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${ROOT_DIR}/scripts/repro/nacc_shm_repro.c"
OUT_DIR="${ROOT_DIR}/scripts/repro/out"
OUT_BIN="${OUT_DIR}/nacc_shm_repro"
CC_BIN="${CC:-${ROOT_DIR}/riscv-tools/bin/riscv64-unknown-linux-gnu-gcc}"
VM_HOST="${VM_HOST:-localhost}"
VM_PORT="${VM_PORT:-2222}"
VM_USER="${VM_USER:-root}"
VM_PASS="${VM_PASS:-riscv}"
VM_DEST="${VM_DEST:-/root/nacc_shm_repro}"

mkdir -p "${OUT_DIR}"

"${CC_BIN}" -O2 -static -Wall -Wextra -o "${OUT_BIN}" "${SRC}"

if command -v sshpass >/dev/null 2>&1; then
	sshpass -p "${VM_PASS}" scp -P "${VM_PORT}" \
		-o StrictHostKeyChecking=no \
		-o UserKnownHostsFile=/dev/null \
		"${OUT_BIN}" "${VM_USER}@${VM_HOST}:${VM_DEST}"
else
	scp -P "${VM_PORT}" \
		-o StrictHostKeyChecking=no \
		-o UserKnownHostsFile=/dev/null \
		"${OUT_BIN}" "${VM_USER}@${VM_HOST}:${VM_DEST}"
fi

cat <<EOF
Installed ${OUT_BIN} to ${VM_USER}@${VM_HOST}:${VM_DEST}

Run inside VM:
docker run --security-opt seccomp=unconfined --rm \\
  -v ${VM_DEST}:/nacc_shm_repro:ro \\
  busybox /nacc_shm_repro
EOF
