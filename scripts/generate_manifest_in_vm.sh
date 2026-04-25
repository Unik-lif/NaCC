#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCAL_GENERATOR="${ROOT_DIR}/scripts/generate_manifest.py"
VM_HOST="${VM_HOST:-localhost}"
VM_PORT="${VM_PORT:-2222}"
VM_USER="${VM_USER:-root}"
VM_PASS="${VM_PASS:-riscv}"
GUEST_HELPER_PATH="${GUEST_HELPER_PATH:-/tmp/nacc_generate_manifest.py}"
GUEST_SEARCH_ROOT="${GUEST_SEARCH_ROOT:-/}"
GUEST_PYTHON="${GUEST_PYTHON:-python3}"
GUEST_MANIFEST_PATH="${GUEST_MANIFEST_PATH:-/tmp/manifest.json}"

usage() {
    cat <<'EOF'
Usage: scripts/generate_manifest_in_vm.sh [options] <guest-entry-elf>

Stage scripts/generate_manifest.py into the guest over SSH/SCP, run it inside the
VM against guest-visible paths only, and perform one guest-side coherence check.

Options:
  -o, --output PATH         Guest path for manifest.json (default: /tmp/manifest.json)
      --guest-helper PATH   Guest path for staged generator helper
      --search-root PATH    Guest-visible search root for PT_INTERP resolution
                            (default: /)
  -h, --help                Show this help text

Environment:
  VM_HOST, VM_PORT, VM_USER, VM_PASS
  GUEST_PYTHON, GUEST_HELPER_PATH, GUEST_SEARCH_ROOT, GUEST_MANIFEST_PATH
EOF
}

run_scp() {
    if command -v sshpass >/dev/null 2>&1; then
        sshpass -p "${VM_PASS}" scp \
            -P "${VM_PORT}" \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            "$@"
    else
        scp \
            -P "${VM_PORT}" \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            "$@"
    fi
}

run_ssh() {
    if command -v sshpass >/dev/null 2>&1; then
        sshpass -p "${VM_PASS}" ssh \
            -p "${VM_PORT}" \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            "$@"
    else
        ssh \
            -p "${VM_PORT}" \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            "$@"
    fi
}

guest_entry=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        -o|--output)
            [ "$#" -ge 2 ] || { echo "error: missing value for $1" >&2; exit 2; }
            GUEST_MANIFEST_PATH="$2"
            shift 2
            ;;
        --guest-helper)
            [ "$#" -ge 2 ] || { echo "error: missing value for $1" >&2; exit 2; }
            GUEST_HELPER_PATH="$2"
            shift 2
            ;;
        --search-root)
            [ "$#" -ge 2 ] || { echo "error: missing value for $1" >&2; exit 2; }
            GUEST_SEARCH_ROOT="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "error: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
        *)
            guest_entry="$1"
            shift
            break
            ;;
    esac
done

if [ -z "${guest_entry}" ]; then
    if [ "$#" -gt 0 ]; then
        guest_entry="$1"
        shift
    fi
fi

if [ -z "${guest_entry}" ] || [ "$#" -gt 0 ]; then
    usage >&2
    exit 2
fi

if [ ! -f "${LOCAL_GENERATOR}" ]; then
    echo "error: local generator not found: ${LOCAL_GENERATOR}" >&2
    exit 1
fi

printf '[nacc-manifest-vm] local_helper=%s\n' "${LOCAL_GENERATOR}"
printf '[nacc-manifest-vm] guest_helper=%s\n' "${GUEST_HELPER_PATH}"
printf '[nacc-manifest-vm] guest_manifest=%s\n' "${GUEST_MANIFEST_PATH}"
printf '[nacc-manifest-vm] guest_entry=%s\n' "${guest_entry}"
printf '[nacc-manifest-vm] guest_search_root=%s\n' "${GUEST_SEARCH_ROOT}"
printf '[nacc-manifest-vm] ssh_target=%s@%s:%s\n' "${VM_USER}" "${VM_HOST}" "${VM_PORT}"

run_scp "${LOCAL_GENERATOR}" "${VM_USER}@${VM_HOST}:${GUEST_HELPER_PATH}"

printf '[nacc-manifest-vm] guest_generate_cmd=%s %s --search-root %s -o %s %s\n' \
    "${GUEST_PYTHON}" \
    "${GUEST_HELPER_PATH}" \
    "${GUEST_SEARCH_ROOT}" \
    "${GUEST_MANIFEST_PATH}" \
    "${guest_entry}"
printf '[nacc-manifest-vm] guest_check_cmd=%s - <manifest> <entry>\n' "${GUEST_PYTHON}"

run_ssh "${VM_USER}@${VM_HOST}" sh -s -- \
    "${GUEST_PYTHON}" \
    "${GUEST_HELPER_PATH}" \
    "${GUEST_SEARCH_ROOT}" \
    "${GUEST_MANIFEST_PATH}" \
    "${guest_entry}" <<'EOF'
set -eu

guest_python=$1
guest_helper=$2
guest_search_root=$3
guest_manifest=$4
guest_entry=$5

if ! command -v "$guest_python" >/dev/null 2>&1; then
    echo "error: guest is missing required interpreter: $guest_python" >&2
    exit 1
fi

if [ ! -f "$guest_entry" ]; then
    echo "error: guest entry ELF is not a regular file: $guest_entry" >&2
    exit 1
fi

"$guest_python" "$guest_helper" --search-root "$guest_search_root" -o "$guest_manifest" "$guest_entry"

"$guest_python" - "$guest_manifest" "$guest_entry" <<'PY'
import json
import os
import sys

manifest_path, entry_path = sys.argv[1:3]

with open(manifest_path, "r", encoding="utf-8") as fh:
    manifest = json.load(fh)

entry = manifest["entry"]
entry_resolved = entry["resolved_path"]
entry_same = os.path.realpath(entry_path) == entry_resolved
if not os.path.isfile(entry_resolved):
    raise SystemExit(f"error: manifest entry path is not a file: {entry_resolved}")
if not entry_same:
    raise SystemExit(
        f"error: manifest entry realpath mismatch: input={os.path.realpath(entry_path)} "
        f"manifest={entry_resolved}"
    )

interp_resolved = entry["interp_resolved_path"]
if interp_resolved is not None and not os.path.isfile(interp_resolved):
    raise SystemExit(f"error: manifest interp path is not a file: {interp_resolved}")

roles = ",".join(obj["role"] for obj in manifest["objects"])
print(f"[nacc-manifest-vm] coherence_manifest={manifest_path}")
print(f"[nacc-manifest-vm] coherence_entry_realpath={entry_resolved}")
print(f"[nacc-manifest-vm] coherence_interp_realpath={interp_resolved}")
print(f"[nacc-manifest-vm] coherence_roles={roles}")
PY
EOF
