#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCAL_PATCH="${ROOT_DIR}/scripts/patches/runc_manifest_register.patch"
VM_HOST="${VM_HOST:-localhost}"
VM_PORT="${VM_PORT:-2222}"
VM_USER="${VM_USER:-root}"
VM_PASS="${VM_PASS:-riscv}"
GUEST_RUNC_DIR="${GUEST_RUNC_DIR:-/root/riscv-docker/runc}"
GUEST_PATCH_PATH="${GUEST_PATCH_PATH:-/tmp/runc_manifest_register.patch}"

usage() {
    cat <<'EOF'
Usage: scripts/install_runc_manifest_register_in_vm.sh

Copy the repo-tracked guest runc patch into the VM, apply it if needed, and
run `make && make install` in the guest runc tree.

Environment:
  VM_HOST, VM_PORT, VM_USER, VM_PASS
  GUEST_RUNC_DIR, GUEST_PATCH_PATH
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

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

if [ "$#" -ne 0 ]; then
    usage >&2
    exit 2
fi

if [ ! -f "${LOCAL_PATCH}" ]; then
    echo "error: local patch not found: ${LOCAL_PATCH}" >&2
    exit 1
fi

printf '[nacc-runc-vm] local_patch=%s\n' "${LOCAL_PATCH}"
printf '[nacc-runc-vm] guest_patch=%s\n' "${GUEST_PATCH_PATH}"
printf '[nacc-runc-vm] guest_runc_dir=%s\n' "${GUEST_RUNC_DIR}"
printf '[nacc-runc-vm] ssh_target=%s@%s:%s\n' "${VM_USER}" "${VM_HOST}" "${VM_PORT}"

run_scp "${LOCAL_PATCH}" "${VM_USER}@${VM_HOST}:${GUEST_PATCH_PATH}"

run_ssh "${VM_USER}@${VM_HOST}" bash -s -- \
    "${GUEST_RUNC_DIR}" \
    "${GUEST_PATCH_PATH}" <<'EOF'
set -euo pipefail

guest_runc_dir=$1
guest_patch_path=$2
guest_runc_file="libcontainer/standard_init_linux.go"

guest_runc_manifest_marker_state() {
    local file_path=$1
    local pattern=$2

    if grep -Fq "${pattern}" "${file_path}"; then
        printf 'present'
    else
        printf 'missing'
    fi
}

log_guest_runc_manifest_shape() {
    local label=$1
    local file_path=$2

    printf '[nacc-runc-vm] %s marker_manifest_env=%s\n' \
        "${label}" \
        "$(guest_runc_manifest_marker_state "${file_path}" 'NACC_MANIFEST_PATH')"
    printf '[nacc-runc-vm] %s marker_identity_func=%s\n' \
        "${label}" \
        "$(guest_runc_manifest_marker_state "${file_path}" 'func naccLoadManifestIdentity(env []string) (*naccManifestIdentity, error) {')"
    printf '[nacc-runc-vm] %s marker_layout_func=%s\n' \
        "${label}" \
        "$(guest_runc_manifest_marker_state "${file_path}" 'func naccLoadManifestLayout(path string) ([]naccManifestLayoutRecord, error) {')"
    printf '[nacc-runc-vm] %s marker_layout_cap=%s\n' \
        "${label}" \
        "$(guest_runc_manifest_marker_state "${file_path}" 'naccManifestMaxLayoutRecords')"
    printf '[nacc-runc-vm] %s marker_layout_ptr=%s\n' \
        "${label}" \
        "$(guest_runc_manifest_marker_state "${file_path}" 'manifestLayoutPtr = uintptr(unsafe.Pointer(&manifestLayout[0]))')"
    printf '[nacc-runc-vm] %s marker_layout_count=%s\n' \
        "${label}" \
        "$(guest_runc_manifest_marker_state "${file_path}" 'manifestLayoutCount = uintptr(len(manifestLayout))')"
    printf '[nacc-runc-vm] %s marker_register_syscall=%s\n' \
        "${label}" \
        "$(guest_runc_manifest_marker_state "${file_path}" 'unix.Syscall6(SYS_NACC_REGISTER')"
    printf '[nacc-runc-vm] %s marker_identity_only_hash_copy=%s\n' \
        "${label}" \
        "$(guest_runc_manifest_marker_state "${file_path}" 'if _, err := io.Copy(hasher, file); err != nil {')"
}

guest_runc_manifest_patch_present() {
    local file_path=$1

    grep -Fq 'NACC_MANIFEST_PATH' "${file_path}" &&
        grep -Fq 'func naccLoadManifestIdentity(env []string) (*naccManifestIdentity, error) {' "${file_path}" &&
        grep -Fq 'func naccLoadManifestLayout(path string) ([]naccManifestLayoutRecord, error) {' "${file_path}" &&
        grep -Fq 'naccManifestMaxLayoutRecords' "${file_path}" &&
        grep -Fq 'manifestLayoutPtr = uintptr(unsafe.Pointer(&manifestLayout[0]))' "${file_path}" &&
        grep -Fq 'manifestLayoutCount = uintptr(len(manifestLayout))' "${file_path}" &&
        grep -Fq 'unix.Syscall6(SYS_NACC_REGISTER' "${file_path}"
}

guest_runc_manifest_identity_only_patch_present() {
    local file_path=$1

    grep -Fq 'NACC_MANIFEST_PATH' "${file_path}" &&
        grep -Fq 'func naccLoadManifestIdentity(env []string) (*naccManifestIdentity, error) {' "${file_path}" &&
        grep -Fq 'if _, err := io.Copy(hasher, file); err != nil {' "${file_path}" &&
        grep -Fq 'if _, _, errno := unix.Syscall6(SYS_NACC_REGISTER, uintptr(idVal), manifestPathPtr, manifestSHA256Ptr, manifestSize, 0, 0); errno != 0 {' "${file_path}" &&
        ! grep -Fq 'func naccLoadManifestLayout(path string) ([]naccManifestLayoutRecord, error) {' "${file_path}"
}

upgrade_guest_runc_manifest_patch_from_head() {
    local repo_dir=$1
    local patch_path=$2
    local file_path=$3
    local head_snapshot
    local temp_dir
    local status=0

    temp_dir=$(mktemp -d)
    head_snapshot="${temp_dir}/head_standard_init_linux.go"
    mkdir -p "${temp_dir}/$(dirname "${file_path}")"

    (
        cd "${repo_dir}"

        git show "HEAD:${file_path}" > "${head_snapshot}"
        cp "${head_snapshot}" "${temp_dir}/${file_path}"
        (
            cd "${temp_dir}"
            git apply "${patch_path}"
        )

        if ! guest_runc_manifest_patch_present "${temp_dir}/${file_path}"; then
            echo 'error: reconstructed guest runc file does not match expected layout-aware shape' >&2
            printf '[nacc-runc-vm] reconstruction_head_commit=%s\n' "$(git rev-parse HEAD)"
            printf '[nacc-runc-vm] reconstruction_head_blob=%s\n' "$(git rev-parse "HEAD:${file_path}")"
            printf '[nacc-runc-vm] reconstruction_blob=%s\n' "$(git hash-object "${temp_dir}/${file_path}")"
            log_guest_runc_manifest_shape "reconstructed" "${temp_dir}/${file_path}"
            log_guest_runc_manifest_shape "head" "${head_snapshot}"
            log_guest_runc_manifest_shape "worktree" "${file_path}"
            echo '[nacc-runc-vm] reconstructed_vs_head_diff_begin'
            diff -u "${head_snapshot}" "${temp_dir}/${file_path}" | sed -n '1,220p' || true
            echo '[nacc-runc-vm] reconstructed_vs_head_diff_end'
            echo '[nacc-runc-vm] reconstructed_vs_worktree_diff_begin'
            diff -u "${file_path}" "${temp_dir}/${file_path}" | sed -n '1,220p' || true
            echo '[nacc-runc-vm] reconstructed_vs_worktree_diff_end'
            exit 1
        fi

        cp "${temp_dir}/${file_path}" "${file_path}"
    ) || status=$?

    rm -rf "${temp_dir}"
    return "${status}"
}

cd "${guest_runc_dir}"
printf '[nacc-runc-vm] guest_pwd=%s\n' "$(pwd)"

if [ -x /usr/local/go/bin/go ]; then
    export PATH="/usr/local/go/bin:${PATH}"
fi

if git apply --check --reverse "${guest_patch_path}" >/dev/null 2>&1; then
    echo '[nacc-runc-vm] installer_path=already_applied_reverse_check'
    echo '[nacc-runc-vm] patch already applied'
elif guest_runc_manifest_patch_present "${guest_runc_file}"; then
    echo '[nacc-runc-vm] installer_path=semantic_match'
    echo '[nacc-runc-vm] patch already applied (semantic match)'
elif guest_runc_manifest_identity_only_patch_present "${guest_runc_file}"; then
    echo '[nacc-runc-vm] installer_path=legacy_head_reconstruction'
    upgrade_guest_runc_manifest_patch_from_head "${guest_runc_dir}" "${guest_patch_path}" "${guest_runc_file}"
    echo '[nacc-runc-vm] upgraded legacy identity-only patch via HEAD reconstruction'
elif git apply --check "${guest_patch_path}"; then
    echo '[nacc-runc-vm] installer_path=clean_apply'
    git apply "${guest_patch_path}"
    echo '[nacc-runc-vm] patch applied'
else
    echo '[nacc-runc-vm] installer_path=apply_failed'
    echo 'error: guest patch does not apply cleanly' >&2
    echo '[nacc-runc-vm] guest_diff_excerpt_begin'
    git diff -- "${guest_runc_file}" | sed -n '1,220p'
    echo '[nacc-runc-vm] guest_diff_excerpt_end'
    exit 1
fi

if command -v gofmt >/dev/null 2>&1; then
    gofmt -w "${guest_runc_file}"
else
    echo '[nacc-runc-vm] gofmt not found; skipping formatting'
fi

echo '[nacc-runc-vm] building runc'
make
echo '[nacc-runc-vm] installing runc'
make install
echo '[nacc-runc-vm] final_git_status'
git status --short -- "${guest_runc_file}"
EOF
