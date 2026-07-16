# NaCC Dynamic Default-Private Page Fault Policy and W1-W8 Rerun

Date: 2026-07-10

Scope: single long-running Codex session outside Harness V2. No task packets were
created, edited, acknowledged, archived, or dispatched.

## Problem

The original concern was that Linux-side `PTE_NACC` / VMA state should be a fast
routing hint, not the security authority for dynamically installed user-data
pages. After a NaCC root page table has been attached and swept by OpenSBI,
ordinary future user data leaves should align with the initial bitmap policy
instead of remaining normal merely because Linux omitted `PTE_NACC`.

The important timing constraint is that pre-attach ELF construction must not be
forced private by this dynamic default rule. Initial ELF content is assumed to
have already passed the separate integrity path; the change here only targets
later page-fault-installed mappings after attach.

## Implementation

OpenSBI now records whether a protected root page table has completed the
attach-time sweep:

- `opensbi/lib/sbi/sm/bitmap.c:14` adds `NACC_ROOT_RECORD_ATTACHED`.
- `opensbi/lib/sbi/sm/bitmap.c:292` adds `nacc_bitmap_mark_root_attached()`.
- `opensbi/lib/sbi/sm/bitmap.c:312` adds `nacc_bitmap_root_is_attached()`.
- `opensbi/include/sm/bitmap.h` declares those APIs.
- `opensbi/lib/sbi/sm/sm.c:204` marks the root attached only after
  `nacc_user_nonleaf_ptp_is_secure()` and `nacc_sync_private_tags()` succeed.

The page-table update policy is split into two concepts:

- `nacc_pte_ordinary_private_data_leaf()` in
  `opensbi/lib/sbi/sm/vm.c:282` means the leaf is a structurally valid resident
  leaf that can be protected if explicitly requested or pending.
- `nacc_pte_default_private_data_leaf()` in
  `opensbi/lib/sbi/sm/vm.c:295` is the monitor-owned default-private class:
  `PTE_U && PTE_W && !PTE_X`, excluding secure/agent/special/devmap pages.

`nacc_prepare_secure_pte_update_for()` in `opensbi/lib/sbi/sm/vm.c:356` now
protects a requested PFN when:

- Linux explicitly requests `PTE_NACC`, or
- the PFN is `PRIVATE_COPY_PENDING`, or
- the root is attached and the requested leaf is a default-private user data
  leaf.

This means post-attach anonymous writable user data does not depend on Linux
remembering `PTE_NACC`, while public/text/file-backed mappings are not
automatically privatized solely because they are resident user leaves.

The attach-time sweep uses the same default-private predicate. Non-default
public leaves are preserved unless Linux explicitly marked them `PTE_NACC`.

The test runner script also received one harness fix:

- `config/debug-batch.sh:426` truncates the per-pane live VM log after a fresh
  VM pane is discovered. This avoids stale `[NaCC] Auto-running` or
  `[NaCC][ssh-auto-exit]` markers if tmux pane ids are reused.

## Important Failed Attempts

A too-broad first implementation treated all ordinary resident leaves as
default private. That caused Docker shell execution failures such as
`exec /bin/sh: bad address` because pre-attach or non-data mappings were made
private too early or too broadly.

After adding the attached-root timing gate, workload 4 exposed the deeper policy
boundary:

- Failed log:
  `logs/bitmap_attached_w1_8_rerun2_04_20260710_164803_qemu_20260710_165633.log`
- VM auto command:
  `docker run --security-opt seccomp=unconfined --rm busybox sh -c 'cat /etc/hostname; echo done'`
- Failure:
  kernel `Oops - load access fault`, then `Kernel panic`.
- Stack:
  `__memcpy -> copy_page_to_iter -> filemap_read -> ext4_file_read_iter -> ovl_read_iter -> __kernel_read -> bprm_execve`.
- Interpretation:
  Linux was executing/reading file-backed container content and copied from a
  PFN through the kernel direct map. Marking such read-only/file/text pages
  private caused the bitmap check to reject S-mode raw load. This is not a TLB
  flush story; it is a classification boundary issue.

The fix was to make monitor-owned default-private classification match
user-data pages (`PTE_U && PTE_W && !PTE_X`) while preserving explicit
`PTE_NACC` and `PRIVATE_COPY_PENDING` behavior.

## Build

Command:

```sh
make opensbi
```

Result: passed. `bear` failed to create its local gRPC socket under the current
sandbox and the Makefile fell back to plain `make`; OpenSBI firmware build
completed successfully.

## Workload 1-8 Validation

Command:

```sh
config/debug-batch.sh \
  --session-name nacc-bitmap-attached-w1-8-20260710-rerun3 \
  --cmd-file config/debug-batch.uaccess_loop_broad_eight_current_tree_validation.txt \
  --tag-prefix bitmap_attached_w1_8_rerun3 \
  --ssh-ready-timeout 480 \
  --ssh-auto-timeout 300 \
  --wait-after-auto 400
```

Result: all eight workloads passed with `[NaCC][ssh-auto-exit] code=0`.

Per-workload logs:

1. `kernel_read_done`
   - VM: `logs/bitmap_attached_w1_8_rerun3_01_20260710_165903_vm_20260710_170257.log`
   - QEMU: `logs/bitmap_attached_w1_8_rerun3_01_20260710_165903_qemu_20260710_170257.log`
2. `kernel_write_done`
   - VM: `logs/bitmap_attached_w1_8_rerun3_02_20260710_170257_vm_20260710_170650.log`
   - QEMU: `logs/bitmap_attached_w1_8_rerun3_02_20260710_170257_qemu_20260710_170650.log`
3. `fork_private_done`
   - VM: `logs/bitmap_attached_w1_8_rerun3_03_20260710_170651_vm_20260710_171049.log`
   - QEMU: `logs/bitmap_attached_w1_8_rerun3_03_20260710_170651_qemu_20260710_171049.log`
4. `cat /etc/hostname; echo done`
   - VM: `logs/bitmap_attached_w1_8_rerun3_04_20260710_171049_vm_20260710_171439.log`
   - QEMU: `logs/bitmap_attached_w1_8_rerun3_04_20260710_171049_qemu_20260710_171439.log`
5. `echo alpha | cat; echo done`
   - VM: `logs/bitmap_attached_w1_8_rerun3_05_20260710_171439_vm_20260710_171835.log`
   - QEMU: `logs/bitmap_attached_w1_8_rerun3_05_20260710_171439_qemu_20260710_171835.log`
6. `wc -c /etc/hostname; echo done`
   - VM: `logs/bitmap_attached_w1_8_rerun3_06_20260710_171835_vm_20260710_172229.log`
   - QEMU: `logs/bitmap_attached_w1_8_rerun3_06_20260710_171835_qemu_20260710_172229.log`
7. `echo alpha | wc -c; echo done`
   - VM: `logs/bitmap_attached_w1_8_rerun3_07_20260710_172229_vm_20260710_172622.log`
   - QEMU: `logs/bitmap_attached_w1_8_rerun3_07_20260710_172229_qemu_20260710_172622.log`
8. shared-memory repro, output `ping`
   - VM: `logs/bitmap_attached_w1_8_rerun3_08_20260710_172623_vm_20260710_173012.log`
   - QEMU: `logs/bitmap_attached_w1_8_rerun3_08_20260710_172623_qemu_20260710_173012.log`

Post-run scan:

```sh
rg -n 'panic|Oops|BUG|bad address|segfault|Unable to handle|Kernel panic|load access fault|ssh-auto-timeout' \
  logs/bitmap_attached_w1_8_rerun3_*_qemu_*.log \
  logs/bitmap_attached_w1_8_rerun3_*_vm_*.log
```

Result: no matches.

## Residual Risk

The W1-W8 batch proves the functional paths used by these workloads, including
the external `cat`/`wc` cases that previously tripped over file-backed exec/read
pages.

It does not yet prove a malicious Linux negative test where Linux intentionally
omits `PTE_NACC` on a post-attach writable anonymous user-data leaf and the
monitor independently marks the PFN private. That needs either targeted
instrumentation or a dedicated kernel-side fault-path probe.

The current rule is intentionally modest and paper-defensible: monitor-owned
default bitmap marking is limited to writable user data leaves after attach;
Linux hints still exist for fast routing and explicit cases, but are not the
sole authority for this default class.
