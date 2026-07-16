# 2026-05-26 Post-put_user Workloads 2-8 Blockers

## Source Packet

- Packet: `docs/workflow/tasks/active/TASK_20260526_180545_post_put_user_workloads_2_8_validation.md`
- Purpose: validation-only run of canonical workloads 2-8 after the Route B scalar private `put_user` repair.
- Important boundary: do not expand the completed rseq scalar `put_user` packet. This evidence belongs to the workload 2-8 validation packet.

## Fresh Artifacts

- Workload 2 QEMU log: `logs/TASK_20260526_180545_post_put_user_w2_8_01_20260526_181450_qemu_20260526_181852.log`
- Workload 2 VM log: `logs/TASK_20260526_180545_post_put_user_w2_8_01_20260526_181450_vm_20260526_181852.log`
- Workload 3 QEMU log: `logs/TASK_20260526_180545_post_put_user_w2_8_02_20260526_182416_qemu_20260526_184724.log`
- Workload 3 VM log: `logs/TASK_20260526_180545_post_put_user_w2_8_02_20260526_182416_vm_20260526_184724.log`
- Prior comparison QEMU log: `logs/TASK_20260526_161413_rseq_put_user_wl1_01_20260526_172512_qemu_20260526_172929.log`

## Verdict

Workload 2 and workload 3 are valid runtime failures, not SSH readiness or runner failures.

- Workload 2 reached authenticated SSH and auto-run, then exited with `code=1` before `kernel_write_done`.
- Workload 3 reached authenticated SSH and auto-run, then the VM-side timeout followed an observed guest Oops/panic in QEMU, so it is runtime fallout rather than a bare timeout.

## First Shared Blocker

The first common blocker across workload 1, workload 2, and workload 3 is a PRIVATE_DATA load denial in the `sys_rt_sigaction` path.

- Workload 2: QEMU lines 4696-4698 show `sys_rt_sigaction` followed by `QEMU deny PRIVATE_DATA load`.
- Workload 3: QEMU lines 4573-4574 and 4843-4872 show the same `sys_rt_sigaction` private-load denial shape.
- Prior workload 1 comparison: QEMU lines 4485-4487 show the same first bad pattern after the scalar `put_user` repair.

Interpretation: the next primary repair family is private `copy_from_user` / user-read load mediation, first exposed through `sys_rt_sigaction`, not another rseq scalar `put_user` repair.

## Secondary Workload 3 Symptoms

Workload 3 also exposes later failures after the shared `sys_rt_sigaction` blocker:

- QEMU line 5182 enters `sys_clone`.
- QEMU lines 5264, 5269, and 5284 log `private-put-user-write-denied`.
- QEMU lines 5444-5446 show a strict SUM-off private load in `__memcpy`.
- QEMU lines 5483-5484 show kernel panic during the coredump/overlay write path.

Interpretation: the workload 3 fork/coredump path should be tracked as a second follow-up or downstream symptom. It should not obscure the first shared blocker, which is the private `copy_from_user` / load direction in `sys_rt_sigaction`.

## Recommended Route

1. Open the next coder repair packet for the shared `sys_rt_sigaction` private `copy_from_user` / load blocker.
2. Preserve workload 3's `sys_clone` / `private-put-user-write-denied` and coredump `__memcpy` strict SUM-off panic as a separate follow-up unless new evidence proves they are directly resolved by the usercopy/load repair.
3. Keep coredump/writeback and fork-specific panic repair out of the first shared-usercopy packet unless the human explicitly broadens that scope.
