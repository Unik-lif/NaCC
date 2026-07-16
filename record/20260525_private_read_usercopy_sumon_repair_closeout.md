# 2026-05-25 Private Read Usercopy SUM-on Repair Closeout

## Task

- Task packet: `docs/workflow/tasks/completed/TASK_20260525_000037_private_read_usercopy_sumon_repair.md`
- Original goal: repair the first strict `SUM=on` failure exposed after OpenSBI default-denied private-data stores from Linux: `sys_read` copying into a NaCC private user buffer through `_copy_to_iter()` / `raw_copy_to_user()` / RISC-V `fallback_scalar_usercopy`.
- Policy constraint: keep OpenSBI strict `SUM=on` denial intact. The repair must make this Linux private-buffer write explicit through a NaCC helper, not restore trap-time fallback.

## Implemented Route

The accepted route was a narrow `raw_copy_to_user()` dispatcher:

- ordinary non-private destinations continue to the existing asm usercopy path;
- active NaCC private destinations are copied through an explicit page-bounded SBI helper before entering `__asm_copy_to_user()`;
- OpenSBI walks the current address space and treats Linux-provided addresses as claims, not authority;
- the helper requires a private user destination leaf with `PTE_W` and a normal supervisor source leaf with `PTE_R` before doing the M-mode physical copy;
- strict `SUM=on` trap fallback denial and the earlier scalar private `get_user` route remain separate and intact.

## Validation Run Conclusion

Validation run:

- QEMU log: `logs/TASK_20260525_000037_private_read_usercopy_sumon_repair_w1_01_20260525_174901_qemu_20260525_175906.log`
- VM log: `logs/TASK_20260525_000037_private_read_usercopy_sumon_repair_w1_01_20260525_174901_vm_20260525_175906.log`
- Batch wrapper log: `logs/TASK_20260525_000037_private_read_usercopy_sumon_repair_debug-batch_20260525_173844.log`

The run did not complete `kernel_read_done`, but it did satisfy this packet's bounded proof target. The previous strict denial at the `sys_read` / `_copy_to_iter` / `fallback_scalar_usercopy` private read buffer path did not recur. QEMU shows `sys_read` entries at lines 1853, 2194, and 2459 without the old denial for `trap_va=0x3ff7318200` or an equivalent private read buffer.

The first new strict marker moved later:

- QEMU line 2907: `sys_rseq`
- QEMU line 2910: `[NACC][strict-sumon-first-deny]`
- access: store
- `pc=0xffffffff80159374`
- `ra=0xffffffff8015935c`
- `trap_va=0x3fa703e808`
- width: 8
- symbolized site: `linux/kernel/rseq.c:257`, `clear_rseq_cs()`, `put_user(0UL, &t->rseq->rseq_cs)`

That is enough to close the original read/copy-to-user task: execution passed the old first bad point and exposed a distinct next private user write path.

## Secondary Failure

After the rseq denial, coredump handling hit a second private-data policy failure:

- QEMU line 2941: `[NACC][strict-sumoff-first-deny]`
- access: load
- `pc=0xffffffff80a258d4`
- symbolized site: `linux/arch/riscv/lib/memcpy.S:43` / `__memcpy`
- stack includes: `copy_page_from_iter_atomic -> generic_perform_write -> ext4_file_write_iter -> do_iter_readv_writev -> dump_user_range -> elf_core_dump -> do_coredump`

This is preserved as follow-on evidence, not part of the closed read-buffer repair. It appears to be coredump code trying to read private data through an ordinary kernel copy path after the rseq fault.

## Boundary For Next Work

Close this packet. Do not continue it as an unresolved `_copy_to_iter()` failure.

If strict `SUM=on` repair continues, seed a new task from the next concrete first bad point:

- primary target: `linux/kernel/rseq.c:257` / `clear_rseq_cs()` / `put_user(0UL, &t->rseq->rseq_cs)`;
- preserve strict `SUM=on` and `SUM=off` private-data denials;
- do not solve it by broad put-user wrappers or policy relaxation before planner scopes the intended helper shape;
- treat the coredump `__memcpy()` panic as secondary evidence unless the next packet explicitly chooses a broader coredump/private-read task.

