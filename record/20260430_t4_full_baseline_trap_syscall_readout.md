# T4 Full Baseline Trap/Syscall Readout - Replacement Run

Timestamp: 2026-04-30 12:38:21 +0800

## Verdict

The replacement full workload 1-8 baseline is acceptable T1 characterization evidence.

The batch `t4-vma-attr-baseline-20260430_120107` exited `0`, all eight launcher rows are `status=ok`, each saved/live VM artifact contains expected workload output plus `[NaCC][ssh-auto-exit] code=0`, and every QEMU artifact contains protected startup diagnostics plus final PRIVATE_DATA dump/trap/context/syscall/hotspot/mepc summaries.

No first-bad runtime point was found. A failure-pattern scan found no `badaddr=0xffffffffffffffda`, panic/Oops, `code=139`, auto-timeout, qemu-owner-block, logger-failed, or owner residue in the replacement artifact set.

## Preconditions

- Launcher: `logs/t4-vma-attr-baseline-20260430_120107.launcher.log`
- Artifact summary: `logs/t4-vma-attr-baseline-20260430_120107-artifact-summary.log`
- Owner preflight and after-batch artifacts both record `no qcow2 owner found`.
- Freshness anchors record reused `final_image.bin` from `2026-04-30 01:12:56 +0800`.
- Frame anchors match the accepted runtime slice: `do_irq` / `__offset64` are 80 bytes, and `do_trap_ecall_u` / `__offset80` are 96 bytes.

## Per-Workload Summary

| Run | Workload | VM result | Dominant QEMU signal | Verdict |
| --- | --- | --- | --- | --- |
| 1 | `printf alpha >/dev/null; echo kernel_read_done` | `kernel_read_done`, code `0` | shell startup, file/open/read setup, `sys_write path=user_buffer_read`, `sys_exit_group`, final PRIVATE_DATA summary | Acceptable |
| 2 | `IFS= read -r line </etc/hostname; echo kernel_write_done` | `kernel_write_done`, code `0` | repeated `sys_read path=user_buffer_write` plus `sys_ppoll`, final write/exit, final PRIVATE_DATA summary | Acceptable |
| 3 | fork-private shell command | `fork_private_done`, code `0` | `sys_clone path=fork_exec`, fork provenance, child exit, parent `wait4`, parent write/exit | Acceptable |
| 4 | `cat /etc/hostname; echo done` | hostname, `done`, code `0` | shell forks `cat`; child read/exit; parent wait/write/exit; final fork/exec buckets | Acceptable |
| 5 | `echo alpha | cat; echo done` | `alpha`, `done`, code `0` | pipeline forks, `cat` read/write/exit, parent waits and exits | Acceptable |
| 6 | `wc -c /etc/hostname; echo done` | `13 /etc/hostname`, `done`, code `0` | shell forks `wc`; child read/write/exit; parent wait/write/exit | Acceptable |
| 7 | `echo alpha | wc -c; echo done` | `6`, `done`, code `0` | pipeline forks, `wc` read/write/exit, `nr=214 path=mapping_update`, `nr=220/221 path=fork_exec`, user buffer buckets | Acceptable |
| 8 | shared-memory `nacc_shm_repro` | `ping`, code `0` | syscall 258 Linux context, `SHARED_EXPLICIT` mmap/fork/munmap provenance, parent `ping`, `sys_unlinkat`, normal `sys_exit_group` | Acceptable |

## Trap And Syscall Counts

| Run | QEMU lines | `do_irq` | `do_page_fault` | `twin_entry scause c` | syscall context entries | Final total traps |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 14788 | 814 | 79 | 19 | 62 | 69134 |
| 2 | 15714 | 856 | 79 | 20 | 84 | 61070 |
| 3 | 22354 | 1266 | 125 | 33 | 62 | 100587 |
| 4 | 31309 | 1654 | 169 | 40 | 112 | 158723 |
| 5 | 38452 | 1980 | 218 | 57 | 130 | 139120 |
| 6 | 32188 | 1666 | 177 | 42 | 117 | 149337 |
| 7 | 38989 | 1956 | 219 | 57 | 133 | 148806 |
| 8 | 8374 | 357 | 38 | 9 | 35 | 4651 |

The `do_irq` and `do_page_fault` lines are diagnostic/progress signals in these successful runs, not failure evidence. They accompany ordinary protected execution and final code-0 workload completion.

## Key Evidence

- Launcher lines `85-92` list runs 1-8 as `status=ok` with both QEMU and VM artifact paths.
- Saved/live VM evidence:
  - run 1: `logs/t4_vma_attr_baseline_01_20260430_120111_vm_20260430_120503.log:9-13`, `logs/live_vm_pane_282.log:9-13`
  - run 2: `logs/t4_vma_attr_baseline_02_20260430_120504_vm_20260430_120846.log:9-13`, `logs/live_vm_pane_286.log:9-13`
  - run 3: `logs/t4_vma_attr_baseline_03_20260430_120846_vm_20260430_121241.log:9-13`, `logs/live_vm_pane_290.log:9-13`
  - run 4: `logs/t4_vma_attr_baseline_04_20260430_121241_vm_20260430_121647.log:9-14`, `logs/live_vm_pane_294.log:9-14`
  - run 5: `logs/t4_vma_attr_baseline_05_20260430_121647_vm_20260430_122101.log:9-14`, `logs/live_vm_pane_298.log:9-14`
  - run 6: `logs/t4_vma_attr_baseline_06_20260430_122101_vm_20260430_122504.log:9-14`, `logs/live_vm_pane_302.log:9-14`
  - run 7: `logs/t4_vma_attr_baseline_07_20260430_122504_vm_20260430_122916.log:9-14`, `logs/live_vm_pane_306.log:9-14`
  - run 8: `logs/t4_vma_attr_baseline_08_20260430_122916_vm_20260430_123254.log:9-13`, `logs/live_vm_pane_310.log:9-13`
- Protected startup `a0_is_zero=yes` appears in each QEMU artifact, for example run 1 line `2003`, run 2 line `2009`, run 3 lines `2044` and `9612`, and run 8 lines `1968` and `4387`.
- Final PRIVATE_DATA summaries begin at:
  - run 1 `logs/t4_vma_attr_baseline_01_20260430_120111_qemu_20260430_120503.log:14696`
  - run 2 `logs/t4_vma_attr_baseline_02_20260430_120504_qemu_20260430_120846.log:15622`
  - run 3 `logs/t4_vma_attr_baseline_03_20260430_120846_qemu_20260430_121241.log:22259`
  - run 4 `logs/t4_vma_attr_baseline_04_20260430_121241_qemu_20260430_121647.log:31207`
  - run 5 `logs/t4_vma_attr_baseline_05_20260430_121647_qemu_20260430_122101.log:38353`
  - run 6 `logs/t4_vma_attr_baseline_06_20260430_122101_qemu_20260430_122504.log:32089`
  - run 7 `logs/t4_vma_attr_baseline_07_20260430_122504_qemu_20260430_122916.log:38885`
  - run 8 `logs/t4_vma_attr_baseline_08_20260430_122916_qemu_20260430_123254.log:8279`

## Workload 8 Attribution Note

Exact final SBI bucket `nr=258 path=unknown` is still absent in run 8. Observed evidence still supports attribution sufficiency for this characterization:

- Linux records syscall 258 context at `logs/t4_vma_attr_baseline_08_20260430_122916_qemu_20260430_123254.log:2309`.
- Final SBI context reports `syscall_bucket_evictions=9` at line `8281`.
- `SHARED_EXPLICIT` provenance is logged at lines `3853`, `4116`, `4274`, `5095-5096`, `5204`, and final provenance line `8304`.
- Final `nr=64 path=user_buffer_read` over the shared range is logged at line `8312`.

Inference: final syscall buckets are lossy under eviction; the absent exact final `nr=258` bucket is not evidence of a PRIVATE_DATA attribution-policy failure in this successful run.

## Evidence / Inference Boundary

Observed evidence: launcher exit code `0`; all eight launcher statuses `ok`; owner-free before and after batch; fresh frame/unwind anchors; saved/live VM expected output plus code-0 markers for every run; QEMU protected entries with `a0_is_zero=yes`; QEMU `do_irq` and `do_page_fault` diagnostics; Linux syscall context lines; final SBI PRIVATE_DATA dump/trap/context/syscall/hotspot/mepc summaries; `PRIVATE_STRICT_ANON` and `PRIVATE_FILE_COW` provenance in all runs; and `SHARED_EXPLICIT` provenance plus syscall 258 Linux context in run 8.

Inference: the replacement run is acceptable T1 baseline characterization, and the prior wrapped-logger parser failure is resolved for this run. This does not prove general architectural completeness beyond the tested workloads, nor does it remove the need to preserve Linux syscall-context lines when final SBI buckets evict less frequent syscall IDs.

## Recommended Next Step

Route to human for closeout/archive decision. No coder repair, planner re-route, test_runner rerun, source edit, or PRIVATE_DATA/VMA/protected-runtime policy change is recommended from this evidence set.

## Optimization Hot Paths

Added 2026-04-30 after follow-up discussion.

The most urgent optimization target in this artifact set is not a failed trap type, but the successful-run PRIVATE_DATA trap volume. Across the final dumps for workloads 1-8, the two recorded PRIVATE_DATA categories are:

| Category | Final total traps | Share of categorized final traps | Interpretation |
| --- | ---: | ---: | --- |
| `syscall_buffer_path` | 646138 | 77.7% | S-mode accesses while Linux is servicing a protected task's syscall context. This dominates normal successful execution. |
| `teardown_mapping_update` | 185290 | 22.3% | Mapping/VMA teardown and update paths such as `mmap`, `mprotect`, `brk`, `munmap`, `exit_mmap`, and exec/fork-related reconciliation. |

### MEPC Code-Path Mapping

`mepc` is the kernel instruction address that performed the protected-data access; it is not the user PC. Therefore a high kernel address can still be associated with user/protected data when that kernel instruction loads from or stores to a protected user page, a user ABI page, or a kernel-owned data page that is being observed while servicing a protected task.

The dominant `mepc[]` values from the final dumps map as follows:

| MEPC range | `vmlinux.asm` mapping | Source nearby | What it is doing | Optimization implication |
| --- | --- | --- | --- | --- |
| `ffffffff800b067e`, `ffffffff800b0680`, `ffffffff800b0686`, `ffffffff800b068a`, `ffffffff800b0730`, `ffffffff800b0736`, `ffffffff800b0742`, `ffffffff800b0746` | `update_vsyscall` loads/stores around `vmlinux.asm:253286-253360` | `linux/kernel/time/vsyscall.c:78-126` | Updating VDSO time data and seqlock-style fields. These PCs dominate the final `mepc` lists, often with data VAs around `ffffffff81604000`. | Treat this as a concrete first optimization candidate: understand why VDSO time-data updates are mediated so often during protected execution, and whether this kernel data page should be handled differently from ordinary syscall user buffers. |
| `ffffffff800b182e`, `ffffffff800b1860`, `ffffffff800b18be` | `exit_robust_list` user loads around `vmlinux.asm:254927-254950` | `linux/kernel/futex/core.c:799-860` | Walking the userspace robust futex list during task exit, including reads from `head->list`, pending entry, and robust-list fields. | A concrete exit-teardown target. Check whether empty/default robust-list state can be detected earlier, cached, or classified separately so normal shell/BusyBox exits do not repeatedly pay full PRIVATE_DATA mediation cost. |
| `ffffffff80157f9a` | `clear_rseq_cs.isra.0` store around `vmlinux.asm:490729` | `linux/kernel/rseq.c:246-257` | Clears `t->rseq->rseq_cs` with `put_user(0UL, ...)` on resume/preemption/signal paths. | rseq ABI maintenance is a real hot path, especially in fork/exec/resume-heavy workloads. It is not business I/O; it may deserve a distinct attribution bucket or a fast path for trusted rseq ABI updates. |
| `ffffffff80158042`, `ffffffff8015825a`, `ffffffff80158266`, `ffffffff80158272`, `ffffffff80158280` | `__rseq_handle_notify_resume` reads/writes around `vmlinux.asm:490785` and `vmlinux.asm:490947-490959` | `linux/kernel/rseq.c:88-108`, `linux/kernel/rseq.c:315-335` | Reads the current rseq critical-section pointer and updates user rseq fields such as `cpu_id_start`, `cpu_id`, `node_id`, and `mm_cid`. | Same rseq family as above. This is a stronger candidate than generic syscall tuning because it points to exact ABI writes under protected return-to-user handling. |
| `ffffffff804d155c` | `strncpy_from_user` word load around `vmlinux.asm:1742652-1742662` | `linux/lib/strncpy_from_user.c:28-130` | Copies a NUL-terminated userspace string into the kernel, commonly file path or argv/env style input. | Optimize or classify user string copy separately from generic syscall-buffer traffic; this is likely tied to exec/open/path handling rather than steady-state data I/O. |
| `ffffffff80a20dea`, `ffffffff80a20df8`, `ffffffff80a20dfe` | `fallback_scalar_usercopy` / `__asm_copy_from_user` byte/word-copy tail around `vmlinux.asm:3680988-3680997` | `linux/arch/riscv/lib/uaccess.S:22-80` | RISC-V uaccess copy loop with SUM enabled, copying to/from userspace. | This is the generic usercopy bucket. If optimization work starts here, it should focus on batching/range validation or reducing repeated mediation in uaccess, not changing workload semantics. |
| `ffffffff80a20748`, `ffffffff80a20784`, `ffffffff80a20794` | `__memcpy` copy loop around `vmlinux.asm:3680443-3680464` | `linux/arch/riscv/lib/memcpy.S:10-90` | Kernel memcpy loop, appearing near usercopy and fork/exec copy activity. | Lower priority than VDSO/rseq/robust-list unless later data proves it is copying protected pages directly rather than being adjacent runtime copy work. |

This mapping changes the practical optimization target from one broad label to four concrete code families: VDSO time-data update, robust futex exit walk, rseq user ABI maintenance, and generic uaccess/user string copy.

Priority 1: reduce the concrete hotspots underneath `syscall_buffer_path`, not the label itself. The largest repeated `mepc` cluster is `update_vsyscall`, not a hand-written NaCC syscall-buffer routine. Before changing policy, inspect why VDSO time data at the `ffffffff81604000` page is being trapped during protected task progress and whether those updates can be excluded, batched, or classified with a more precise trusted-kernel-data path.

Priority 2: reduce `teardown_mapping_update` traps. This is smaller than `syscall_buffer_path` but still large, and it grows with fork/exec/pipeline workloads. Workloads 4-7 are the clearest stressors because they combine shell orchestration, external command exec, parent waits, child exit, and mapping cleanup. Optimizing VMA reconciliation or avoiding repeated mapping-update scans during `mprotect`, `mmap`, `exec`, `munmap`, and `exit_mmap` should be the second target.

Priority 3: optimize exit/resume ABI maintenance. `exit_robust_list` and rseq maintenance are concrete, recurring sources of protected-data touches that are not the workload's useful I/O. They become visible in shell, fork, exec, pipeline, and shared-memory runs because normal process exit and return-to-user paths touch user ABI structures.

Priority 4: separate workload/business I/O from runtime overhead. `user_buffer_read` and `user_buffer_write` are important semantic evidence, but they are not the dominant volume in this baseline. They are visible in workload 2 reads, workload 4-7 command output/pipe activity, and workload 8 `ping`, but the total trap volume is mostly runtime scaffolding around VDSO updates, rseq/robust-list ABI handling, generic usercopy, fork/exec, and teardown.

Priority 5: keep workload 8 as a dedicated shared-memory attribution sample, not a volume benchmark. Its final trap total is much smaller than workloads 1-7, but it uniquely exercises syscall 258 context, `SHARED_EXPLICIT` provenance, shared-memory mmap/fork/munmap, parent `sys_write` of `ping`, `sys_unlinkat`, and clean `sys_exit_group`.

Terminology note: `category=syscall_buffer_path` and `path=unknown` are different attribution layers. `category=...` is the OpenSBI trap-category classification for the actual PRIVATE_DATA load/store. In the current implementation, S-mode accesses while servicing a protected syscall are classified as `syscall_buffer_path` unless they are explicitly recognized as mapping-update work. `path=...` is the Linux-provided syscall semantic label carried in the active syscall context, such as `user_buffer_read`, `user_buffer_write`, `file_path`, `fork_exec`, `mapping_update`, or `exit_teardown`. Therefore a line can correctly say `cat=syscall_buffer_path` and also `path=unknown`: the trap happened in the syscall-buffer handling path, but the syscall number did not have a more specific semantic path label. This is a labeling granularity issue, not proof that the trap was unclassified.
