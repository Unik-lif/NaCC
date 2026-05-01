# T4.3 PRIVATE_DATA Hotspot Closeout

Timestamp: 2026-04-30 20:56:25 +0800

## Verdict

The accepted replacement baseline `t4-vma-attr-baseline-20260430_120107` is acceptable characterization evidence for choosing the first optimization target.

The dominant concrete MEPC family in the final dumps is `VDSO_TIME_UPDATE`. At final MEPC-bucket granularity it accounts for about 826,777 of 831,428 PRIVATE_DATA traps, or 99.4%, across workloads 1-7. Workload 8 is much smaller and exposes `RSEQ_ABI` plus `ROBUST_FUTEX_EXIT` instead.

Recommended first optimization target: `VDSO/VVAR special classification or kernel-maintained ABI-data treatment`. This is not generic shared memory and not a reason to unseal ordinary user pages.

## Evidence Sources

- `record/count_task_packet.md` was consulted as the canonical task brief and was not modified.
- `logs/t4-vma-attr-baseline-20260430_120107-artifact-summary.log:1-34` records batch exit `0`, all eight launcher rows as `status=ok`, code-0 VM markers, and QEMU anchors with private dump, trap stats, syscall bucket, hotspot, and MEPC summaries.
- `record/20260430_t4_full_baseline_trap_syscall_readout.md` was used as the prior accepted full-baseline readout.
- `vmlinux.asm` and `riscv-linux/System.map` were used for MEPC symbolization.

## Workload Pass/Fail

| Run | Command | Result | Exit | Final PRIVATE_DATA total | Exact broad split |
| --- | --- | --- | ---: | ---: | --- |
| 1 | `printf alpha >/dev/null; echo kernel_read_done` | pass | 0 | 69,134 | `syscall_buffer_path=58,076`, `teardown_mapping_update=11,058` |
| 2 | `IFS= read -r line </etc/hostname; echo kernel_write_done` | pass | 0 | 61,070 | `syscall_buffer_path=48,528`, `teardown_mapping_update=12,542` |
| 3 | fork-private shell command | pass | 0 | 100,587 | `syscall_buffer_path=83,704`, `teardown_mapping_update=16,883` |
| 4 | `cat /etc/hostname; echo done` | pass | 0 | 158,723 | `syscall_buffer_path=123,915`, `teardown_mapping_update=34,808` |
| 5 | `echo alpha \| cat; echo done` | pass | 0 | 139,120 | `syscall_buffer_path=101,789`, `teardown_mapping_update=37,331` |
| 6 | `wc -c /etc/hostname; echo done` | pass | 0 | 149,337 | `syscall_buffer_path=116,716`, `teardown_mapping_update=32,621` |
| 7 | `echo alpha \| wc -c; echo done` | pass | 0 | 148,806 | `syscall_buffer_path=109,783`, `teardown_mapping_update=39,023` |
| 8 | shared-memory `nacc_shm_repro` | pass | 0 | 4,651 | `syscall_buffer_path=3,627`, `teardown_mapping_update=1,024` |

Evidence: artifact summary lines `7-24` give pass/code-0 markers. Final trap-stat lines are run 1 `logs/t4_vma_attr_baseline_01_20260430_120111_qemu_20260430_120503.log:14697`, run 2 `...120846.log:15623`, run 3 `...121241.log:22260`, run 4 `...121647.log:31208`, run 5 `...122101.log:38354`, run 6 `...122504.log:32090`, run 7 `...122916.log:38886`, and run 8 `...123254.log:8280`.

## Exact Broad Categories

| Broad category | Exact traps | Share of total |
| --- | ---: | ---: |
| `syscall_buffer_path` | 646,138 | 77.7% |
| `teardown_mapping_update` | 185,290 | 22.3% |
| Total | 831,428 | 100.0% |

Interpretation: `syscall_buffer_path` is useful as a top-level accounting label, but it is too broad to be an optimization target. The MEPC split shows that the bulk of this label is not generic user buffer copying.

## MEPC Symbolization

| PC or range | Symbol/source | Family | Object-kind inference |
| --- | --- | --- | --- |
| `ffffffff800b067e`, `...0680`, `...0686`, `...068a`, `...0730`, `...0736`, `...0742`, `...0746` | `update_vsyscall` in `vmlinux.asm:253232`, sampled instructions at `vmlinux.asm:253286` and `vmlinux.asm:253353`; source writes VDSO time data in `linux/kernel/time/vsyscall.c:78-126`; `vdso_data_store` is at `riscv-linux/System.map:66676` | `VDSO_TIME_UPDATE` | `VDSO_VVAR_TIME_DATA` |
| `ffffffff80157f9a`, `ffffffff80158042`, `ffffffff8015825a`, `ffffffff80158266`, `ffffffff80158272`, `ffffffff80158280` | `clear_rseq_cs.isra.0` and `__rseq_handle_notify_resume`; sampled at `vmlinux.asm:490729`, `vmlinux.asm:490785`, `vmlinux.asm:490947-490959`; source writes `rseq` user ABI fields in `linux/kernel/rseq.c:88-108` and `linux/kernel/rseq.c:246-257` | `RSEQ_ABI` | `RSEQ_USER_ABI` |
| `ffffffff800b1860`, `ffffffff800b18be` | `exit_robust_list`, sampled at `vmlinux.asm:254941` and `vmlinux.asm:254977`; source walks userspace robust-list fields in `linux/kernel/futex/core.c:799-859` | `ROBUST_FUTEX_EXIT` | `ROBUST_FUTEX_LIST` |
| `ffffffff804d155c` | `strncpy_from_user+0x9e`, sampled at `vmlinux.asm:1742669`; source user string copy in `linux/lib/strncpy_from_user.c:28-130` | `USER_STRING_COPY` | `USER_STRING` |
| `ffffffff80a20dea`, `ffffffff80a20df8`, `ffffffff80a20dfe` | `fallback_scalar_usercopy`, sampled at `vmlinux.asm:3680988-3680997`; source RISC-V uaccess copy loop in `linux/arch/riscv/lib/uaccess.S:1-100` | `GENERIC_UACCESS` | `GENERIC_USER_BUFFER` |
| `ffffffff80a20748`, `ffffffff80a20784`, `ffffffff80a20794` | `__memcpy`, sampled at `vmlinux.asm:3680443`, `vmlinux.asm:3680460`, and `vmlinux.asm:3680466`; source in `linux/arch/riscv/lib/memcpy.S:1-120` | `KERNEL_MEMCPY_ADJACENT` | `KERNEL_INTERNAL_OR_ALIAS` |

Only the first three families appear in the final top-MEPC buckets for the accepted replacement run. The user string, generic uaccess, and memcpy families are symbolized because they were part of the required known mapping set and were visible in the prior accepted readout, but they do not carry measurable final top-bucket volume in this run.

## MEPC Family Summary

The counts below use the final `mepc[] approx=` buckets. These buckets partition the final totals closely, but they are still approximate attribution buckets, not independent exact trap counters.

| Family | Approx traps | Share of total | Approx load | Approx store | Unique MEPCs | Top MEPC | Top symbol | Top workload |
| --- | ---: | ---: | ---: | ---: | ---: | --- | --- | --- |
| `VDSO_TIME_UPDATE` | 826,777 | 99.4% | 206,696 | 620,081 | 8 | `ffffffff800b068a` | `update_vsyscall+0xa2` | run 4, 158,723 |
| `RSEQ_ABI` | 3,509 | 0.4% | 584 | 2,925 | 6 | `ffffffff80157f9a` and peers | `clear_rseq_cs` / `__rseq_handle_notify_resume` | run 8, 3,509 |
| `ROBUST_FUTEX_EXIT` | 1,142 | 0.1% | 1,142 | 0 | 2 | `ffffffff800b18be` / `ffffffff800b1860` | `exit_robust_list` | run 8, 1,142 |
| `USER_STRING_COPY` | 0 observed in final top buckets | 0.0% | 0 | 0 | 0 in final top buckets | `ffffffff804d155c` known mapping | `strncpy_from_user+0x9e` | none |
| `GENERIC_UACCESS` | 0 observed in final top buckets | 0.0% | 0 | 0 | 0 in final top buckets | known `fallback_scalar_usercopy` PCs | `fallback_scalar_usercopy` | none |
| `MAPPING_TEARDOWN` | not a separate final MEPC family | n/a | n/a | n/a | n/a | n/a | broad category only | runs 4-7 by exact broad total |
| `UNKNOWN_MEPC` | 0 in final top buckets | 0.0% | 0 | 0 | 0 | n/a | n/a | n/a |

## Object-Kind Summary

| Object kind | Approx traps | Share | Main MEPC family | Confidence | Notes |
| --- | ---: | ---: | --- | --- | --- |
| `VDSO_VVAR_TIME_DATA` | 826,777 | 99.4% | `VDSO_TIME_UPDATE` | high for function/object kind, medium for PFN origin | `va=ffffffff81604000` samples align with `vdso_data_store` at `riscv-linux/System.map:66676`; final samples often have `class=INVALID range=[0,0)`, so PFN-origin metadata does not prove the object by itself. |
| `RSEQ_USER_ABI` | 3,509 | 0.4% | `RSEQ_ABI` | high | Run 8 PCs map to `clear_rseq_cs` and `rseq_update_cpu_node_id` user ABI writes. |
| `ROBUST_FUTEX_LIST` | 1,142 | 0.1% | `ROBUST_FUTEX_EXIT` | high | Run 8 PCs map to robust-list user loads in `exit_robust_list`. |
| `USER_STRING` | 0 observed in final top buckets | 0.0% | `USER_STRING_COPY` | medium | Known source path exists, but no final top-bucket volume in this accepted run. |
| `GENERIC_USER_BUFFER` | 0 observed in final top buckets | 0.0% | `GENERIC_UACCESS` | medium | Known source path exists, but no final top-bucket volume in this accepted run. |
| `MAPPING_METADATA` / `ORDINARY_USER_DATA` | 185,290 exact broad-category traps | 22.3% broad category | not isolated as its own final MEPC family | low for object kind | The exact broad category exists, but the final concrete PCs remain dominated by `update_vsyscall`, so this should not be treated as a separate first optimization target from this artifact alone. |

## Family By Workload

| Workload | `VDSO_TIME_UPDATE` | `RSEQ_ABI` | `ROBUST_FUTEX_EXIT` | `USER_STRING_COPY` | `GENERIC_UACCESS` | `MAPPING_TEARDOWN` exact broad category | `UNKNOWN` |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 69,134 | 0 | 0 | 0 | 0 | 11,058 | 0 |
| 2 | 61,070 | 0 | 0 | 0 | 0 | 12,542 | 0 |
| 3 | 100,587 | 0 | 0 | 0 | 0 | 16,883 | 0 |
| 4 | 158,723 | 0 | 0 | 0 | 0 | 34,808 | 0 |
| 5 | 139,120 | 0 | 0 | 0 | 0 | 37,331 | 0 |
| 6 | 149,337 | 0 | 0 | 0 | 0 | 32,621 | 0 |
| 7 | 148,806 | 0 | 0 | 0 | 0 | 39,023 | 0 |
| 8 | 0 | 3,509 | 1,142 | 0 | 0 | 1,024 | 0 |

Note: `MAPPING_TEARDOWN` here is the exact broad-category total, not an independent concrete MEPC family. It overlaps the execution periods where the sampled concrete MEPCs still resolve to VDSO/rseq/robust-list code.

## Family By Broad Category

| Broad category | Family | Count basis | Traps | Share within broad category |
| --- | --- | --- | ---: | ---: |
| `syscall_buffer_path` | all final sampled concrete families | exact category total | 646,138 | 100.0% |
| `syscall_buffer_path` | `VDSO_TIME_UPDATE` | final MEPC approximation, category sample labels | dominates runs 1-7 | not exactly separable from final artifacts |
| `syscall_buffer_path` | `RSEQ_ABI` | final MEPC approximation, run 8 | 3,509 | 0.5% of exact syscall category |
| `syscall_buffer_path` | `ROBUST_FUTEX_EXIT` | final MEPC approximation, run 8 | 1,142 | 0.2% of exact syscall category |
| `teardown_mapping_update` | broad category only | exact category total | 185,290 | 100.0% |

The final logs do not provide an exact cross-tab of broad category by concrete MEPC family. The concrete-family conclusion is therefore driven by final MEPC buckets and symbolization, while broad-category shares remain exact only at the original two-label level.

## Candidate Optimization Ranking

| Rank | Optimization candidate | Supporting family | Estimated trap share | Implementation scope | Safety risk | Expected payoff | Recommendation |
| ---: | --- | --- | ---: | --- | --- | --- | --- |
| 1 | VDSO/VVAR special classification or kernel-maintained ABI-data treatment | `VDSO_TIME_UPDATE` | 99.4% final top-MEPC approximation | medium | medium | high | First target. Preserve all-private ordinary user memory; classify only kernel-maintained VDSO/VVAR ABI data. |
| 2 | rseq disable experiment or rseq ABI fast path | `RSEQ_ABI` | 0.4% overall, 75.4% of run 8 | medium | medium | low overall, high for run 8 slice | Defer until VDSO is handled or if shared-memory-style run 8 becomes the priority. |
| 3 | robust-list NULL/empty fast path | `ROBUST_FUTEX_EXIT` | 0.1% overall, 24.6% of run 8 | small | medium | low overall | Defer; useful for exit-heavy slices but not the dominant baseline issue. |
| 4 | mapping teardown batching / metadata cache / lazy teardown | broad `teardown_mapping_update` | 22.3% exact broad category | medium | high | medium | Do not start first because concrete MEPC/object attribution is weaker than VDSO. |
| 5 | generic syscall staging / mediation portal | `GENERIC_UACCESS` | 0 observed in final top buckets | large | high | unknown | Do not start from this evidence; `syscall_buffer_path` is too broad to justify it. |
| 6 | bounded pathname/string mediation portal | `USER_STRING_COPY` | 0 observed in final top buckets | medium | medium | unknown | Do not start from this evidence. |
| 7 | attribution repair | none required for first target | n/a | small | low | medium | Not the first recommendation because the dominant MEPC/object is sufficiently clear. |

## Unknown Breakdown

| Unknown class | Count | Meaning |
| --- | ---: | --- |
| `MEPC_SYMBOL_MISSING` | 0 final top-bucket traps | All final top MEPCs resolved through `vmlinux.asm` / `System.map`. |
| `MEPC_OUTSIDE_VMLINUX` | 0 final top-bucket traps | No final top MEPC was outside the kernel symbol space. |
| `OBJECT_KIND_UNKNOWN` | 0 for final top concrete families | Object kind is inferred for VDSO/rseq/robust-list. |
| `BROAD_CATEGORY_ONLY` | 185,290 exact broad-category traps | `teardown_mapping_update` remains exact as a broad label, but not isolated as a separate concrete MEPC family. |
| `PFN_ORIGIN_MISSING` | 826,777 VDSO-family approximate traps | VDSO samples often show `class=INVALID range=[0,0)`, so PFN-origin metadata alone is insufficient; symbol/source mapping carries the object-kind inference. |
| `NO_SYSCALL_CONTEXT` | present but not blocking | Several VDSO samples carry `syscall=-1 path=unknown` in prior/intermediate and final summaries; the MEPC and VA still resolve the dominant object. |
| `NO_MAPPING_CONTEXT` | not blocking for first target | VDSO object classification does not require VMA authority. |
| `PARSER_LIMITATION` | final MEPC `approx=` precision | The final MEPC buckets are approximate and do not provide an exact broad-category-by-family cross-tab. |
| `TRUE_UNKNOWN` | 0 final top-bucket traps | No remaining unresolved final top family. |

This exceeds 15% only if `BROAD_CATEGORY_ONLY` or `PFN_ORIGIN_MISSING` are treated as blocking unknowns. I do not treat them as blocking for the first target because the dominant PC family and object are independently resolved by `vmlinux.asm`, source, and the `vdso_data_store` symbol. They are important boundaries, not reasons to choose a generic attribution repair before the VDSO/VVAR optimization planning step.

## Required Final Answers

1. `syscall_buffer_path` is still meaningful as an accounting label, but it is too broad as an optimization target.
2. The largest concrete MEPC family is `VDSO_TIME_UPDATE`.
3. Yes. `update_vsyscall` / VDSO-VVAR time update is the largest concrete hotspot in the final MEPC buckets.
4. `RSEQ_ABI` accounts for about 3,509 traps, 0.4% overall and 75.4% of run 8.
5. `ROBUST_FUTEX_EXIT` accounts for about 1,142 traps, 0.1% overall and 24.6% of run 8.
6. True generic uaccess accounts for 0 observed traps in the final top-MEPC buckets; absence outside top buckets is not proven.
7. User string/path copy accounts for 0 observed traps in the final top-MEPC buckets; absence outside top buckets is not proven.
8. Mapping/teardown remains 185,290 exact broad-category traps, 22.3% of total, but it is not isolated as a first-class concrete MEPC family in the final dumps.
9. There is enough evidence to start optimization planning for VDSO/VVAR classification. There is not enough evidence to start generic syscall staging or mapping-teardown optimization first.
10. The single recommended first optimization target is VDSO/VVAR special classification or kernel-maintained ABI-data treatment.

## Evidence / Inference Boundary

Observed evidence: artifact summary exit code, all eight launcher rows and VM code-0 markers; final exact PRIVATE_DATA totals and broad categories from QEMU final dumps; final `mepc[] approx=` entries; `vmlinux.asm` and `System.map` symbol joins; source lines for `update_vsyscall`, rseq, robust futex, string copy, uaccess, and memcpy.

Inference: grouping adjacent PCs into MEPC families; mapping `update_vsyscall` plus `vdso_data_store` to `VDSO_VVAR_TIME_DATA`; treating rseq/robust-list PCs as ABI-maintenance object kinds; using final `mepc[] approx=` as approximate family volume; and choosing VDSO/VVAR classification as the first target. These inferences do not prove a fix, do not authorize unsealing ordinary user pages, and do not turn VMA/syscall/MEPC/ELF data into security authority.

## Next Handoff

Next owner: planner.

Recommended next step: create a narrow planning packet for a VDSO/VVAR classification experiment. The packet should keep ordinary confidential-container user memory `PRIVATE_DATA`, keep private bitmap enforcement enabled, and limit the candidate to kernel-maintained VDSO/VVAR ABI data identified by the trusted kernel object path, not by generic user VMA, syscall, MEPC, or ELF-derived policy.
