# Current-Tree Fresh PRIVATE_DATA Attribution Reconciliation

Timestamp: 2026-05-02 02:40:11 +0800

## Verdict

The fresh current-tree top-MEPC summaries are not directly comparable to the old VDSO-dominant closeout in `record/20260430_t4_3_private_data_hotspot_closeout.md`.

The old closeout used the 2026-04-30 `t4-vma-attr-baseline` final dumps, where `update_vsyscall` / `VDSO_TIME_UPDATE` accounted for about 826,777 of 831,428 final top-MEPC traps. The fresh current-tree logs that contain final PRIVATE_DATA summaries instead show top MEPCs in `fallback_scalar_usercopy`, `__memset`, `crc32_le_generic.part.0`, rseq maintenance, and robust-futex exit. No fresh final top-MEPC bucket observed here resolves to `update_vsyscall`.

Current-tree optimization decision: blocked. The updated fresh table does not justify carrying forward the old VDSO/VVAR-first recommendation as current-tree validated, and it also does not yet justify starting generic syscall staging. The single next target should be attribution repair for the fresh `INVALID` / `cid=0` top buckets, especially `fallback_scalar_usercopy`, `__memset`, and `crc32_le_generic.part.0`, with object/PFN origin and the missing fresh run 1/3/4 final summaries.

## Evidence Sources

- Old closeout: `record/20260430_t4_3_private_data_hotspot_closeout.md`
- Fresh validation: `logs/t4-count-fresh-20260502_005408.launcher.log`
- Retry validation: `logs/t4-count-fresh-retry-2-6-20260502.launcher.log`
- Fresh final-summary QEMU logs:
  - `logs/t4_count_fresh_05_20260502_013711_qemu_20260502_014115.log`
  - `logs/t4_count_fresh_07_20260502_014920_qemu_20260502_015324.log`
  - `logs/t4_count_fresh_08_20260502_015324_qemu_20260502_015703.log`
  - `logs/t4_count_fresh_retry_2_6_01_20260502_021121_qemu_20260502_021506.log`
  - `logs/t4_count_fresh_retry_2_6_02_20260502_021506_qemu_20260502_021906.log`
- Symbol sources: `vmlinux.asm`, `riscv-linux/System.map`

## Fresh Workload Status

| Workload | Fresh status | Fresh final summary used here |
| --- | --- | --- |
| 1 `printf alpha >/dev/null; echo kernel_read_done` | ok | no final PRIVATE_DATA summary in fresh QEMU log |
| 2 hostname read | ok after retry | retry run 1 QEMU summary |
| 3 fork-private repro | ok | no final PRIVATE_DATA summary in fresh QEMU log |
| 4 `cat /etc/hostname; echo done` | ok | no final PRIVATE_DATA summary in fresh QEMU log |
| 5 `echo alpha \| cat; echo done` | ok | fresh run 5 QEMU summary |
| 6 `wc -c /etc/hostname; echo done` | ok after retry | retry run 2 QEMU summary |
| 7 `echo alpha \| wc -c; echo done` | ok | fresh run 7 QEMU summary |
| 8 shared-memory repro | ok | fresh run 8 QEMU summary |

The pass/fail gap is filled by the retry child. The attribution evidence is still partial because fresh runs 1, 3, and 4 do not have final PRIVATE_DATA summaries in their QEMU logs.

## Fresh Final-Summary Totals

| Source | Total | `syscall_buffer_path` | `teardown_mapping_update` | Dominant observed top-MEPC family |
| --- | ---: | ---: | ---: | --- |
| fresh run 5 | 33,200 | 16,092 | 17,108 | `GENERIC_UACCESS` / `fallback_scalar_usercopy` |
| fresh run 7 | 42,390 | 24,071 | 18,319 | mixed `GENERIC_UACCESS`, `OTHER_KERNEL` `__memset`, `OTHER_KERNEL` `crc32` |
| fresh run 8 | 4,621 | 3,597 | 1,024 | `RSEQ_ABI`, `ROBUST_FUTEX_EXIT` |
| retry run 1 | 8,503 | 3,860 | 4,643 | `RSEQ_ABI`, plus `fallback_scalar_usercopy` and robust futex |
| retry run 2 | 34,646 | 18,351 | 16,295 | `OTHER_KERNEL` `__memset`, plus `fallback_scalar_usercopy` |
| Total summarized fresh volume | 123,360 | 65,971 | 57,389 | not VDSO-dominant |

## Updated MEPC Family Table

| Family | Approx traps | Share of summarized fresh volume | Top symbols | Object-kind confidence |
| --- | ---: | ---: | --- | --- |
| `GENERIC_UACCESS` | 57,221 | 46.4% | `fallback_scalar_usercopy` / `__asm_copy_from_user` | medium-low: function family is clear, but many top rows have `class=INVALID`, `cid=0`, `path=unknown`, and no useful range |
| `OTHER_KERNEL` (`__memset`) | 48,989 | 39.7% | `__memset+0xc4..0xdc` | low: object is not established from existing logs |
| `RSEQ_ABI` | 9,865 | 8.0% | `clear_rseq_cs.isra.0`, `__rseq_handle_notify_resume` | high |
| `OTHER_KERNEL` (`crc32_le_generic.part.0`) | 5,121 | 4.2% | `crc32_le_generic.part.0+0x22` | low |
| `ROBUST_FUTEX_EXIT` | 2,164 | 1.8% | `exit_robust_list+0x74`, `exit_robust_list+0xd2` | high |
| `VDSO_TIME_UPDATE` | 0 observed in fresh final summaries | 0.0% | no `update_vsyscall` top bucket observed | not present in summarized fresh evidence |

## Updated Candidate Ranking

| Rank | Candidate | Basis | Recommendation |
| ---: | --- | --- | --- |
| 1 | Attribution repair | More than 40% of summarized fresh volume is `OTHER_KERNEL`, and much of the `fallback_scalar_usercopy` volume also lacks object/PFN origin | First target. Repair fresh attribution before optimization. |
| 2 | Generic syscall staging / mediation portal | `fallback_scalar_usercopy` is the largest single concrete family | Do not start yet; object provenance is too weak and a large adjacent `__memset`/`crc32` volume is unresolved. |
| 3 | rseq disable or rseq ABI fast path | rseq is concrete but only about 8.0% of summarized fresh volume | Defer unless a workload-specific rseq slice becomes the priority. |
| 4 | robust-list NULL/empty fast path | robust futex is concrete but only about 1.8% of summarized fresh volume | Defer. |
| 5 | VDSO/VVAR special classification | old baseline was VDSO-dominant, fresh summarized evidence is not | Do not carry forward as current-tree validated from these fresh logs. |

## Evidence / Inference Boundary

Observed evidence: launcher statuses, VM code-0 markers, QEMU PRIVATE_DATA totals/categories, QEMU top-MEPC buckets, and symbol joins from `vmlinux.asm` / `System.map`.

Inference: grouping top PCs into families; judging the old and fresh summaries non-comparable; treating large `INVALID` / `cid=0` buckets as insufficient object attribution; and recommending an attribution repair task before any optimization. This does not prove VDSO/VVAR classification is wrong for the old baseline, does not prove generic syscall staging is the correct next optimization, and does not authorize relaxing PRIVATE_DATA or private-bitmap enforcement.
