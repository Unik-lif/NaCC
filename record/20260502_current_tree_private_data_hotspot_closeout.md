# Current-Tree PRIVATE_DATA Hotspot Closeout

Timestamp: 2026-05-02 04:29:21 +0800

Source task packet: `docs/workflow/tasks/active/TASK_20260502_042430_count_final_current_tree_closeout.md`

Canonical requirements: `record/count_task_packet.md`

## Verdict

Verdict: accepted, with evidence-quality caveats.

The current-tree evidence is sufficient to close the count attribution slice and select exactly one first optimization target. The old VDSO/VVAR-first recommendation must not be carried forward: no current final top-MEPC row in this reduction resolves to `update_vsyscall`. The dominant current-tree pattern is `fallback_scalar_usercopy` plus adjacent bulk-memory routines (`memset`, `crc32_le_generic.part.0`) touching PRIVATE_DATA user-origin pages, often through S-mode direct-map aliases.

Single recommended first optimization target: explicit typed syscall/usercopy mediation or staging portal for generic user buffers. This must keep original user pages PRIVATE_DATA and must not alias or unseal ordinary user pages.

Residual caveat: the 04:19 origin-repair evidence uses a bounded, lossy leaf-origin cache. Final origin-repair counters include leaf-origin overwrites and high `pfn_fallback_ambiguous` counts. Those counters are an evidence-quality boundary, not proof of a lossless attribution mechanism. They do not block this closeout because the formerly dominant `INVALID` / `cid=0` rows for `fallback_scalar_usercopy`, `crc32_le_generic.part.0`, and the `memset` range gained useful origin fields in the accepted 04:19 artifact.

## Evidence Sources

- Canonical packet: `record/count_task_packet.md`
- Fresh validation child: `docs/workflow/tasks/completed/TASK_20260502_005408_count_fresh_validation_rerun.md`
- Retry child for workloads 2 and 6: `docs/workflow/tasks/completed/TASK_20260502_020440_count_fresh_retry_2_6.md`
- Current-tree reconciliation: `record/20260502_count_fresh_attribution_reconciliation.md`
- Accepted origin-repair child: `docs/workflow/tasks/completed/TASK_20260502_024346_count_fresh_invalid_origin_repair.md`
- Primary origin-repair launcher: `logs/t4-count-origin-repair-20260502_035501.launcher.log`
- Origin-repair QEMU logs for workloads 1, 3, 4, 5, 6, and 7:
  - `logs/t4_count_origin_repair_01_20260502_035501_qemu_20260502_035847.log`
  - `logs/t4_count_origin_repair_02_20260502_035848_qemu_20260502_040237.log`
  - `logs/t4_count_origin_repair_03_20260502_040238_qemu_20260502_040632.log`
  - `logs/t4_count_origin_repair_04_20260502_040633_qemu_20260502_041039.log`
  - `logs/t4_count_origin_repair_05_20260502_041040_qemu_20260502_041438.log`
  - `logs/t4_count_origin_repair_06_20260502_041438_qemu_20260502_041842.log`
- Retry QEMU log for workload 2: `logs/t4_count_fresh_retry_2_6_01_20260502_021121_qemu_20260502_021506.log`
- Fresh QEMU log for workload 8: `logs/t4_count_fresh_08_20260502_015324_qemu_20260502_015703.log`
- Symbol source: `riscv-linux/System.map`

## 8.1 Workload Pass/Fail Table

All workload results are code-0 in the final accepted evidence set. Workloads 1, 3, 4, 5, 6, and 7 use the accepted 04:19 origin-repair rerun where available. Workload 2 uses the retry child. Workload 8 uses the original fresh validation log because it was not part of the 04:19 bounded origin-repair batch.

| Workload | Command | Status | Exit code | Final total | Broad category split |
| ---: | --- | --- | ---: | ---: | --- |
| 1 | `printf alpha >/dev/null; echo kernel_read_done` | pass | 0 | 7,756 | syscall_buffer_path 7,735; teardown_mapping_update 21 |
| 2 | `IFS= read -r line </etc/hostname; echo kernel_write_done` | pass after retry | 0 | 8,503 | syscall_buffer_path 3,860; teardown_mapping_update 4,643 |
| 3 | anonymous/private fork repro; `echo fork_private_done` | pass | 0 | 16,316 | syscall_buffer_path 15,272; teardown_mapping_update 1,044 |
| 4 | `cat /etc/hostname; echo done` | pass | 0 | 28,440 | syscall_buffer_path 26,267; teardown_mapping_update 2,173 |
| 5 | `echo alpha \| cat; echo done` | pass | 0 | 42,821 | syscall_buffer_path 39,520; teardown_mapping_update 3,301 |
| 6 | `wc -c /etc/hostname; echo done` | pass | 0 | 30,636 | syscall_buffer_path 27,330; teardown_mapping_update 3,306 |
| 7 | `echo alpha \| wc -c; echo done` | pass | 0 | 43,493 | syscall_buffer_path 38,649; teardown_mapping_update 4,844 |
| 8 | shared-memory repro; expected `ping` | pass | 0 | 4,621 | syscall_buffer_path 3,597; teardown_mapping_update 1,024 |

Total reduced final PRIVATE_DATA volume: 182,586 traps.

## 8.2 MEPC Family Summary

Counts below are summed from final `PRIVATE_DATA mepc[...] approx=` rows after symbolizing PCs with `riscv-linux/System.map`. In this final summary set the printed top-MEPC rows account for the same total volume as the final PRIVATE_DATA totals.

| Family | Total traps | Share | Load count | Store count | Unique MEPC count | Top MEPC / symbol | Top workload |
| --- | ---: | ---: | ---: | ---: | ---: | --- | --- |
| GENERIC_UACCESS | 115,332 | 63.2% | 165 | 4,451 | 10 | `ffffffff80a20dfa` `fallback_scalar_usercopy+0xaa` | W7 |
| KERNEL_MEMCPY_ADJACENT | 36,228 | 19.8% | 1,024 | 6 | 7 | `ffffffff80a20a1c` `memset+0xd8`; `crc32_le_generic.part.0+0x22` also present | W7 for `memset`; W6 for `crc32` |
| RSEQ_ABI | 21,826 | 12.0% | 325 | 1,655 | 6 | `__rseq_handle_notify_resume+0x2b4..0x2ce` | W3 |
| ROBUST_FUTEX_EXIT | 9,200 | 5.0% | 7 | 0 | 3 | `exit_robust_list+0x74` / `+0xd2` | W3 |
| VDSO_TIME_UPDATE | 0 | 0.0% | 0 | 0 | 0 | none observed | none |
| USER_STRING_COPY | 0 | 0.0% | 0 | 0 | 0 | none observed | none |
| MAPPING_TEARDOWN | 0 as a distinct MEPC family | 0.0% | 0 | 0 | 0 | no distinct teardown function among final top-MEPC rows | none |
| UNKNOWN_MEPC | 0 | 0.0% | 0 | 0 | 0 | none | none |

Symbol anchors:

- `exit_robust_list`: `ffffffff800b1800`
- `clear_rseq_cs.isra.0`: `ffffffff80157f78`
- `__rseq_handle_notify_resume`: `ffffffff80157fc6`
- `crc32_le_generic.part.0`: `ffffffff80a1ffb6`
- `memset`: `ffffffff80a20944`
- `fallback_scalar_usercopy`: `ffffffff80a20d50`

## 8.3 Object-Kind Summary

| Object kind | Total traps | Share | Main MEPC family | Confidence | Notes |
| --- | ---: | ---: | --- | --- | --- |
| GENERIC_USER_BUFFER / ORDINARY_USER_DATA | 151,560 | 83.0% | GENERIC_UACCESS plus KERNEL_MEMCPY_ADJACENT | medium | The accepted 04:19 rows map dominant direct-map aliases back to nonzero `cid`, nonzero `origin_va`, useful ranges, and `PRIVATE_FILE_COW` or `PRIVATE_STRICT_ANON`. Confidence is medium, not high, because many decisive rows use `origin_source=pa_pfn_fallback` and the cache has high ambiguity counters. |
| RSEQ_USER_ABI | 21,826 | 12.0% | RSEQ_ABI | high | Symbol family and ABI object are clear from `clear_rseq_cs.isra.0` and `__rseq_handle_notify_resume`. |
| ROBUST_FUTEX_LIST | 9,200 | 5.0% | ROBUST_FUTEX_EXIT | high | Symbol family and object class are clear from `exit_robust_list`. |
| VDSO_VVAR_TIME_DATA | 0 | 0.0% | VDSO_TIME_UPDATE | high absence in current top rows | No current final top-MEPC row resolves to `update_vsyscall`. |
| USER_STRING | 0 | 0.0% | USER_STRING_COPY | high absence in current top rows | No `strncpy_from_user` top row observed. |
| MAPPING_METADATA | not additive; broad counter is 20,356 | 11.1% broad-category overlay | no distinct MEPC family | medium-low | The stats category `teardown_mapping_update` remains visible, but the final top-MEPC rows in that path resolve to already counted concrete functions, mostly `fallback_scalar_usercopy`. |
| UNKNOWN_OBJECT | 0 dominant top-MEPC volume | 0.0% | none | medium | Dominant formerly unknown rows are repaired. Residual non-dominant invalid rows and fallback ambiguity counters remain caveats. |

## 8.4 Family by Workload

| Workload | VDSO_TIME_UPDATE | RSEQ_ABI | ROBUST_FUTEX_EXIT | USER_STRING_COPY | GENERIC_UACCESS | KERNEL_MEMCPY_ADJACENT | MAPPING_TEARDOWN | UNKNOWN |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 0 | 5,868 | 941 | 0 | 947 | 0 | 0 | 0 |
| 2 | 0 | 6,388 | 1,020 | 0 | 1,095 | 0 | 0 | 0 |
| 3 | 0 | 6,093 | 6,095 | 0 | 4,128 | 0 | 0 | 0 |
| 4 | 0 | 0 | 0 | 0 | 28,440 | 0 | 0 | 0 |
| 5 | 0 | 0 | 0 | 0 | 42,821 | 0 | 0 | 0 |
| 6 | 0 | 0 | 0 | 0 | 26,606 | 4,030 | 0 | 0 |
| 7 | 0 | 0 | 0 | 0 | 11,295 | 32,198 | 0 | 0 |
| 8 | 0 | 3,477 | 1,144 | 0 | 0 | 0 | 0 | 0 |

Pattern: RSEQ and robust-futex are concentrated in the smaller startup/fork/shared-memory cases. The larger file/pipe workloads are dominated by generic usercopy and adjacent bulk-memory routines.

## 8.5 Family by Broad Category

Authoritative final stats category totals:

| Broad category | Total traps | Share of all final traps |
| --- | ---: | ---: |
| syscall_buffer_path | 162,230 | 88.9% |
| teardown_mapping_update | 20,356 | 11.1% |

The table below uses the `cat=` field printed on final MEPC rows. Its denominator is the printed per-MEPC category volume, not the authoritative stats category total, because some final MEPC row `cat=` volume over-assigns to `syscall_buffer_path` relative to the stats category counters. That mismatch is an observed reporting caveat, not a workload failure.

| Broad category from MEPC rows | Family | Top-MEPC volume | Share within printed MEPC category |
| --- | --- | ---: | ---: |
| syscall_buffer_path | GENERIC_UACCESS | 111,220 | 62.3% |
| syscall_buffer_path | KERNEL_MEMCPY_ADJACENT | 36,228 | 20.3% |
| syscall_buffer_path | RSEQ_ABI | 21,826 | 12.2% |
| syscall_buffer_path | ROBUST_FUTEX_EXIT | 9,200 | 5.2% |
| teardown_mapping_update | GENERIC_UACCESS | 4,112 | 100.0% |

Conclusion for `syscall_buffer_path`: it is too broad as an optimization target. In current-tree evidence it mainly contains generic usercopy and adjacent memory routines, with smaller RSEQ and robust-futex components. It is not a synonym for VDSO/VVAR.

## 8.6 Candidate Optimization Ranking

| Rank | Optimization candidate | Supporting family | Estimated trap share | Implementation scope | Safety risk | Expected payoff | Recommendation |
| ---: | --- | --- | ---: | --- | --- | --- | --- |
| 1 | generic syscall staging / explicit typed mediation portal | GENERIC_UACCESS plus KERNEL_MEMCPY_ADJACENT | 83.0% combined; 63.2% generic alone | medium | medium | high | First target. Keep original user pages private; use typed copied/staged data and do not alias or unseal ordinary user pages. |
| 2 | rseq disable experiment or rseq ABI fast path | RSEQ_ABI | 12.0% | small | medium | medium-low | Defer. Useful but no longer dominant. |
| 3 | robust futex NULL/empty fast path | ROBUST_FUTEX_EXIT | 5.0% | small | medium | low | Defer. Concrete but not the first payoff target. |
| 4 | mapping teardown batching / metadata cache / lazy teardown | broad `teardown_mapping_update` overlay | 11.1% broad category | medium | medium | low-medium | Defer. It is a remaining category, but final top PCs do not show a distinct teardown MEPC family dominating. |
| 5 | pathname/string mediation portal | USER_STRING_COPY | 0.0% | medium | medium | low | Defer. No `strncpy_from_user` top row observed in this current evidence set. |
| 6 | VDSO/VVAR special classification | VDSO_TIME_UPDATE | 0.0% current-tree top-MEPC volume | medium | high | low for current tree | Do not carry forward the old VDSO-first closeout as current-tree validated. |
| 7 | attribution repair | residual caveats only | no dominant unknown top-MEPC volume | small | low | unknown | Not the first target for this closeout. A separate robustness slice may reduce ambiguity/overwrite counters, but it is not the single blocker now. |

## 8.7 Unknown Breakdown

| Unknown subtype | Count in final dominant top-MEPC volume | Treatment |
| --- | ---: | --- |
| MEPC_SYMBOL_MISSING | 0 | Top PCs resolved with `riscv-linux/System.map`. |
| MEPC_OUTSIDE_VMLINUX | 0 | No top PC used here fell outside the symbolized kernel range. |
| OBJECT_KIND_UNKNOWN | 0 dominant volume | The previously blocking dominant direct-map rows gained useful object origin in the accepted 04:19 run. |
| BROAD_CATEGORY_ONLY | 20,356 as stats overlay | `teardown_mapping_update` remains a broad category, but it is not an unresolved MEPC family in the final top-MEPC table. |
| PFN_ORIGIN_MISSING | 0 for the required dominant repaired rows | Residual non-dominant invalid rows exist; final origin-repair counters still show ambiguity and overwrites. |
| NO_SYSCALL_CONTEXT | non-dominant caveat | Some accepted rows have `pid=0/syscall=-1/path=unknown`, but PFN-origin fields identify useful user-object origins for the dominant buckets. |
| NO_MAPPING_CONTEXT | non-dominant caveat | Some rows retain `range=[0,0)`; the decisive repaired rows for the required buckets have useful ranges. |
| PARSER_LIMITATION | 0 counted | Reduction used final printed summaries and System.map; it did not require addr2line/debug info. |
| TRUE_UNKNOWN | 0 dominant top-MEPC volume | No remaining dominant unknown bucket blocks the first optimization decision. |

Important caveat: final origin-repair `leaf_origin` overwrite counters were run 1 `0`, run 2 `77`, run 3 `239`, run 4 `164`, run 5 `95`, and run 6 `247`; final `pfn_fallback_ambiguous` counters were run 1 `0`, run 2 `1536`, run 3 `3280`, run 4 `4920`, run 5 `3597`, and run 6 `4920`. Those counters mean the attribution mechanism is lossy/ambiguous under pressure. They do not change the closeout verdict because the required dominant rows gained useful unique attribution in the accepted child analysis.

## 8.8 Hotspot Chain Interpretation

This closeout identifies the dominant hotspot family and protected object kind, but it does not yet uniquely identify a full Linux caller chain for every dominant row.

What is now well supported:

- The broad `syscall_buffer_path` bucket is not a single mechanism and is not VDSO/VVAR-dominant in the current tree.
- The largest concrete MEPC family is `fallback_scalar_usercopy` / GENERIC_UACCESS.
- The adjacent large bucket is `__memset` / `crc32_le_generic.part.0`, treated here as KERNEL_MEMCPY_ADJACENT because the accepted origin rows point to ordinary private user-origin pages.
- The dominant object kind is ordinary private user data: mostly `PRIVATE_FILE_COW` and `PRIVATE_STRICT_ANON` ranges recovered through PFN-origin attribution.

Representative current-tree evidence:

- Workload 4, `cat /etc/hostname; echo done`, ends with 28,440 traps, all attributed to GENERIC_UACCESS in the final family table. Its representative final row is `pc=ffffffff80a20dfa` (`fallback_scalar_usercopy+0xaa`) with `origin_source=pa_pfn_fallback`, nonzero `cid`, `origin_va=3f8bd4e000`, `range=[3f8bd4d000,3f8bd4f000)`, and `class=PRIVATE_STRICT_ANON` in `logs/t4_count_origin_repair_03_20260502_040238_qemu_20260502_040632.log:29796`.
- Workload 5, `echo alpha | cat; echo done`, ends with 42,821 traps, all attributed to GENERIC_UACCESS in the final family table. Its representative rows include `pc=ffffffff80a20dfa` (`fallback_scalar_usercopy+0xaa`) and `pc=ffffffff80a20d7a` (`fallback_scalar_usercopy+0x2a`), both recovered to `class=PRIVATE_FILE_COW`, `origin_source=pa_pfn_fallback`, nonzero `cid`, and a useful file-COW range in `logs/t4_count_origin_repair_04_20260502_040633_qemu_20260502_041039.log:37257` and `:37259`.
- Workload 6, `wc -c /etc/hostname; echo done`, ends with 26,606 GENERIC_UACCESS traps plus 4,030 KERNEL_MEMCPY_ADJACENT traps. The adjacent row `pc=ffffffff80a1ffd8` resolves to `crc32_le_generic.part.0+0x22` and maps back to `class=PRIVATE_STRICT_ANON`, `origin_source=pa_pfn_fallback`, nonzero `cid`, and `range=[3fb2da4000,3fb2da6000)` in `logs/t4_count_origin_repair_05_20260502_041040_qemu_20260502_041438.log:31432`.
- Workload 7, `echo alpha | wc -c; echo done`, is the largest final workload at 43,493 traps. It has 11,295 GENERIC_UACCESS traps and 32,198 KERNEL_MEMCPY_ADJACENT traps. Representative `__memset`-range rows include `pc=ffffffff80a20a1c`, `pc=ffffffff80a20a20`, and `pc=ffffffff80a20a0c`, all mapped to `class=PRIVATE_FILE_COW`, `origin_source=pa_pfn_fallback`, nonzero `cid`, `origin_va=2ae7dbc000`, and `range=[2ae7cc8000,2ae7dc1000)` in `logs/t4_count_origin_repair_06_20260502_041438_qemu_20260502_041842.log:38110-38112`.

What remains unresolved at caller-chain level:

- Many dominant MEPC rows are S-mode direct-map rows with `syscall=-1`, `path=unknown`, and sometimes `pid=0`. That means the final MEPC rows are reliable for the kernel instruction family and object kind, but they are not always tied to a live syscall context.
- The syscall-context buckets show that the same workload also has mapping, fork/exec, user-buffer read/write, file-path, and unknown syscall activity. For example workload 7 includes buckets such as `nr=-1 path=unknown total=15479`, `nr=226 path=mapping_update total=4824`, `nr=220 path=fork_exec total=3796`, `nr=221 path=fork_exec total=2943`, `nr=63 path=user_buffer_write total=996`, and `nr=64 path=user_buffer_read total=699` in `logs/t4_count_origin_repair_06_20260502_041438_qemu_20260502_041842.log:38076-38085`. These buckets suggest that the generic-user-buffer cost is mixed across active syscall, mapping update, fork/exec, and inactive/direct-map contexts rather than being attributable to one syscall alone.
- Therefore the current evidence supports "generic usercopy and adjacent memory routines over private user-origin pages" as the first optimization target, but it does not prove that a single chain such as `sys_read -> copy_to_user` is the sole cause.

If a future planning round needs to choose a concrete insertion point before implementation, the narrow next attribution improvement should be caller-chain attribution for the dominant MEPC families: record `mepc + ra` or a small kernel call-site/caller bucket for `fallback_scalar_usercopy`, `__memset`, and `crc32_le_generic.part.0`, preserving syscall context where available. That would distinguish read/write user-buffer copies, fork/exec lifecycle work, mapping/mprotect updates, loader/file-COW activity, and pipe workloads without changing PRIVATE_DATA enforcement.

## Required Final Answers

1. `syscall_buffer_path` is too broad as an optimization target. It currently hides generic usercopy, adjacent memory routines, RSEQ, robust futex, and teardown-overlay effects.
2. The largest concrete MEPC family is GENERIC_UACCESS: 115,332 traps, 63.2% of the reduced final volume.
3. No. `update_vsyscall` / VDSO-VVAR is not the largest current-tree hotspot; it is 0 in the current final top-MEPC rows.
4. RSEQ ABI maintenance accounts for 21,826 traps, 12.0%.
5. Robust futex exit walk accounts for 9,200 traps, 5.0%.
6. True generic uaccess accounts for 115,332 traps, 63.2%; generic uaccess plus adjacent memory routines accounts for 151,560 traps, 83.0%.
7. User string/path copy accounts for 0 observed traps in the current final top-MEPC rows.
8. Mapping/teardown remains 20,356 traps as a broad stats category, 11.1%, but no distinct MAPPING_TEARDOWN MEPC family dominates after symbolization.
9. Yes, there is enough evidence to start one bounded optimization slice. The evidence is acceptable but suspicious as a general attribution mechanism because of leaf-origin overwrites, high PFN fallback ambiguity, and residual non-dominant invalid rows.
10. The single recommended first optimization target is an explicit typed syscall/usercopy mediation or staging portal for generic user buffers. It must preserve the all-private baseline and must not unseal or alias original ordinary user pages.

## Acceptance Criteria Check

| Criterion | Result |
| --- | --- |
| Workload results unchanged | Pass: final accepted evidence has all eight workloads code-0; retry filled the earlier run 2/run 6 timeout gap. |
| No enforcement behavior changed by this slice | Pass: this closeout is analysis/reporting only. |
| No ordinary user page unsealed | Pass: no policy change or unseal action in this analysis slice. |
| Top MEPCs symbolized | Pass: top PCs resolved with `riscv-linux/System.map`. |
| Top MEPCs grouped into families | Pass. |
| `syscall_buffer_path` broken down | Pass, with a reporting caveat about MEPC `cat=` volume versus stats category totals. |
| Object-kind summary produced | Pass. |
| Unknown breakdown produced | Pass. |
| Candidate optimization ranking produced | Pass. |
| Exactly one first optimization target recommended | Pass: explicit typed syscall/usercopy mediation or staging portal. |
| If insufficient evidence, recommend one repair | Not needed for this closeout. A future attribution robustness slice is optional, not the blocker. |

## Evidence / Inference Boundary

Observed evidence:

- Launcher status lines for fresh, retry, and 04:19 origin-repair runs.
- VM output markers and `ssh-auto-exit` code-0 lines.
- Final QEMU `PRIVATE_DATA trap stats`, category counters, hotspot rows, MEPC rows, origin fields, and leaf-origin counters.
- `riscv-linux/System.map` symbol names and addresses.
- Completed child packet analysis results.

Inference:

- Grouping PCs into MEPC families.
- Treating `memset` and `crc32_le_generic.part.0` rows as KERNEL_MEMCPY_ADJACENT and as supporting the same generic user-buffer mediation candidate when their accepted origin rows point to PRIVATE_FILE_COW or PRIVATE_STRICT_ANON user-origin pages.
- Treating residual invalid/non-dominant rows and high ambiguity counters as evidence-quality caveats rather than proof of workload failure.
- Selecting generic usercopy mediation/staging as the first optimization target.

This report does not prove that the PFN-origin cache is lossless, does not authorize relaxing PRIVATE_DATA/private-bitmap enforcement, and does not authorize VMA/ELF-derived unsealing of ordinary user pages.
