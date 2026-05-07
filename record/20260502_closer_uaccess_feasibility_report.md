# T5.0 Closer Uaccess Feasibility Report

Generated: 2026-05-02 18:41:06 +0800

Source packet: `record/closer_task_packet.md`
Current validation authority: `logs/t5-uaccess-closer-20260502_174902.launcher.log`

## A. Branch/Commit Inspected

- Superproject: `228a3d1`
- Linux: `bc4d680936a9`
- OpenSBI: `a8d6c08`
- Worktree note: the top-level worktree has broad pre-existing dirt; this report did not change code or rerun validation.

## B. Workload Pass/Fail Table

All eight workloads completed through authenticated SSH auto-run and ended with `[NaCC][ssh-auto-exit] code=0`.

| Run | Workload | VM output evidence | Status |
| --- | --- | --- | --- |
| 1 | `printf alpha >/dev/null; echo kernel_read_done` | `kernel_read_done` | pass |
| 2 | `IFS= read -r line </etc/hostname; echo kernel_write_done` | `kernel_write_done` | pass |
| 3 | anonymous/private fork repro | `fork_private_done` | pass |
| 4 | `cat /etc/hostname; echo done` | hostname plus `done` | pass |
| 5 | `echo alpha | cat; echo done` | `alpha`, `done` | pass |
| 6 | `wc -c /etc/hostname; echo done` | `13 /etc/hostname`, `done` | pass |
| 7 | `echo alpha | wc -c; echo done` | `6`, `done` | pass |
| 8 | shared-memory repro | `ping` | pass |

## C. GENERIC_UACCESS Total And Share

The source closeout baseline that triggered this closer task reports `GENERIC_UACCESS = 115,332 / 182,586` reduced final PRIVATE_DATA traps, or `63.2%`.

The fresh `174902` exact attribution layer reports `11,054` active raw-uaccess traps across `183,878` final PRIVATE_DATA traps, or `6.0%` of this run's final trap volume. This active-wrapper count is the decision-quality caller/path/direction evidence for this report; it is not treated as a replacement for the source closeout's broader MEPC-family total.

## D. KERNEL_MEMCPY_ADJACENT Total And Share

The source closeout baseline reports `KERNEL_MEMCPY_ADJACENT = 36,228 / 182,586`, or `19.8%`.

The fresh `174902` adjacent summaries are exact-filtered top-MEPC evidence, not a complete family-total table. They are suitable for relation analysis because every final adjacent row shows `active_uaccess_mepc_filter=exact`, `active_uaccess_mepc_slots=64`, and `active_uaccess_mepc_overflows=0`.

## E. Top Fallback Scalar Usercopy Callers

Final exact uaccess caller summaries are concentrated at the common raw-uaccess/fallback scalar copy layer, but immediate callers are not concentrated enough by themselves for a narrow caller-only portal.

| Caller/function bucket | Direction | Path | Traps | Share of exact active uaccess |
| --- | --- | --- | ---: | ---: |
| `copy_page_to_iter+0xa6` | `to_user` | `user_buffer_write` | 4,718 | 42.7% |
| `copy_strings.isra.0+0x196` | `from_user` | `fork_exec` | 1,000 | 9.0% |
| `__riscv_sys_rt_sigaction+0x50` | `from_user` | `unknown` | 672 | 6.1% |
| `cp_new_stat+0x108` | `to_user` | `unknown` | 608 | 5.5% |
| `load_elf_binary+0x1124` | `to_user` | `unknown` | 576 | 5.2% |
| `syscall_exit_to_user_mode+0x7c` | `to_user` | `unknown` | 560 | 5.1% |
| `do_trap_ecall_u+0x208` | `from_user` | `unknown` | 560 | 5.1% |

Top 1 immediate caller coverage is `42.7%`; top 2 is `51.7%`; top 5 is `68.5%`; top 6 crosses `70%`. The unifying abstraction is the Linux/RISC-V raw uaccess path, not one or two immediate call sites.

## F. Direction Summary

| Direction | Traps | Share |
| --- | ---: | ---: |
| `to_user` | 8,243 | 74.6% |
| `from_user` | 2,811 | 25.4% |
| `unknown` | 0 | 0.0% |

Direction attribution is good enough for a decision. The dominant first direction is `to_user`.

## G. Syscall/Path Summary

| Syscall/path/direction | Traps | Share | Sample caller |
| --- | ---: | ---: | --- |
| `63 user_buffer_write to_user` | 4,718 | 42.7% | `copy_page_to_iter+0xa6` |
| `221 fork_exec from_user` | 1,000 | 9.0% | `copy_strings.isra.0+0x196` |
| `260 unknown to_user` | 896 | 8.1% | `copy_siginfo_to_user+0x18` |
| `139 unknown from_user` | 728 | 6.6% | `do_trap_ecall_u+0x208` |
| `0 unknown to_user` | 704 | 6.4% | `load_elf_binary+0x92c` |
| `134 unknown from_user` | 672 | 6.1% | `__riscv_sys_rt_sigaction+0x50` |
| `80 unknown to_user` | 608 | 5.5% | `cp_new_stat+0x108` |
| `134 unknown to_user` | 504 | 4.6% | `__riscv_sys_rt_sigaction+0x7a` |

One syscall/path bucket does not reach `60%`; the top two do not reach `60%` either. The reason to proceed is not syscall concentration. The reason is that many paths share the same raw uaccess abstraction and a dominant `to_user` direction.

## H. Workload Summary

| Run | Private traps | Exact active uaccess | `to_user` | `from_user` | Top observed path |
| --- | ---: | ---: | ---: | ---: | --- |
| 1 | 8,136 | 651 | 562 | 89 | `unknown` |
| 2 | 8,575 | 753 | 559 | 194 | `unknown` |
| 3 | 16,198 | 924 | 682 | 242 | `unknown` |
| 4 | 32,900 | 1,973 | 1,482 | 491 | `fork_exec` |
| 5 | 40,712 | 2,259 | 1,632 | 627 | `unknown` |
| 6 | 28,332 | 2,039 | 1,527 | 512 | `fork_exec` |
| 7 | 44,284 | 2,291 | 1,664 | 627 | `unknown` |
| 8 | 4,741 | 164 | 135 | 29 | `unknown` |

## I. KERNEL_MEMCPY_ADJACENT Relation Analysis

Observed adjacent top rows remain mixed and relation is not proven:

- Long runs include `fallback_scalar_usercopy+0xaa`, `fallback_scalar_usercopy+0x2a`, and `__memset+0xc8..0xdc`.
- Shorter/smaller runs include `__rseq_handle_notify_resume`, `clear_rseq_cs.isra.0`, and `exit_robust_list`.
- All final adjacent rows are cleanly filtered from active raw-uaccess MEPCs; the residual scalar-copy rows are therefore not explained by active-MEPC table overflow.
- Caller is still printed as `unknown` in adjacent rows, and relation remains `unknown_relation`.

Decision: do not include `KERNEL_MEMCPY_ADJACENT` as guaranteed first-portal payoff. Treat it as possible secondary benefit only after a later semantic relation slice.

## J. Origin Quality Summary

For the exact active uaccess summaries:

| Origin field | Count |
| --- | ---: |
| `exact` | 9,168 |
| `pa_pfn_fallback` | 104 |
| `ambiguous` | 0 |
| `missing` | 1,782 |
| `leaf_origin_overwrites` | 654 |
| `pfn_fallback_ambiguous` | 17,663 |

Exact plus fallback origin covers `9,272 / 11,054` active uaccess traps, or `83.9%`. The top syscall/path rows report `origin_confidence=exact`. Origin quality is good enough for a bounded design recommendation, but not good enough to make adjacent-memory payoff claims.

## K. Portal Insertion Candidate Ranking

| Rank | Candidate | Estimated coverage | Scope | Risk | Recommendation |
| --- | --- | --- | --- | --- | --- |
| 1 | `copy_to_user` / raw-uaccess kernel-to-user mediation layer on the RISC-V raw usercopy path | `74.6%` of exact active uaccess direction; common raw wrapper observed across rows | medium | medium/high | proceed as T5.1 prototype |
| 2 | Selected syscall/path prototype: syscall `63`, `copy_page_to_iter+0xa6`, `user_buffer_write`, `to_user` | `42.7%` of exact active uaccess | small/medium | medium | acceptable narrower fallback |
| 3 | Full bidirectional raw-uaccess portal | `100%` of exact active uaccess but mixed semantics | large | high | defer |
| 4 | Adjacent `__memset` / rseq / robust-list optimization | relation unknown for this task | unknown | high | defer |

## L. Decision

GO for a bounded T5.1 portal prototype, but only for the dominant `to_user` / kernel-to-user raw-uaccess direction.

This is not a GO for broad syscall-router engineering, bidirectional mediation, ordinary user-page unsealing, shared aliasing, or adjacent-memory optimization. The acceptable first target is a directional and auditable copy-to-user/raw-uaccess mediation point that preserves the all-private PRIVATE_DATA baseline.

## M. Recommended First Prototype Scope

Prototype at the Linux/RISC-V `copy_to_user` raw-uaccess layer that reaches `fallback_scalar_usercopy`, constrained to `to_user` copies only. Use syscall `63` / `copy_page_to_iter+0xa6` / `user_buffer_write` as the first validation workload and success metric because it is the largest exact path bucket at `42.7%`.

The insertion point should be above the per-instruction scalar loop and at or near the raw copy-to-user wrapper, so the prototype can mediate a bounded typed kernel-to-user buffer copy without treating Linux VMA/ELF/MEPC as authority and without unsealing original user pages.

## N. If Not Proceeding, Narrower Alternative

If planner decides the wrapper-level insertion is still too broad, the single narrower alternative is a selected syscall/path prototype for syscall `63` `user_buffer_write` via `copy_page_to_iter+0xa6`, still constrained to `to_user`. Do not switch to rseq, robust futex, teardown, VDSO/VVAR, manifest authority, or adjacent-memory optimization from this evidence.

## Evidence / Inference Boundary

Observed evidence:

- Build and execution evidence comes from the `174902` OpenSBI/Linux build logs, launcher log, and eight QEMU/VM log pairs.
- Final uaccess caller/path/direction rows are observed with `count_mode=exact`, `retained_table_overflows=0`, `uaccess_bucket_overflows=0`, and `uaccess_path_bucket_overflows=0`.
- Final adjacent rows are observed with `active_uaccess_mepc_filter=exact`, `active_uaccess_mepc_slots=64`, and `uaccess_active_mepc_overflows=0`.
- Symbol names are direct `vmlinux.asm` lookups from the observed PCs.

Inference:

- Grouping caller PCs into function/path buckets is a log-analyzer reduction.
- Treating the raw-uaccess wrapper as the unifying abstraction is an interpretation of the exact callee/caller rows.
- Ranking a `copy_to_user` raw-uaccess mediation layer as feasible applies the source packet decision rules to the observed direction and wrapper concentration.
- Excluding adjacent rows from guaranteed payoff is an inference from `caller=unknown`, `relation=unknown_relation`, mixed rseq/robust/memset/scalar-copy symbols, and the absence of a proven downstream relation.

## O. Supplemental Interpretation: MEPC-Family Hotspot Versus Syscall-Specific Routing

Added: 2026-05-02 19:59:53 +0800

This addendum refines the design interpretation after human review. Where sections K-M frame the next step around `copy_to_user`, syscall `63`, or `copy_page_to_iter`, treat those rows as validation context rather than the optimization boundary. The important correction is that caller/syscall attribution is useful for understanding the workload mix, but it should not become the optimization target by itself. NaCC should avoid a syscall-by-syscall repair strategy. Patching `read`, `write`, `stat`, `exec`, pipe, fork/exec, and every other Linux path one by one would turn this into ordinary Linux hot-path maintenance, which is explicitly not the desired optimization shape.

The stronger current signal remains the MEPC-family concentration from the current-tree hotspot closeout:

- Reduced final PRIVATE_DATA trap volume: `182,586`.
- `GENERIC_UACCESS`: `115,332` traps, `63.2%`.
- The `GENERIC_UACCESS` family was assigned by symbolizing trap-time MEPCs with `riscv-linux/System.map`; the decisive instruction family is `fallback_scalar_usercopy` / `__asm_copy_from_user` / `__asm_copy_to_user`.
- This is a low-level kernel instruction-family hotspot. It does not require knowing that a specific syscall, such as syscall `63`, is the semantic cause before it can be considered a central optimization entry.

The later `174902` active-uaccess layer answers a narrower question:

- Final PRIVATE_DATA traps in that run: `183,878`.
- Exact active raw-uaccess traps: `11,054`, or `6.0%`.
- `to_user` within active raw-uaccess: `8,243`, or `74.6%` of active raw-uaccess.
- Top active path, syscall `63` / `copy_page_to_iter+0xa6` / `user_buffer_write`: `4,718`, or `42.7%` of active raw-uaccess, but only about `2.6%` of all final PRIVATE_DATA traps.

The active-uaccess total is exact for its instrumentation scope; it is not known to be limited by bucket sampling in the `174902` run because the final logs report `uaccess_bucket_overflows=0`, `uaccess_path_bucket_overflows=0`, and `uaccess_active_mepc_overflows=0`. However, it is still a wrapper-context subtotal, not a replacement denominator for the MEPC-family hotspot. It should be treated as caller/direction evidence for the subset of traps that occurred while Linux's raw-copy wrapper context was active.

Therefore the right interpretation is:

- `copy_page_to_iter+0xa6` is not the main PRIVATE_DATA hotspot. It is the largest observed caller/path inside the exact active raw-uaccess subset.
- The main hotspot candidate is still the MEPC family around `fallback_scalar_usercopy`, because that family accounts for `63.2%` of the reduced current-tree PRIVATE_DATA volume.
- The gap between `63.2%` MEPC-family volume and `6.0%` active-wrapper volume does not disprove the MEPC hotspot. It shows that wrapper-context telemetry is narrower than the MEPC-family classification and that a future design should not be justified only by syscall/path rows.

### Revised Optimization Shape

The preferred next design target should be framed as a centralized `fallback_scalar_usercopy` / RISC-V uaccess-loop mediation prototype, not a selected-syscall optimization.

The future prototype should aim at the common copy loop or immediately surrounding raw uaccess machinery, preserving these constraints:

- Do not unseal ordinary user pages.
- Do not alias original user pages into a shared aperture.
- Do not use Linux VMA, ELF, syscall number, or MEPC alone as authority to relax PRIVATE_DATA.
- Treat MEPC as an execution-location proof for selecting a mediation path, not as ownership authority for the data being accessed.
- Validate every mediated range against the protected task / PFN ownership metadata that NaCC already uses for PRIVATE_DATA enforcement.
- Keep the operation bounded, directional when needed, auditable, and fail-closed back to ordinary trapping if range/state checks are incomplete.

Caller/syscall attribution remains useful, but as validation and safety context:

- It helps choose representative workloads.
- It helps verify that the prototype does not silently depend on one Linux syscall.
- It helps explain direction mix and regression behavior.
- It should not cause the project to implement one-off fixes for syscall `63`, `221`, `80`, `134`, or any other individual Linux path.

### Feasibility Analysis

Feasibility is better for a MEPC-family prototype than for syscall-specific routing, because the observed concentration is already at the instruction-family layer. The project can target one central RISC-V uaccess loop rather than dozens of Linux callers.

Potentially feasible route:

- Add a narrow T5.1 planning/coder packet for a `fallback_scalar_usercopy` MEPC-family mediation experiment.
- First perform denominator reconciliation: for every trap whose MEPC resolves inside `fallback_scalar_usercopy` / `__asm_copy_*_user`, print whether `uaccess_active` was true, the current trap direction if known, the fault VA / target PFN, and whether bounded copy-loop state can be recovered.
- If register state and PFN ownership checks are sufficient, prototype a monitor-mediated bounded copy for a small range, then fall back to normal per-access trapping whenever the state is not exactly recognized.
- Use syscall `63` / `copy_page_to_iter+0xa6` only as an early validation workload because it is reproducible and visible in the active subset, not because syscall `63` is the optimization target.

Main risks:

- `fallback_scalar_usercopy` is shared by `copy_from_user` and `copy_to_user`, and RISC-V aliases `__asm_copy_from_user` and `__asm_copy_to_user` to the same assembly body. Direction may need to come from register semantics, load/store trap type, wrapper context, or an explicit entry marker.
- The scalar loop contains byte, word, aligned, and misaligned-copy cases. A prototype should start with the simplest exactly recognized case and fall back for the rest.
- MEPC proves where execution is, not whether the target PFN is safely mediable. PFN ownership and current protected-task identity must remain the authority.
- Adjacent memory rows (`__memset`, `crc32`, rseq, robust-list) should not be folded into the first payoff estimate until their relation to the uaccess loop is proven.

Revised recommendation:

- Keep the attribution closeout, but refine the next-step framing.
- Do not start a syscall-specific `copy_page_to_iter` optimization.
- Do not require full caller-chain attribution before any optimization planning.
- Start from the MEPC-family hotspot: `fallback_scalar_usercopy` / `__asm_copy_*_user`.
- Treat caller/syscall attribution as a validation lens, not as the optimization boundary.
