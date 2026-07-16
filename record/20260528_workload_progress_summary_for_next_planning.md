# 2026-05-28 Workload Progress Summary For Next Planning

## Purpose

This note is a compact handoff for discussing NaCC's next step with another
assistant. It summarizes the completed workload/SUM-trap task series as of
2026-05-28, using the completed task packets and human reports as the source of
truth. It intentionally does not rely on `docs/workflow/CURRENT_STATE.md`.

## Current Bottom Line

The current tree passed a fresh full workload 1-8 validation rerun:

- Packet: `docs/workflow/tasks/completed/TASK_20260528_120936_rerun_wrapup.md`
- Command: `config/debug-batch.sh --cmd-file config/debug-batch.uaccess_loop_broad_eight_current_tree_validation.txt --tag-prefix rerun_wrapup`
- Batch log: `logs/test_runner/TASK_20260528_120936_rerun_wrapup_batch_20260528_123348.log`
- Result: all eight runs reported `status=ok`.
- VM-side result: every run reached `[NaCC][ssh-auto-exit] code=0`.
- Log-analysis result: no `SUM on`, `SUM off`, standalone `SUM`, `sstatus.*SUM`, panic/Oops/BUG/unhandled-trap/fatal-fault signature, SSH retry loop, or Docker command failure was found in the fresh QEMU/VM logs.

This is high-confidence evidence that the previously observed workload SUM trap
sequence no longer reproduces in the canonical workload 1-8 pass on the current
tree. It is not exhaustive proof for all workloads, stress conditions, or future
code states.

## Experimental Arc

The recent work moved from observing accidental trap-time private-data fallback
to replacing the important user access paths with explicit Linux-to-OpenSBI
mediated helpers.

1. SUM-off workload sweep
   - Packet: `TASK_20260520_113130_all_workloads_sum_off_walkthrough`
   - Workloads 4-8 completed without a clear kernel Oops/BUG marker.
   - Final accounting snapshots reported `sum_off=0`.
   - This did not identify a direct SUM-off repair target.

2. SUM-on strict fallback diagnosis
   - Packet: `TASK_20260520_141343_all_workloads_sum_on`
   - Workload 1 initially completed through fallback/emulation while QEMU/OpenSBI reported 1522 SUM-on PRIVATE_DATA traps.
   - A diagnostic SUM-on strict-deny hook showed the first concrete stop in `sys_openat` filename copying, symbolized to `strncpy_from_user()` / `do_strncpy_from_user()`.

3. String-read private get-user repair
   - Packet: `TASK_20260521_152437_analyse_sum_on`
   - Added a conservative `STRING_READ` / `FROM_USER` scope and scalar private `get_user` mediation.
   - Validation passed the old file-path/string-read stop and exposed a later `sys_read` / `user_buffer_write` private store boundary.

4. Profiling cleanup and agent frame repair
   - Packet: `TASK_20260523_001714_slimer`
   - Removed old profiling/context bucket machinery and kept only functional active-scope state plus aggregate SUM-on/SUM-off trap counts.
   - Runtime exposed an agent/trampoline unwind mismatch: Linux `do_trap_ecall_u` compiled with an 80-byte frame while `agent/src/entry.S::__offset80` still unwound 96 bytes.
   - Updating the agent unwind to 80 bytes removed the old agent-range crash and exposed the next private uaccess blockers.

5. Strict SUM-on trap fallback enforcement
   - Packet: `TASK_20260524_174106_sum_on_traps`
   - OpenSBI strict `SUM=on` private-data trap denial was enabled for load/store/CBO-zero fallback paths.
   - Workload 1 then stopped at `sys_read` copying into a private user buffer through `_copy_to_iter()` / `raw_copy_to_user()` / `fallback_scalar_usercopy`.

6. Explicit private `copy_to_user`
   - Packet: `TASK_20260525_000037_private_read_usercopy_sumon_repair`
   - Added a `raw_copy_to_user()` dispatcher and page-bounded OpenSBI helper for private user destinations.
   - OpenSBI validates private writable user destination and normal readable supervisor source before M-mode copying.
   - The previous `sys_read` private destination denial disappeared; the next stop became `rseq` scalar `put_user`.

7. Descriptor-backed string-read route
   - Packet: `TASK_20260525_211200_scope_get_user`
   - Reworked string reads toward a descriptor-backed Route B: OpenSBI prepares bounded private C-string results at scope begin, and Linux consumes staged data/metadata.
   - Fixed early exec-time `create_elf_tables()` / `strnlen_user()` failure by enabling SUM around the descriptor begin ecall and making normal/non-private unhandled pages return unsupported/fallback.
   - Validation passed the early string-read failure and reached the expected later rseq `put_user` boundary.

8. Scalar private `put_user`
   - Packet: `TASK_20260526_161413_rseq_put_user_discussion`
   - Added scalar private `put_user` mediation as one explicit OpenSBI ecall per scalar private write.
   - The previous `clear_rseq_cs()` private store denial did not recur.
   - The next exposed blocker was private `copy_from_user` / load mediation through `sys_rt_sigaction`.

9. Private bulk `copy_from_user`
   - Packet: `TASK_20260527_000836_continue_sumon`
   - Added a mirrored `raw_copy_from_user()` path and page-bounded OpenSBI helper for private user sources.
   - Workload 2 reached `kernel_write_done` and exited code 0 without the old `sys_rt_sigaction` / `fallback_scalar_usercopy` private-load denial.

10. Scalar `put_user` COW retry
    - Packet: `TASK_20260527_134754_private_put_user_cow_retry`
    - OpenSBI now returns a distinct COW-needed/retry status when a valid private user leaf is missing `PTE_W`.
    - Linux uses `fault_in_safe_writeable()` and retries the private scalar write once.
    - The old `private-put-user-write-denied err=-4` fork/rseq symptom disappeared; the next blocker was signal-frame private stack clearing.

11. Private `clear_user`
    - Packet: `TASK_20260527_145405_signal_frame_private_stack_coredump_followup`
    - Added generic private `clear_user` / zero-to-user mediation.
    - Workload 3 cleared the signal-frame stage and printed `fork_private_done`.
    - Workloads 3-8 exited successfully in that packet. The only residual was one workload 8 raw `copy_to_user` strict-deny marker, while workload 8 still exited code 0.

12. Workload 8 `copy_to_user` prefault/retry
    - Packet: `TASK_20260527_202649_wrapup`
    - Diagnostics showed active NaCC `copy_to_user` helper attempts fell through because destination resolution returned `NOT_SUPPORTED`, then scalar uaccess hit strict SUM-on denial.
    - Linux added a one-shot per-chunk `fault_in_safe_writeable(dst, chunk)` retry before scalar fallback.
    - Workload 8 repair validation exited code 0 with no helper fallback, raw fallback, strict SUM-on deny, prefault-failed, denied, or bad-result markers.

13. Final workload 1-8 rerun
    - Packet: `TASK_20260528_120936_rerun_wrapup`
    - Full canonical workload batch passed with all runs `status=ok`.
    - Log analyzer found no SUM-trap or refined fatal signature in the fresh logs.

## Current Technical Shape

The project is now closer to the intended model:

- Accidental OpenSBI trap-time fallback for private data is strict-denied for
  SUM-on and SUM-off cases instead of silently emulating important accesses.
- Intentional Linux accesses to private user data are being routed through
  explicit OpenSBI helpers, where the monitor walks the current address space
  and validates tags, permissions, width/range, task/root context, and page
  boundaries.
- Implemented helper families now include:
  - descriptor-backed string read / C-string measure/copy staging;
  - scalar private `get_user` read;
  - scalar private `put_user` write, including COW-needed retry;
  - page-bounded private `copy_to_user`;
  - page-bounded private `copy_from_user`;
  - page-bounded private `clear_user`.
- The old profiling bucket/context-feed machinery has been removed or reduced.
  Remaining private-data accounting is intended to be small and functional,
  not a large diagnostic framework.

## Important Evidence Boundaries

- The final pass is one fresh canonical workload 1-8 pass, not a stress matrix.
- Several earlier packets closed by showing progress past the packet's original
  blocker, even when a later blocker appeared. That is intentional and should
  not be overread as full correctness at each intermediate point.
- The coredump/writeback `__memcpy` strict SUM-off panic was observed multiple
  times earlier as a downstream symptom, but it did not recur in the final
  successful workload batch. It has not been isolated as a separately solved
  coredump design problem.
- Workload 8 repair still left non-blocking `dst_resolve rc=-2` diagnostics in
  one T2 run, but the downstream helper fallback/raw fallback/strict-deny chain
  was absent. The final 1-8 rerun had no SUM/fatal signature.
- The agent return shim still depends on the compiled Linux
  `do_trap_ecall_u` frame size. The 80-byte value is currently correct for the
  built tree, but the mechanism is brittle.

## Recommended Next-Step Discussion Surface

Good next discussion questions:

1. Should the next phase prioritize broader validation or design cleanup?
   - Validation options: repeat workload 1-8 multiple times, add stress loops,
     run mixed private/non-private boundary cases, or add fork/signal/rseq-heavy
     targeted workloads.
   - Cleanup options: reduce diagnostic noise, add explicit success markers for
     prefault/retry paths, or simplify now-stabilized helper APIs.

2. Should coredump/private-page behavior become an explicit policy task?
   - Earlier logs showed private-data reads during coredump/writeback could hit
     strict SUM-off denial and panic.
   - Current final workload pass does not reproduce it, so a new packet should
     first decide whether coredump should be disabled, sanitized, mediated, or
     treated as out of scope for protected private pages.

3. Should the agent/Linux trap-frame coupling be hardened?
   - The 96-byte to 80-byte unwind repair fixed the current failure.
   - A robust next step could remove the magic frame-size dependency or add a
     build-time/runtime consistency check.

4. Should the helper ABI be documented as the main design result?
   - The recent work has effectively defined the NaCC private-user-access ABI.
   - A design note could document all helper families, return conventions,
     fallback rules, COW retry semantics, and fail-closed cases.

5. Should the final current-tree state be frozen in a commit/checkpoint?
   - Some task packets mention scoped commits, but the repo has a broad dirty
     worktree. Before starting another repair phase, it would be useful to
     explicitly audit and preserve the known-good state that passed the fresh
     workload 1-8 rerun.

## Suggested Prompt For Web ChatGPT

Use this prompt if handing the summary to another assistant:

> We are working on NaCC, a RISC-V confidential-container prototype. The recent
> task series replaced accidental SUM-on/SUM-off private-data trap fallback with
> explicit Linux-to-OpenSBI helpers for string reads, scalar get_user/put_user,
> copy_to_user, copy_from_user, clear_user, and COW retry. A fresh canonical
> workload 1-8 rerun on 2026-05-28 completed with all runs status=ok and no SUM
> or fatal trap signatures in QEMU/VM logs. Please help plan the next phase:
> broader validation versus design cleanup/documentation, with special attention
> to coredump/private-page policy, agent trap-frame coupling, helper ABI
> documentation, and freezing the current known-good state.
