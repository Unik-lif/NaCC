# Task Packet

- Task ID: TASK_20260414_113719_private_bitmap
- Created: 2026-04-14 11:37:19 +0800
- Priority: P1
- Lane: A
- Packet Type: execution
- Owner Role: human
- Status: done
- Goal: Enforce real private-bitmap protection for NACC user data leaf pages so Linux S-mode can no longer directly read or directly write those `PRIVATE_DATA` PFNs; both access types should trap and be mediated by the monitor, and the resulting trap surface should be measurable.
- Critical Intent: Turn the existing `PRIVATE_DATA` PFN tag from a log-only marker into enforced protection. The first acceptable landing must deny both Linux S-mode loads and stores to tagged private user pages, route those faults through the existing access-fault path, and let the monitor emulate the required access so current NaCC flows can still run while trap cost is measured. A direct Linux access that still succeeds without entering the monitor-visible mediation path does not satisfy this task even if the workload appears to keep running.
- Preferred Shape: Reuse the existing 2-bit PFN tag model and the existing QEMU/OpenSBI access-fault path. Centralize Linux S-mode deny/enforcement in `qemu/target/riscv/cpu_helper.c`; perform the authorized emulated load/store in OpenSBI `sbi_trap_ldst.c`; keep Linux changes optional and minimal; and add bounded counters plus sampled fault PCs so trap origins can be attributed after a run. Deny only the targeted Linux S-mode accesses; keep current M-mode and agent access behavior unchanged unless a narrowly-scoped bug fix is required to make mediation correct.
- Disallowed Shape: Leaving `PRIVATE_DATA` in log-only mode; landing a store-only fallback without first updating this packet; adding rich per-page owner/refcount/COW metadata; widening Linux into a broad explicit "ask M-mode to touch user data" ABI at many call sites; relying only on raw log spam without bounded stats; mixing secure non-leaf PTP protection into the bitmap scope; or silently clearing / retagging `PRIVATE_DATA` pages just to keep smoke tests green.
- Allowed Freedom: The coder may keep lifecycle handling coarse, reuse the current monotonic `PRIVATE_DATA` tagging model, choose a simple bounded representation for counters and sampled PCs, and add one narrow debug dump hook if needed for trap statistics. The first cut may focus on correctness and observability over performance. A fixed-size ring, bounded sample array, or top-N bucketed representation is acceptable for PC attribution. If the runtime immediately proves that full load+store mediation cannot land without staged fallback, the packet must be updated before landing that fallback because the intended target shape is full mediation.
- Scope:
  - existing `PRIVATE_DATA` PFN tags produced by `nacc_sync_private_tags()` and `sm_nacc_set_ptes()`
  - QEMU-side Linux S-mode access checks for tagged private-data PFNs
  - OpenSBI load/store access-fault emulation for those tagged PFNs
  - trap-cost observability sufficient to identify whether traps are dominated by copy paths, COW, or other kernel access sites
- Constraints:
  - Full protection comes first: tagged NACC user data pages must no longer be directly read or directly written by Linux S-mode.
  - First landing targets both read and write mediation for `PRIVATE_DATA`; store-only protection is not an acceptable silent scope reduction.
  - Prefer trap-detect-and-monitor-emulate over invasive Linux MM rewrites.
  - Preserve current Linux-native fork / exec / page-fault structure as much as possible outside the trap mediation path.
  - Keep secure non-leaf PTP pages out of bitmap scope.
  - Same-CID fork inheritance remains allowed; do not add per-page sharing metadata.
  - Do not turn the monitor into a full Linux MM shadow.
  - The work is explicitly a strawman cost-study implementation and may be slow.
- Open Semantic Questions:
  - No blocking intent ambiguity remains at planner level: the target landing is full load+store mediation for `PRIVATE_DATA`, not observation-only tagging and not store-only staging.
  - Remaining operational choice: use the narrowest bounded stats dump surface that works, with `SBI_EXT_LINUX_DEBUG` reuse preferred over a new persistent ABI.
  - Remaining operational choice: if a helper is needed for VA-to-PA resolution or tag checks, place it in the smallest existing OpenSBI helper surface rather than creating a new subsystem.
- Human Concern: Current bitmap tagging is security-insufficient because Linux can still directly read or directly modify the tagged NACC user data pages. The human wants both access types to be monitor-mediated first, then an honest measurement of how many traps that causes and where those traps originate.
- Reconciliation Required: no
- Post-Run Analysis Required: no
- Definition Of Done: On a rebuilt tree, Linux can no longer directly read or directly write NACC user data leaf pages tagged as `PRIVATE_DATA`; both relevant loads and stores are observed reaching a monitor-visible trap/emulation path; and the monitor performs the emulated access needed for the bounded smoke set to continue. At minimum, direct Linux modification of those pages no longer succeeds without a trap, and targeted kernel-read plus kernel-write user-buffer repros both demonstrate mediation. A bounded runtime smoke set still completes, and the logs/counters are good enough to tell whether the dominant trap sources are copy paths, COW, or other kernel access sites.
- Related State:
  - `docs/workflow/CURRENT_STATE.md`
  - `docs/workflow/NEXT_STEPS.md`
- Related Ticket / Plan:
  - `docs/workflow/tasks/completed/TASK_20260410_111541_bitmap.md`
  - `docs/workflow/chatgpt_bitmap_plans.md`
- Branch / Worktree: `main` workspace with local subrepo edits expected
- Validation Tier: T2

## Reference Values

- Priority: `P0` / `P1` / `P2` / `P3`
- Lane: `A` / `B` / `C`
- Packet Type: `execution` / `planning` / `analysis`
- Owner Role: `human` / `planner` / `coder` / `reviewer` / `test_runner` / `log_analyzer`
- Status: `draft` / `in_progress` / `needs_review` / `changes_requested` / `needs_test` / `test_failed` / `blocked` / `done`
- Validation Tier: `T0` / `T1` / `T2` / `T3`
- Reconciliation Required: `yes` / `no`

## Required Artifacts

- Patch or commit: code changes primarily in `qemu/`, `opensbi/`, and packet/docs only if needed; `linux/` only if a minimal debug-dump hook or test plumbing is required
- Minimal compile result:
  - `make qemu`
  - `make opensbi`
  - `make linux-update` only if Linux files change
- Test command or batch plan:
  - existing smoke after rebuild:
    - `docker run --security-opt seccomp=unconfined --rm busybox sh -c "cat /etc/hostname; echo done"`
  - existing shared-memory regression smoke:
    - `docker run --security-opt seccomp=unconfined --rm -v /root/nacc_shm_repro:/nacc_shm_repro:ro busybox /nacc_shm_repro`
  - targeted private-data mediation repro:
    - use or add a minimal repro that exercises:
      - kernel read from a user buffer
      - kernel write into a user buffer
      - `fork` + private-page write to provoke COW/copy activity
  - capture trap counters or sampled fault PCs and correlate hot PCs against the built Linux image to identify source functions
- Log path if validation fails: `logs/*private_bitmap*`, or the standard batch launcher / QEMU / VM logs with the trap-stat dump called out explicitly

## Latest Summary

- Reviewer follow-up confirms the landed shape is faithful to this packet on the current QEMU virt scope: QEMU denies Linux S-mode `PRIVATE_DATA` load/store, OpenSBI mediates the resulting faults through the existing access-fault path including the narrow `cbo.zero` follow-up, and the clean T2 batch satisfies the packet definition of done.
- Follow-up coder analysis corrected the first-failure mechanism: `clear_page+0x10` is the first `CBO_ZERO(a0)` in `linux/arch/riscv/lib/clear_page.S`, so the fatal run-1 fault came from unsupported `cbo.zero` mediation on a tagged `PRIVATE_DATA` page, not from a proven direct-map VA-resolution miss.
- The follow-up fix stays inside the preferred control model: `opensbi/lib/sbi/sbi_trap_ldst.c` now intercepts `cbo.zero` in the store-access path, validates the aligned target PFN as `PRIVATE_DATA`, zeroes the 64-byte cache block in M-mode, records it in the bounded width stats as `other=64`, and resumes Linux without widening the ABI.
- A fresh T2 batch (`private-bitmap-batch-20260414_154000`) now completes cleanly for runs 1 through 5: run 1 prints `kernel_read_done`, run 2 prints `kernel_write_done`, run 3 prints `fork_private_done`, run 4 prints `hostname` plus `done`, and run 5 prints `ping`, with no late `clear_page()` panic in the new logs.
- Human intent seed was supplied on 2026-04-14 and this packet now intentionally pulls `PRIVATE_DATA` protection ahead of the older "later hardening item" backlog order.
- The pre-task repo state already had the PFN tag model and `PRIVATE_DATA` tagging in place; this landed diff flips QEMU from `log-only` observation to enforced deny for Linux S-mode loads and stores, and the follow-up runtime batch validates that route on the current platform scope.
- Human clarified that full Linux read+write mediation is required for `PRIVATE_DATA`; write-only mediation is not sufficient for this packet.
- The chosen route is to reuse the existing QEMU/OpenSBI access-fault path and convert `PRIVATE_DATA` from observation into enforced trap-and-emulate protection, with attribution data attached.
- This packet intentionally overrides older workflow notes that still classify bitmap protection as a later `P3` hardening item; for this task only, `PRIVATE_DATA` user-leaf protection is active `P1` execution work.
- Log review shows the first runtime bad point is earlier than the invalid run-3 fork repro: run 1 reaches `kernel_read_done` and then panics in `clear_page()` on a tagged `PRIVATE_DATA` PFN. Run 3 is still invalid, but it is not the first failure in this batch.

## Next Handoff

- Next owner: human
- Handoff type: review the approved packet and successful T2 artifacts, then archive or close the packet
- Trigger: reviewer confirmed spec fidelity and risk acceptability after the clean `private-bitmap-batch-20260414_154000` run on the bounded current-platform scope
- Exact artifact to read first: `docs/workflow/tasks/active/TASK_20260414_113719_private_bitmap.md`
- Exact logs to read first:
  - `logs/private_bitmap_fix_04_20260414_161015_vm_20260414_161458.log`
  - `logs/private_bitmap_fix_04_20260414_161015_qemu_20260414_161458.log`
  - `logs/private_bitmap_fix_03_20260414_160530_vm_20260414_161015.log`
  - `logs/private_bitmap_fix_03_20260414_160530_qemu_20260414_161015.log`
  - `logs/private_bitmap_fix_05_20260414_161459_vm_20260414_161942.log`
  - `logs/private_bitmap_fix_05_20260414_161459_qemu_20260414_161942.log`
  - `config/debug-batch.private_bitmap_t2.txt`

## Coder Result

- Implementation summary:
  - `qemu/target/riscv/cpu_helper.c` now enforces `PRIVATE_DATA` as a deny policy for Linux S-mode `MMU_DATA_LOAD` and `MMU_DATA_STORE`, returning the same access-fault classification already used for protected NaCC paths instead of leaving the tag in observation-only mode.
  - `opensbi/lib/sbi/sbi_trap_ldst.c` now has an explicit `PRIVATE_DATA` load-emulation branch and an explicit `PRIVATE_DATA` store-emulation branch before platform fallback. Both resolve `tval` through the current `satp` root, verify that the resolved PFN is tagged `NACC_PFN_TAG_PRIVATE_DATA`, and perform the requested access directly in M-mode so Linux resumes through the existing trap-emulation path.
  - The store path keeps the implementation narrow: normal byte/half/word/dword stores are copied directly in M-mode, and the already-recognized `amoswap` store form is handled explicitly with writeback to `rd`. Other unsupported widths/forms are rejected explicitly instead of widening the ABI.
  - Bounded observability now lives in OpenSBI near the mediation path: total load/store trap counters, per-width buckets split by access type, and a fixed-size approximate top-PC table keyed by `mepc`.
  - No Linux code changes were required. The existing `SBI_EXT_LINUX_DEBUG` path is reused by extending `sm_pgtbl_debug()` to dump `PRIVATE_DATA` trap stats alongside the existing page-table debug output, which Linux already invokes on the NaCC mm teardown/debug path.
- Commit or patch:
  - working tree patch only in this coder pass
  - touched files:
    - `qemu/target/riscv/cpu_helper.c`
    - `opensbi/lib/sbi/sbi_trap_ldst.c`
    - `opensbi/include/sbi/sbi_trap_ldst.h`
    - `opensbi/lib/sbi/sm/sm.c`
    - this packet
- Route chosen and why:
  - followed the packet’s preferred route exactly: deny Linux S-mode access in QEMU by PFN tag, then mediate the access in OpenSBI through the existing load/store access-fault path
  - this kept scope bounded to QEMU/OpenSBI, preserved the current control model, avoided a new Linux-side per-access mediation ABI, and made trap attribution local to the monitor path where `mepc`, access type, and width are already visible
- Escalations made:
  - none
- Remaining risks:
  - runtime validation is still pending; this coder pass confirms build integration, not live smoke behavior
  - the `PRIVATE_DATA` tag lifecycle remains intentionally coarse/monotonic in this round
  - the bounded PC table is approximate rather than exact heavy-hitter accounting
  - the store path explicitly supports ordinary stores plus the existing `amoswap` form; if runtime surfaces another legitimate store instruction pattern, capture it before widening support

## Review Result (Initial Pre-Test Review)

- Approval status: approve-with-conditions
- Spec fidelity: acceptable; the landed shape matches the packet's preferred route and stays within the intended control model
- Fidelity findings:
  - `PRIVATE_DATA` is no longer log-only in QEMU for Linux S-mode data access. `get_physical_nacc_tag_check()` now denies both `MMU_DATA_LOAD` and `MMU_DATA_STORE` on tagged `PRIVATE_DATA` PFNs and feeds the existing access-fault classification via `TRANSLATE_NACC_PGD_CHECK_FAIL` in [qemu/target/riscv/cpu_helper.c](/home/link/NaCC/qemu/target/riscv/cpu_helper.c:957).
  - OpenSBI now has explicit `PRIVATE_DATA` mediation before generic fallback for both access types. The new load path resolves `tval` through the current `satp` root, verifies the PFN tag, performs the read in M-mode, and records bounded stats in [opensbi/lib/sbi/sbi_trap_ldst.c](/home/link/NaCC/opensbi/lib/sbi/sbi_trap_ldst.c:492). The store path does the same for ordinary stores plus explicit `amoswap` handling in [opensbi/lib/sbi/sbi_trap_ldst.c](/home/link/NaCC/opensbi/lib/sbi/sbi_trap_ldst.c:680).
  - Observability stays bounded and attributable inside OpenSBI, not in a widened Linux ABI: total load/store counters, width buckets, and a fixed-size approximate top-PC table are implemented in [opensbi/lib/sbi/sbi_trap_ldst.c](/home/link/NaCC/opensbi/lib/sbi/sbi_trap_ldst.c:45), and the dump is reused through the existing `SBI_EXT_LINUX_DEBUG` path in [opensbi/lib/sbi/sm/sm.c](/home/link/NaCC/opensbi/lib/sbi/sm/sm.c:200).
  - The landing stayed within the allowed route. No new Linux-side per-access mediation ABI was introduced, and the touched code stays in `qemu/`, `opensbi/`, plus this packet.
- Risk review: acceptable to proceed to targeted runtime validation, but only with explicit watchpoints for unsupported instruction forms and for trap-stat capture
- Risk findings:
  - Unsupported instruction-form risk remains real. The generic load decode used by `sbi_load_access_handler()` does not cover `lr.*`, and the generic store decode only reaches ordinary stores plus the explicitly-recognized `amoswap` form; `sc.*` and other AMOs still redirect instead of being mediated in [opensbi/lib/sbi/sbi_trap_ldst.c](/home/link/NaCC/opensbi/lib/sbi/sbi_trap_ldst.c:239) and [opensbi/lib/sbi/sbi_trap_ldst.c](/home/link/NaCC/opensbi/lib/sbi/sbi_trap_ldst.c:368). If runtime surfaces futex-style LR/SC or another non-`amoswap` AMO on `PRIVATE_DATA`, that is first-failure evidence to hand back, not a test-side scope change.
  - Trap attribution is dumped only through the existing debug/teardown call sites, not continuously. The dump path is reachable via `pgtbl_debug()` from [linux/mm/memory.c](/home/link/NaCC/linux/mm/memory.c:1936), [linux/mm/mmap.c](/home/link/NaCC/linux/mm/mmap.c:2066), and [linux/arch/riscv/mm/nacc.c](/home/link/NaCC/linux/arch/riscv/mm/nacc.c:110). If a repro wedges before those paths run, lack of stats does not prove lack of mediation.
- Can proceed to test: yes, with conditions: run the targeted kernel-read, kernel-write, and `fork` + private-page-write repros first; preserve the first deny/mediation evidence and the first trap-stat dump; if unsupported instruction forms or direct unmediated access appear, stop and route back to coder with first-failure artifacts
- Requirements checked directly from code:
  - QEMU deny branch for Linux S-mode `PRIVATE_DATA` load/store: [qemu/target/riscv/cpu_helper.c](/home/link/NaCC/qemu/target/riscv/cpu_helper.c:957)
  - OpenSBI bounded stats and PC attribution: [opensbi/lib/sbi/sbi_trap_ldst.c](/home/link/NaCC/opensbi/lib/sbi/sbi_trap_ldst.c:45)
  - OpenSBI `PRIVATE_DATA` load mediation before platform fallback: [opensbi/lib/sbi/sbi_trap_ldst.c](/home/link/NaCC/opensbi/lib/sbi/sbi_trap_ldst.c:544)
  - OpenSBI `PRIVATE_DATA` store mediation before root/platform fallback: [opensbi/lib/sbi/sbi_trap_ldst.c](/home/link/NaCC/opensbi/lib/sbi/sbi_trap_ldst.c:757)
  - Existing debug hook reused for stats dump: [opensbi/lib/sbi/sm/sm.c](/home/link/NaCC/opensbi/lib/sbi/sm/sm.c:200)
- Human-facing summary: The code shape is faithful to the packet: `PRIVATE_DATA` moved from observation to enforced Linux S-mode deny in QEMU, OpenSBI now mediates both load and store access faults through the existing trap path, and bounded attribution data is present without widening Linux ABI scope. The remaining work is runtime proof, with explicit attention to unsupported LR/SC or other non-`amoswap` atomic forms if they show up.

## Test Result

- Command run:
  - `make qemu`
  - `make opensbi`
  - `config/debug-batch.sh --session-name private-bitmap-batch-20260414_144840 --tag-prefix private_bitmap --wait-after-auto 180 --cmd-file config/debug-batch.private_bitmap_t2.txt`
- Build actions:
  - rebuilt only the task-owned touched components
  - `make qemu`: success
  - `make opensbi`: success
  - no Linux rebuild was needed because this landing stayed inside `qemu/` and `opensbi/`
- Outcome:
  - Batch session `private-bitmap-batch-20260414_144840` completed with harness summary `status=ok` for runs 1 through 5
  - Run 1 targeted kernel-read repro completed; VM log shows `kernel_read_done`
  - Run 2 targeted kernel-write repro completed; VM log shows `kernel_write_done`
  - Run 3 intended `fork` + private-page-write repro did not execute correctly; VM log shows `sh: syntax error: unexpected \")\" (expecting \"done\")`
  - Run 4 existing smoke completed far enough for logger capture and produced QEMU/VM artifacts
  - Run 5 shared-memory regression smoke completed; VM log shows `ping`
  - QEMU logs for the valid runs captured `deny PRIVATE_DATA` entries plus repeated `PRIVATE_DATA trap stats` dumps
  - The valid runs are not clean: runs 1, 2, 4, and 5 each later end with `Oops - store (or AMO) access fault` followed by `Kernel panic - not syncing: Fatal exception in interrupt` in the QEMU log
  - The earliest such failure is run 1, after `kernel_read_done`, at `clear_page+0x10` under `__handle_mm_fault`
  - Run 4 never prints `hostname` or `done` in the VM log before its later panic
  - A follow-up single-command rerun for the corrected fork workload was prepared, but the user intentionally interrupted it before completion; no launcher log or live tmux session remained from that aborted rerun
  - Packet-level result for this pass: `test_failed`, because the first valid runtime artifact already panics and the requested T2 fork/private-page-write repro was also invalid
- Artifact / log path:
  - batch launcher:
    - `logs/private-bitmap-batch-20260414_144840.launcher.log`
  - run 1:
    - `logs/private_bitmap_01_20260414_144840_qemu_20260414_145329.log`
    - `logs/private_bitmap_01_20260414_144840_vm_20260414_145329.log`
  - run 2:
    - `logs/private_bitmap_02_20260414_145329_qemu_20260414_145812.log`
    - `logs/private_bitmap_02_20260414_145329_vm_20260414_145812.log`
  - run 3 invalid fork workload:
    - `logs/private_bitmap_03_20260414_145813_qemu_20260414_150300.log`
    - `logs/private_bitmap_03_20260414_145813_vm_20260414_150300.log`
  - run 4:
    - `logs/private_bitmap_04_20260414_150300_qemu_20260414_150745.log`
    - `logs/private_bitmap_04_20260414_150300_vm_20260414_150745.log`
  - run 5:
    - `logs/private_bitmap_05_20260414_150745_qemu_20260414_151228.log`
    - `logs/private_bitmap_05_20260414_150745_vm_20260414_151228.log`
  - updated batch plan for the corrected fork workload:
    - `config/debug-batch.private_bitmap_t2.txt`
  - rebuilt outputs:
    - `riscv-qemu/bin/qemu-system-riscv64`
    - `opensbi/build/platform/generic/firmware/fw_payload.bin`

## Analysis Result

- First bad point:
  - The first real failure in this batch is not the malformed run-3 fork repro. It appears earlier in run 1: after `kernel_read_done`, the kernel takes `Oops - store (or AMO) access fault [#1]` at `clear_page+0x10` while inside `__handle_mm_fault`, then panics.
- Evidence:
  - `logs/private_bitmap_01_20260414_144840_vm_20260414_145329.log:10` shows `kernel_read_done`, so the targeted repro reached user-visible completion before the fatal fault.
  - `logs/private_bitmap_01_20260414_144840_qemu_20260414_145329.log:1694` logs `[USER] pte 47ecbcd7 pa 11fb2f000 [level 0]`.
  - The same run’s Oops frame at `logs/private_bitmap_01_20260414_144840_qemu_20260414_145329.log:11166` onward shows `epc : clear_page+0x10/0xc2`, `a4 : 000000011fb2f000`, and `badaddr: ffffffd69fb2f000`. That ties the faulting kernel address to the same physical page logged as a user leaf PFN.
  - The same late failure pattern repeats in runs 2, 4, and 5: `clear_page+0x10` store fault, then kernel panic, on physical pages `0x11f3b6000`, `0x11f4ca000`, and `0x11f6fb000` respectively.
  - Run 3 is still invalid evidence for fork/COW. `logs/private_bitmap_03_20260414_145813_vm_20260414_150300.log:11` shows `sh: syntax error: unexpected ")"`, and the auto-run line above it shows the shell command was already mangled before execution.
- Likely cause:
  - High-likelihood narrow bug: the new QEMU policy denies any Linux S-mode load/store to PFNs tagged `PRIVATE_DATA` by physical tag, including kernel linear/direct-map aliases used by routines like `clear_page()`.
  - OpenSBI’s `PRIVATE_DATA` mediation path currently resolves only the faulting `tval` through the current `satp` root before checking the PFN tag. That matches the logs: a kernel direct-map alias of a tagged user PFN faults in `clear_page()`, but the access is not successfully mediated and instead returns as a fatal Linux store fault.
  - This is still within the bounded coder route. The logs do not yet force a planner-level conclusion such as richer ownership metadata or a broader Linux-side mediation ABI.
- Confidence:
  - High that the first bad point is run 1 `clear_page()` store faulting on a tagged `PRIVATE_DATA` PFN.
  - Medium-high that the immediate cause is over-broad S-mode deny plus incomplete mediation for kernel direct-map aliases; this matches both the log addresses and the current QEMU/OpenSBI implementation shape.
  - High that the run-3 fork artifact is a separate test-command failure and should not be treated as the first runtime fault.
- Recommended next step:
  - Next hop should be `coder`, not `planner`.
  - Fix the direct-map alias case inside the current bounded mediation route, then rerun run 1, run 2, and the corrected run-3 fork repro from `config/debug-batch.private_bitmap_t2.txt`.
  - If the only viable fix would require richer per-page ownership metadata or a broader Linux mediation ABI, stop there and reroute to planner with the `clear_page()` first-failure evidence preserved.

## Coder Follow-up Result

- Implementation summary:
  - Follow-up code and log reading corrected the immediate bug: `clear_page+0x10` is the first `cbo.zero` in `linux/arch/riscv/lib/clear_page.S`, so the first failing path was the generic OpenSBI store decoder rejecting an unsupported store-form before `PRIVATE_DATA` mediation ran.
  - `opensbi/lib/sbi/sbi_trap_ldst.c` now adds a narrow `cbo.zero` handler ahead of `sbi_trap_emulate_store()`. It fetches the trapped instruction, matches only `cbo.zero`, aligns the fault address to the cache-block boundary, resolves the aligned target through the existing `PRIVATE_DATA` PFN-tag check, zeros the 64-byte block in M-mode, records the trap in the existing bounded stats, and advances `mepc`.
  - Existing `PRIVATE_DATA` load handling, ordinary store handling, and `amoswap` handling remain intact; no Linux or QEMU code changes were needed in this follow-up pass.
- Commit or patch:
  - working tree patch only in this follow-up coder pass
  - touched files:
    - `opensbi/lib/sbi/sbi_trap_ldst.c`
    - this packet
- Route chosen and why:
  - kept the fix inside the already-approved OpenSBI access-fault path instead of widening Linux or introducing richer metadata
  - matched the first observed failing instruction form exactly, which is the least invasive route that preserves the packet’s intended control model
- Escalations made:
  - requested approval to rerun the tmux-based validation batch after sandboxed tmux socket access was denied
- Remaining risks:
  - `PRIVATE_DATA` mediation still does not cover LR/SC or non-`amoswap` AMOs; if runtime surfaces those on tagged pages, capture them as the next bounded instruction-form gap
  - the `cbo.zero` handler uses the current QEMU virt platform block size of 64 bytes, which matches local artifacts (`final.dts` advertises `riscv,cboz-block-size = <0x40>`); if the platform block size changes, that plumbing should be widened deliberately rather than inferred ad hoc

## Test Follow-up Result

- Command run:
  - `make opensbi`
  - `config/debug-batch.sh --session-name private-bitmap-batch-20260414_154000 --tag-prefix private_bitmap_fix --wait-after-auto 180 --cmd-file config/debug-batch.private_bitmap_t2.txt`
- Build actions:
  - rebuilt only the touched component in this follow-up pass
  - `make opensbi`: success
  - no `make qemu` or `make linux-update` was needed because the follow-up change stayed inside `opensbi/`
- Outcome:
  - Batch session `private-bitmap-batch-20260414_154000` completed with harness summary `status=ok` for runs 1 through 5
  - Run 1 targeted kernel-read repro completed; VM log shows `kernel_read_done`, and the paired QEMU log no longer ends with `clear_page+0x10`
  - Run 2 targeted kernel-write repro completed; VM log shows `kernel_write_done`, and the paired QEMU log ends in normal teardown/debug output
  - Run 3 corrected `fork` + private-page-write repro executed literally and completed; VM log shows `fork_private_done`
  - Run 4 existing smoke completed with visible `hostname` plus `done`; the QEMU trap stats include `PRIVATE_DATA width store: ... other=64`, which is the new `cbo.zero` path
  - Run 5 shared-memory regression smoke completed; VM log shows `ping`
  - No new run in this batch shows `Oops - store (or AMO) access fault` or `Kernel panic - not syncing`
- Artifact / log path:
  - run 1:
    - `logs/private_bitmap_fix_01_20260414_155556_qemu_20260414_160041.log`
    - `logs/private_bitmap_fix_01_20260414_155556_vm_20260414_160041.log`
  - run 2:
    - `logs/private_bitmap_fix_02_20260414_160041_qemu_20260414_160530.log`
    - `logs/private_bitmap_fix_02_20260414_160041_vm_20260414_160530.log`
  - run 3:
    - `logs/private_bitmap_fix_03_20260414_160530_qemu_20260414_161015.log`
    - `logs/private_bitmap_fix_03_20260414_160530_vm_20260414_161015.log`
  - run 4:
    - `logs/private_bitmap_fix_04_20260414_161015_qemu_20260414_161458.log`
    - `logs/private_bitmap_fix_04_20260414_161015_vm_20260414_161458.log`
  - run 5:
    - `logs/private_bitmap_fix_05_20260414_161459_qemu_20260414_161942.log`
    - `logs/private_bitmap_fix_05_20260414_161459_vm_20260414_161942.log`
  - rebuilt output:
    - `opensbi/build/platform/generic/firmware/fw_payload.bin`

## Analysis Follow-up Result

- Corrected first-failure mechanism:
  - The old “direct-map alias not resolved” hypothesis is weaker than the code-backed explanation. `logs/private_bitmap_01_20260414_144840_qemu_20260414_145329.log` reports `epc : clear_page+0x10/0xc2`, and `linux/arch/riscv/lib/clear_page.S` shows `clear_page+0x10` is the first `CBO_ZERO(a0)`.
  - That means the first missing path was an unsupported store-form in the OpenSBI decoder, not a demonstrated requirement for richer ownership metadata or a broader Linux mediation ABI.
- New evidence:
  - `logs/private_bitmap_fix_04_20260414_161015_qemu_20260414_161458.log` shows `PRIVATE_DATA width store: ... other=64`, which is the expected signature of mediated `cbo.zero`
  - The same run reaches visible `hostname` plus `done`, and the new batch contains no late `clear_page()` panic
  - `logs/private_bitmap_fix_03_20260414_160530_vm_20260414_161015.log` now prints `fork_private_done`, so the fork/COW-oriented repro is finally valid evidence instead of a malformed harness command

## Review Follow-up Result

- Findings:
  - No blocking spec-fidelity or risk issue remains in the landed route on the current QEMU virt scope.
  - The `cbo.zero` fix is the least invasive correction consistent with the packet intent: it stays inside `opensbi/lib/sbi/sbi_trap_ldst.c`, is limited to tagged `PRIVATE_DATA`, and does not widen Linux ABI surface, bitmap scope, or page-ownership metadata.
  - The observability requirement is satisfied with bounded monitor-side data rather than raw log spam alone: run 4 records `PRIVATE_DATA width store: ... other=64`, and the preserved `mepc` buckets map in `vmlinux.asm` to `update_vsyscall`, which is sufficient to classify the dominant source as an "other kernel access site" in this smoke rather than leaving attribution implicit.
- Approval status: approve
- Spec fidelity: pass
- Risk review: pass
- Can proceed to test: yes; satisfied by `private-bitmap-batch-20260414_154000`
- Change summary:
  - QEMU now denies Linux S-mode `PRIVATE_DATA` loads and stores by PFN tag, OpenSBI mediates load/store faults through the existing access-fault path, the narrow follow-up adds `cbo.zero` mediation for the observed `clear_page()` path, and bounded trap counters plus `mepc` buckets remain in the monitor path.
- Validation gaps:
  - No blocking validation gap remains for packet closure on the current bounded platform scope.
  - Residual non-blocking watchpoints remain:
    - `lr/sc` and non-`amoswap` AMOs are still unsupported for `PRIVATE_DATA`
    - the `cbo.zero` path is intentionally fixed to the current virt `riscv,cboz-block-size = <0x40>` scope
    - trap dumps still depend on the existing debug/teardown call sites
- Next handoff:
  - Next owner: human
  - Trigger: reviewer approved the landed route after the clean T2 batch; review the packet, archive it, and open a new packet only if a later platform or instruction-form extension is needed
  - Exact artifact to read first: `docs/workflow/tasks/active/TASK_20260414_113719_private_bitmap.md`

## Reconciliation Notes

- `docs/workflow/CURRENT_STATE.md` and `docs/workflow/NEXT_STEPS.md` still describe bitmap protection as a later hardening item. This packet supersedes that ordering for the narrow scope of `PRIVATE_DATA` user leaf-page protection.
- This override is intentionally narrow. It does not authorize a broader redesign of NaCC runtime-context ownership, explicit Linux mediation ABIs, or secure non-leaf PTP protection under the bitmap umbrella.
- If full load+store mediation immediately exposes a deeper blocker that cannot be solved inside the bounded route, capture the first-failure evidence, update this packet, and hand back to planner rather than silently widening scope.

## Planner Route

### Route Chosen And Why

- Reuse the current PFN-tag model and the already-working `ROOT_L0` trap path shape instead of inventing a new metadata plane.
- Push enforcement to the same place that already sees the physical page and access type:
  - QEMU classifies and blocks the Linux S-mode access.
  - OpenSBI handles the resulting access fault and performs the authorized memory access in M-mode.
- Reason:
  - this is the narrowest route that gives real protection
  - it preserves Linux-native MM structure outside the trap path
  - it naturally exposes the trap rate and hot PCs needed for the cost study

### Work Slices

- Slice 1: flip `PRIVATE_DATA` from observation to protection in QEMU
  - entry point: `qemu/target/riscv/cpu_helper.c`
  - keep `ROOT_L0` logic unchanged
  - make tagged `PRIVATE_DATA` accesses by Linux S-mode fail through the same access-fault shape already used for protected root writes
  - retain explicit access-type distinction so logs/counters can separate load vs store

- Slice 2: add `PRIVATE_DATA` mediation in OpenSBI load/store access handlers
  - entry point: `opensbi/lib/sbi/sbi_trap_ldst.c`
  - extend `sbi_ld_access_emulator()` and `sbi_st_access_emulator()` with a `PRIVATE_DATA` branch before platform fallback
  - on fault:
    - resolve `tval` VA through the current root to a physical target
    - confirm the target PFN is tagged `PRIVATE_DATA`
    - perform the requested byte/word access directly in M-mode
    - return through the existing OpenSBI trap-emulation path so Linux resumes as if the access succeeded
  - keep M-mode and agent accesses unchanged
  - unsupported instruction forms should stay narrow and explicit; if runtime shows a new legitimate form, record it before widening support
  - success condition for this slice is not "store path works"; both load and store branches must exist unless the packet is updated first

- Slice 3: add trap-source observability
  - preferred placement: OpenSBI, near the `PRIVATE_DATA` access-emulation branch
  - minimum stats:
    - total `PRIVATE_DATA` load traps
    - total `PRIVATE_DATA` store traps
    - width buckets
    - a bounded top-N or sampled list of faulting `mepc` PCs
  - the stats should be cheap and bounded; do not add unbounded per-page history
  - if a dump hook is needed, keep it minimal:
    - reuse `SBI_EXT_LINUX_DEBUG` with a narrow subcommand or equivalent bounded debug path
    - avoid inventing a large new management ABI
  - test-side attribution can then map hot `mepc` PCs back to Linux functions such as copy helpers or COW paths

- Slice 4: keep tagging/lifecycle coarse
  - continue using the current `PRIVATE_DATA` tagging points:
    - `nacc_sync_private_tags()`
    - `sm_nacc_set_ptes()`
  - same-CID fork inherited pages remain tagged
  - do not add precise `PRIVATE_DATA` untagging, refcounts, owner tables, or a VMA mirror in this round
  - if coarse monotonic tagging causes ambiguity in logs, document it as a bounded limitation instead of expanding the metadata model

### Execution Rules

- `PRIVATE_DATA` enforcement must remain tag-based plus privilege-based. Do not add new per-page ownership or sharing metadata just to decide whether a trap is allowed.
- The primary success path is existing access-fault reuse, not a new Linux call-out ABI. Any Linux changes should be optional debug/test plumbing only.
- Preserve explicit attribution by access type and width. The coder should not collapse all mediated accesses into a single undifferentiated counter.
- The first unsupported instruction form, translation mismatch, or trap storm that threatens baseline behavior should be captured as evidence and written back into the packet before scope is widened.

### Stop And Replan Triggers

- Only one side of the mediation pair lands cleanly:
  - load works but store does not, or store works but load does not
- Correctness appears to require richer page ownership / refcount / COW metadata than the current bounded tag model
- Correctness appears to require a broad Linux-side explicit mediation ABI at multiple call sites rather than reusing the current access-fault path
- The first viable implementation would need to pull secure non-leaf PTP protection into scope
- Trap accounting cannot reliably distinguish `PRIVATE_DATA` mediation faults from unrelated background faults with bounded stats
- The existing access-fault path cannot resume Linux correctly after a mediated legitimate access and would require a broader control-flow redesign

### Likely File Entry Points

- `qemu/target/riscv/cpu_helper.c`
- `opensbi/lib/sbi/sbi_trap_ldst.c`
- `opensbi/lib/sbi/sm/vm.c` if a tiny helper for `PRIVATE_DATA` resolution/tag checks is useful
- `opensbi/lib/sbi/sm/bitmap.c` only if stats or helper plumbing belongs there
- `opensbi/lib/sbi/sbi_ecall_nacc.c`
- `opensbi/include/sm/bitmap.h`
- `opensbi/include/sm/sm.h`
- `linux/arch/riscv/mm/nacc.c`
- `linux/arch/riscv/kernel/sys_riscv.c`
- `linux/arch/riscv/include/asm/nacc.h`

### Validation Order

- Build the touched components first.
- Run a targeted private-data repro before broad container smoke so the first bad point is easier to interpret.
  - kernel reads from a user buffer must show mediated load behavior
  - kernel writes into a user buffer must show mediated store behavior
  - `fork` plus private-page write should be attempted to surface copy / COW-origin traps
- Then run the existing container smokes to check whether the strawman protection immediately regresses current baseline behavior.
- Capture and preserve the first trap-stat dump that shows dominant PCs or categories.
- If the hot PCs map to COW or copy helpers, record that directly in the packet instead of leaving the result implicit in raw logs.

### Acceptance Checklist For Coder / Reviewer

- QEMU no longer treats Linux S-mode access to `PRIVATE_DATA` PFNs as observation-only; the access is denied into the existing access-fault path
- OpenSBI has explicit `PRIVATE_DATA` mediation branches for both load and store emulation before generic fallback
- Successful mediation remains narrow:
  - applies to tagged `PRIVATE_DATA` user leaf pages
  - does not broaden into non-leaf PTP protection
  - does not depend on new rich page metadata
- Observability is bounded and attributable:
  - total load traps and total store traps are visible
  - width buckets are visible
  - a bounded set of faulting `mepc` PCs is preserved for symbol attribution
- The preserved evidence is sufficient to tell whether the first dominant trap sources look like copy helpers, COW, or another kernel access site

### Non-Goals

- Do not redesign NaCC into a process-level enclave model.
- Do not add per-page owner CID tables, refcounts, or rich sharing metadata.
- Do not bring secure non-leaf PTP pages into bitmap scope.
- Do not redesign Linux memory allocation into a monitor-only allocator path.
- Do not attempt precise page-lifecycle retirement for every private PFN in this stage.
- Do not widen Linux into a broad explicit per-access SBI mediation ABI if the trap path can carry the job.

## Log Analyzer Follow-up Result

- Scope of this readout:
  - This follow-up analyzes the clean `private_bitmap_fix_*` artifacts after the `cbo.zero` fix, with focus on final mediated-trap counts and dominant origin PCs for planner use.
  - The exact total load/store counters and width buckets are exact per-run counters.
  - The `mepc` table is intentionally approximate top-hot-PC attribution from a bounded 8-slot table; treat it as heavy-hitter guidance, not an exact full histogram.
- Final trap counts by run:
  - Run 1 kernel-read repro: `load=9434 store=24865 total=34299` in `logs/private_bitmap_fix_01_20260414_155556_qemu_20260414_160041.log:11242`
  - Run 2 kernel-write repro: `load=9530 store=24788 total=34318` in `logs/private_bitmap_fix_02_20260414_160041_qemu_20260414_160530.log:11415`
  - Run 3 corrected `fork` + private-page-write repro: `load=18373 store=45006 total=63379` in `logs/private_bitmap_fix_03_20260414_160530_qemu_20260414_161015.log:16743`
  - Run 4 `cat /etc/hostname; echo done`: `load=25501 store=60460 total=85961` in `logs/private_bitmap_fix_04_20260414_161015_qemu_20260414_161458.log:23714`
  - Run 5 shared-memory smoke: `load=11937 store=874 total=12811` in `logs/private_bitmap_fix_05_20260414_161459_qemu_20260414_161942.log:6587`
  - Batch sum across these five successful runs: `load=74775 store=155993 total=230768`
- Width breakdown from the final stats:
  - Runs 1 through 4 are dominated by 8-byte accesses, then 4-byte accesses. Example run 4 ends with `load: 8=17807 4=7365 1=329` and `store: 8=38856 4=20994 1=546 other=64` at `logs/private_bitmap_fix_04_20260414_161015_qemu_20260414_161458.log:23715`
  - Run 5 is overwhelmingly load-heavy and almost entirely 8-byte loads: `load: 8=11891 1=46`, `store: 8=374 4=306 1=194` at `logs/private_bitmap_fix_05_20260414_161459_qemu_20260414_161942.log:6588`
  - `other=64` in run 4 is not 64 bytes of data accounting; it means 64 mediated store traps whose width was outside `1/2/4/8`. On this tree that corresponds to 64 trapped `cbo.zero` 64-byte block clears after the follow-up fix.
- Dominant origin PCs seen in the final heavy-hitter tables:
  - Runs 1 through 4 end with the same hot-PC cluster around `0xffffffff800afac6` through `0xffffffff800afb8e`, which resolves in `riscv-linux/vmlinux` to `update_vdso_data` and `vdso_write_end` in `linux/kernel/time/vsyscall.c` and `linux/include/vdso/helpers.h`
  - Run 5 ends with a different hot-PC set:
    - `0xffffffff801573e2`, `0xffffffff8015748a`, `0xffffffff801576a2`, `0xffffffff801576ae`, `0xffffffff801576ba`, `0xffffffff801576c8` resolve to `clear_rseq_cs`, `rseq_get_rseq_cs`, and `rseq_update_cpu_node_id` in `linux/kernel/rseq.c`
    - `0xffffffff800b0c76`, `0xffffffff800b0ca8`, `0xffffffff800b0d06` resolve to `fetch_robust_entry` and `exit_robust_list` in `linux/kernel/futex/core.c`
    - Intermediate and earlier run-4 tables also show `__pi___memcpy`, `fallback_scalar_usercopy`, and `do_strncpy_from_user`, which means some mediated traffic is coming from usercopy/string-copy paths before the final top-8 converges back to the VDSO cluster
- What these counters are counting:
  - They count mediated Linux S-mode accesses to PFNs tagged `PRIVATE_DATA` after QEMU denies the direct access and OpenSBI emulates it in M-mode.
  - They do not count only "the user process wrote its own buffer". They also count kernel housekeeping and helper paths that touch those tagged pages on behalf of the process, which is why the hot PCs are kernel functions such as `update_vdso_data`, `rseq_*`, futex robust-list helpers, and usercopy helpers.
  - Because the top source in runs 1 through 4 is the VDSO update path, a large part of the measured trap surface is kernel-maintained runtime metadata touching tagged pages, not only application payload writes.
- Planner-facing interpretation:
  - The measured trap cost is already high on simple successful workloads: about `34k` traps for the minimal read/write repros, `63k` for the corrected fork/private-write repro, and `86k` for the small `hostname + done` smoke.
  - Across the batch, stores dominate overall (`155993 / 230768`, about two-thirds), but the shared-memory smoke is the opposite shape and is dominated by loads.
  - The evidence suggests the current page-granularity `PRIVATE_DATA` tag is coarse enough that it captures hot kernel-touched regions such as VDSO/rseq/usercopy-related pages. That does not by itself prove the final redesign, but it is concrete evidence that finer-grained tagging or a more selective tagging policy is worth planner attention.
- Confidence:
  - High on the per-run total counts and width buckets.
  - Medium-high on the source attribution by function name.
  - Medium on any design conclusion beyond "current granularity captures a lot of kernel-touch traffic", because the PC table is approximate and bounded.
- Recommended next step:
  - Next hop should be `planner`, not `coder`, if the goal is to discuss finer bitmap granularity or a more selective protection policy using these measured hot paths.
  - Return to `coder` only if the planner wants extra instrumentation such as exact per-PC histograms, per-VMA attribution, or separate accounting for VDSO/rseq/usercopy classes.
