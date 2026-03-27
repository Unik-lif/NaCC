# Current State

Last updated: 2026-03-27

## Current Goal

The project is no longer focused only on "can fork pass at all". The current goal is to push container-semantic coverage after partial fork smoke progress, with special attention to:

- multi-child / `wait` / pipeline behavior
- shared memory / `mmap` / `MAP_SHARED`
- small but real multi-process applications
- stability under repeated and concurrent runs

## Current Branch / Checkpoints

- main repo: `main`
- `linux/`: `main`
- `opensbi/`: `NoPIC`
- stable bootstrap entry: `docs/agent/SESSION_BOOTSTRAP.md`

## Latest Accepted Understanding

- `VM_NACC` / agent-aperture inheritance is no longer the primary issue.
- The old child `ptp_list` registration and `ptdesc->ptl` initialization problem is no longer the primary root cause.
- 2026-03-25 regression work confirmed that the old `fork child attach` PID mismatch has been fixed:
  - parent early registration now uses the global PID instead of `pid_vnr()`
  - `first-user-return attach` no longer hits `child pid ... is not registered`
  - attach failure paths now fail fast instead of leaving the child in `NACC_FORKED` and retrying repeatedly
- However, the same minimal fork+exec smoke:
  - `docker run --security-opt seccomp=unconfined --rm busybox sh -c "cat /etc/hostname; echo done"`
  still does not reliably produce visible VM-side `hostname` / `done` output, so attach success must not be misread as "fork+exec is fixed".
- Likewise, analysis of:
  - `docker run --security-opt seccomp=unconfined --rm busybox sh -c "echo alpha | wc -c; echo done"`
  suggests the problem is not simply "`wc` is broken". It still looks more like an execution-progress / file-backed fault / runtime continuation issue.
- The current long-term fork direction remains Linux-friendly fork:
  - Linux should stay on native fork/read/walk/accounting paths as much as possible
  - OpenSBI should be used only when secure page-table writes are required
  - the project should not keep expanding prototype-only bypass logic or semantic replay as the final model
- `bitmap` protection is still not implemented and remains a later security-hardening item, not a precondition for current semantic validation.
- The active standard fork path is no longer legacy `nacc_fork` bypass. The real path is Linux-native `dup_mmap()/copy_page_range()` plus NaCC hooks in `__pte_alloc/__pmd_alloc` and `set_pte/set_ptes`.
- `nacc_fork()` / `sm_nacc_fork()` are treated as legacy / compatibility paths, not the current semantic baseline.
- `NACC_FORKED` child handling now includes first-user-return attach:
  - parent registers `child pid -> cid` before `wake_up_new_task()`
  - the child fills in `VM_NACC`, agent mapping, and `NACC_STATE` before its first user return
  - after attach, the child converges to `NACC_INITED + mm ACTIVE`
- `exec` is currently modeled through the `NACC_EXEC` transition state:
  - `NACC_INITED -> NACC_EXEC` happens before `bprm_mm_init()`
  - the fresh exec `mm` is built on the normal Linux page-table path first
  - successful exec later converges through `nacc_exec()` / `sm_nacc_exec()` to finish `transfer_ptp + VM_NACC + attach`
  - if exec fails before point-of-no-return, `free_bprm()` restores `NACC_EXEC -> NACC_INITED`
- Historical names such as `SBI_EXT_*REEXEC` and `AGENT_REEXEC_ENTRY_OFFSET` are intentionally kept as ABI / fixed-entry names and are no longer treated as a naming-cleanup priority.
- Pushed checkpoints currently referenced in this phase:
  - `linux`: `1f2f4c92d67f` `[CODE]: linux attach forked child and unify exec state`
  - `opensbi`: `8d77341` `[CODE]: opensbi add child attach and exec path cleanup`
  - `linux`: `411367a75e5d` `[CODE]: fork register global pid for child attach`
  - `linux`: `07678123b368` `[CODE]: nacc fail fast on fork child attach errors`
- 2026-03-25 log/code reading led to a stronger conclusion:
  - printed `SEGV_ACCERR` is misleading and must not be equated directly with a permissions-bit failure
  - many faults in secure `mm`s are normal `access_error=0` not-present faults
  - `handle_mm_fault()` often turns a zero PTE into a valid leaf PTE as expected
  - the project now looks less like "a single PTE write is wrong" and more like "local faults can be resolved, but full execution does not converge to visible user progress"
- 2026-03-27 planning tightened the deeper diagnosis further:
  - the current blocker is increasingly likely to be incomplete trusted runtime-context modeling under multi-process execution
  - `CSR_NACC_STATE` should no longer be treated as a full process-state register; it should be treated as a hart-local runtime mode register
  - the missing object is more likely an OpenSBI-owned `per-thread Secure Runtime Context`
  - the design must now distinguish:
    - per-hart loaded runtime state
    - per-thread continuation / return state
    - per-mm secure address-space state
    - Linux semantic state
  - accepted invariants are now:
    - `AGENT` is a transient hart execution mode
    - scheduling in a protected thread must restore a full trusted runtime context, not just a `cid` / mode bit
    - first landing of protected user traps must be enforced by hardware / monitor into agent, not chosen by Linux

## Current Blockers

- `fork+exec` still does not produce stable visible output; attach is improved, but the final blocker is not isolated yet.
- Multi-process runtime context is still not explicitly modeled. Current OpenSBI / QEMU logic still looks too close to "a few hart-local runtime fields", which does not match the desired control-flow model of "first to agent, delegate Linux, return to agent".
- Tier 0 to Tier 2 validation has not been completed, so the project cannot claim stable fork / `mmap` / shared-memory semantics.
- It is still unclear whether the earlier accounting risks are truly gone or merely not reproduced in the current smoke cases.
- Both `echo alpha | wc -c` and `cat /etc/hostname; echo done` now look more like execution-progress / repeated-fault / convergence issues than a simple attach or single-PTE-install bug.
- `bitmap` protection is still not implemented.

## Latest Evidence

- 2026-03-24 / 2026-03-25 repeated runs of:
  - `docker run --security-opt seccomp=unconfined --rm busybox sh -c "cat /etc/hostname; echo done"`
  showed:
  - child attach PID mismatch is fixed
  - `child pid ... is not registered before sm_nacc_attach_forked_child` is gone
  - but VM-side `hostname` / `done` output is still not stable
- `do_wp_page()` / `wp_page_copy()` have been strongly de-prioritized as the primary fault:
  - file-backed private pages enter the normal `do_wp_page -> copy` path
  - `wp_page_copy()` clears the old file-backed PTE and installs a new anon writable PTE
  - Linux and OpenSBI logs can be matched across `GET_AND_CLEAR_PTE` old values and new writeback values
- Earlier suspicion about `...d3` / `...93` bit drift is now treated as likely normal divergence between parent and child `mm`s during `fork/copy_page_range()`:
  - parent source PTE stays `...d3` after write-protect
  - child destination PTE becomes `...93` after `pte_mkold()`
  - this should no longer be treated as the primary anomaly
- 2026-03-25 log `logs/nacc_qemu_20260325_233943.log` finally provided `fault_pte` observations:
  - several secure-`mm` faults showed:
    - `pte=0` before the fault
    - `access_error=0`
    - a valid leaf PTE after `handle_mm_fault()`
  - this strongly supports the claim that many earlier "permission failures" were really ordinary missing-PTE faults
- `docs/workflow/PLAN_20260322_filemap_fault_wedge.md`
  - still captures the split-and-diagnose strategy for the `wc` wedge
- 2026-03-24 code updates:
  - `linux` `1f2f4c92d67f`
  - `opensbi` `8d77341`
  - the code now has `NACC_FORKED` child attach, `NACC_EXEC` exec-build state, and the `nacc_exec()/sm_nacc_exec()` chain wired up, but still lacks a stable end-to-end result
- `logs/fork_exec_default_freshwait_20260317_qemu_20260317_151037.log`
  - remains the strongest historical negative accounting evidence:
    - `Bad rss-counter state`
    - `non-zero pgtables_bytes on freeing mm: -32768`
  - if new tests stop reproducing it, the log should be downgraded to historical context rather than treated as the current primary state
- The current round still contains many diagnostic-only changes, mainly for narrowing the search space:
  - `filemap_map_pages` / `set_pte_range`
  - `do_wp_page` / `wp_page_copy`
  - `ptep_get_and_clear`
  - `ptep_set_access_flags` / `ptep_test_and_clear_young`
  - `fault_pte`
  - OpenSBI `sm_nacc_set_ptes` / `sm_nacc_wrprotect_ptes` / `sm_nacc_get_and_clear_pte`
  - these logs can be trimmed later, but the conclusions derived from them should be preserved
- `docs/workflow/PLAN_20260322_container_validation.md`
  - the validation order remains `coverage-first -> real-app -> targeted-stress`
- `docs/workflow/PLAN_20260327_secure_runtime_context.md`
  - now captures the runtime-context design framing explicitly
  - recommends an OpenSBI-owned `per-thread Secure Runtime Context`
  - recommends keeping `TWIN_ENTRY` as a trusted first landing while moving `nacc_sstatus` / `resume_pc` into thread-owned continuation state

## Immediate State Updates Still Needed

- the exact source checkpoints or commit IDs for the current experiments
- the first real bad point in the current uncommitted debug state after `linux 07678123b368` / `opensbi 8d77341`
- a runtime-state inventory covering:
  - `CSR_NACC_STATE`
  - `nacc_sstatus`
  - `trampoline/resume_pc`
  - `TWIN_ENTRY`
  - `user_pt_regs` anchor
  - agent trap-save anchor
- updated investigation focus on "is the process making real execution progress?" rather than "did a single PTE look suspicious?"
  - does the same address fault repeatedly?
  - does the user PC actually advance?
  - does the process reach `write(1, ...)` / `writev(1, ...)` at all?
- Tier 0 to Tier 2 execution results, especially for shared-memory / `mmap`
- split results for the `echo alpha | wc -c` wedge:
  - `echo alpha | cat`
  - `wc -c /etc/hostname`
  - `busybox wc -c /etc/hostname`
  - `cat /etc/hostname`
