# Next Steps

Prioritized actions. Update this file when an item is completed or falsified.

| Priority | Action | Owner | Status | Dependency |
| --- | --- | --- | --- | --- |
| P0 | Freeze the multi-process secure trap / continuation problem as a runtime-context design problem instead of continuing to treat `CSR_NACC_STATE` as a full process state machine | planner | completed | `PLAN_20260327_secure_runtime_context.md` |
| P0 | Inventory the distributed runtime state in QEMU / OpenSBI / agent: `nacc_state`, `nacc_sstatus`, `trampoline/resume_pc`, `TWIN_ENTRY`, `user_pt_regs`, and trap-save anchor; classify which fields must become per-thread owned state | planner / coder | pending | `PLAN_20260327_secure_runtime_context.md` |
| P0 | Design the minimum OpenSBI-side `nacc_thread_ctx`: trusted fields, save/load API, and Linux task -> secure thread context mapping | planner / coder | pending | `PLAN_20260327_secure_runtime_context.md` |
| P0 | Re-run the minimal smoke set on `linux 1f2f4c92d67f` / `opensbi 8d77341`: simple fork, fork+exec, same-pid exec, and pipeline; verify that `NACC_FORKED` attach and `NACC_EXEC` exec-build did not regress | human / test runner | pending | latest pushed subrepo commits |
| P0 | Fill in the exact command, checkpoint, and log summary for the 2026-03-22 simple fork smoke in `CURRENT_STATE.md` and `EXPERIMENT_LOG.md` | human | pending | latest manual experiment details |
| P0 | Keep the long-term fork direction fixed as Linux-friendly fork, with Linux-native paths plus OpenSBI secure-write assistance | planner | completed | `PLAN_20260318_linux_friendly_fork.md` |
| P0 | Keep the accounting-observability ticket available for page-table vs leaf-accounting separation | planner | completed | latest log analysis results |
| P0 | Keep the container validation plan active, with shared memory / `mmap` as a first-class tier | planner | completed | `PLAN_20260322_container_validation.md` |
| P1 | Re-evaluate `echo alpha | wc -c` on the latest fork/exec baseline: confirm whether the first bad point is still filemap/page fault, or whether it has shifted toward non-exec child / exec attach / runtime continuation | human / log analyzer / planner | pending | `PLAN_20260322_filemap_fault_wedge.md` |
| P1 | Under the current Linux scheduler model, design a context-switch handoff that saves the old secure thread context and loads the next one, restoring `CSR_NACC_STATE`, `nacc_sstatus`, `resume_pc`, and a trusted `TWIN_ENTRY` | coder | pending | `PLAN_20260327_secure_runtime_context.md` |
| P1 | Converge the trap / delegate / return chain into a fixed model: protected user trap first lands in agent; Linux delegation returns to agent first; agent then decides final resume | planner / coder | pending | `PLAN_20260327_secure_runtime_context.md` |
| P1 | If the split runs still point at `filemap_map_pages()`, let coder implement the diagnostic fallback that uses a more conservative file-backed fault path in NaCC mode | coder | pending | `PLAN_20260322_filemap_fault_wedge.md` |
| P1 | Once `fork+exec` and same-pid exec both reliably reuse the `NACC_EXEC -> nacc_exec()/sm_nacc_exec()` chain, continue with Tier 0 to Tier 2 validation, especially shared memory / `mmap` commands | human / test runner | pending | `PLAN_20260322_container_validation.md` |
| P2 | If Tier 0 to Tier 2 become stable, move on to Tier 3 small real applications; do not make full Ubuntu the immediate next goal | planner / human | pending | `PLAN_20260322_container_validation.md` |
| P2 | If shared memory / `mmap` or loop stress re-exposes the old accounting issues, reactivate the accounting observability ticket and inspect `pgtables_bytes`, `rss`, `rmap`, and `refcount` | planner / coder | pending | `TICKET_20260317_fork_accounting_observability.md` |
| P2 | After Stage 1/2, decide whether to keep historical ABI names such as `SBI_EXT_*REEXEC` / `AGENT_REEXEC_ENTRY_OFFSET` or simply document that their meaning has converged to generic exec attach | planner | pending | ABI stability requirements |
| P3 | Keep `bitmap` protection as a later hardening item, after fork / `mmap` / shared-memory semantics are stable | planner / coder | pending | `PLAN_20260318_linux_friendly_fork.md` |
| P3 | Promote stable smoke / shared-memory / `mmap` conclusions into `docs/agent/NACC_KNOWLEDGE_BASE.md` | planner | pending | stable conclusions |
