# Task Packet

- Task ID: TASK_20260514_103148_nacc_fix_refcount_metadata
- Created: 2026-05-14 10:31:48 +0800
- Priority: P1
- Lane: A
- Packet Type: execution
- Owner Role: human
- Status: done
- Goal: Build a minimal prototype for NaCC private user-data leaf page lifecycle management. The prototype should add trusted Agent-resident PFN-global refcount metadata, make OpenSBI use that metadata before clearing `PRIVATE_DATA` bitmap tags, and bring post-attach anonymous fault / COW new leaf pages into the same detached private-data lifecycle instead of leaving them as ordinary Linux anon pages.
- Critical Intent: RSS/rmap/refcount accounting in Linux must remain correct, but Linux must not be the security authority for `PRIVATE_DATA -> NORMAL`. Linux may allocate pages, lay out PTEs, and report lifecycle events; OpenSBI / trusted metadata decides when a private PFN is still live and when the bitmap tag may be cleared.
- Preferred Shape:
  - Follow the existing exec/attach shape: Linux first builds the mapping, then NaCC detaches user leaves and OpenSBI synchronizes private-data tags.
  - Store minimal lifecycle metadata in a fixed protected Agent-region carve-out, indexed by PFN over the current Linux physical address space.
  - Keep the first prototype PFN-global only; do not add cid/pid/root ownership records unless required to make the minimal refcount work.
  - Prefer simple OpenSBI helpers for acquire/release of private-data PFNs. Tag clearing should happen only when trusted refcount reaches zero.
- Disallowed Shape:
  - Do not keep direct PFN-wide tag clearing based only on a single Linux COW/zap event.
  - Do not rely on Linux folio refcount, rmap, mapcount, pid, or RSS counters as the authority for declassifying private data.
  - Do not broaden this into a full owner model, batch teardown ABI, large refactor, or cid/pid lifecycle database in the first prototype.
  - Do not regress the RSS-counter repair: detached special leaves still need enough Linux accounting to avoid `BUG: Bad rss-counter state`.
- Allowed Freedom:
  - Choose the exact Agent metadata carve-out address/size inside the protected Agent region, as long as Agent allocation cannot reuse it.
  - Choose ecall/function names and helper placement that fit the current Linux/OpenSBI style.
  - It is acceptable to keep diagnostics noisy enough for bring-up.
  - Constrain the minimal prototype to ordinary 4 KiB user-data leaves and defer optimized batching or large-folio policy.
- Scope:
  - Linux protected user-data leaf paths after NaCC attach: anonymous page fault, COW replacement, fork-copy sharing, and zap/munmap/exit release paths reachable through existing zap handling.
  - OpenSBI private-data bitmap lifecycle: tag/acquire on private leaf installation or sync, release on old mapping removal, clear tag only on last trusted reference.
  - Agent protected memory layout: reserve a fixed metadata/refcount arena and keep it out of the Agent runtime allocator.
  - SBI ABI/header updates needed for the minimal lifecycle events.
- Constraints:
  - Human explicitly approved coder handoff on 2026-05-14 after resolving the prototype choices.
  - Stay inside the packet intent and human-named evidence unless a later owner needs exact code evidence for implementation.
  - Preserve Linux RSS/rmap behavior needed for current accounting while reducing ordinary Linux VM ownership of NaCC private user leaves where practical.
  - OpenSBI must remain the authority for bitmap tag transitions.
  - The Agent metadata region must be inaccessible to Linux and ordinary user code.
- Open Semantic Questions: resolved for prototype; install new fault/COW private leaves as `pte_special` directly, and force/order-0 4 KiB private-data leaves in NaCC protected ranges.
- Human Concern: The RSS-counter failure class is basically repaired, but tag lifecycle is still unsafe. A tagged confidential PFN must not be retired simply because one Linux mapping was replaced; fork/COW can leave another live confidential mapping to the same PFN. New page fault and COW pages must also stop remaining ordinary Linux anon pages after becoming NaCC process user data.
- Key Assumptions:
  - The current exec/attach detach flow is the correct precedent for Linux layout followed by NaCC ownership.
  - PFN-global metadata is sufficient for the minimal prototype and is easier for OpenSBI to consult than cid/pid/root-scoped records.
  - A protected Agent-region carve-out is acceptable TCB storage if it is excluded from Agent allocation and accessed by OpenSBI via physical address.
  - Linux accounting may remain as compatibility/accounting state, but trusted refcount controls private-data tag retirement.
  - Fork-copy is the authoritative acquire event for inherited child mappings; child attach validates secure non-leaf PTPs but does not re-walk inherited leaves for another acquire, because that would double-count the same child mappings.
- Evidence / Inference Boundary:
  - Human-named evidence: `record/20260514.md`.
  - Code evidence read for planning: `linux/arch/riscv/mm/nacc.c`, `linux/mm/memory.c`, `linux/arch/riscv/include/asm/pgtable.h`, `linux/include/asm-generic/pgalloc.h`, `opensbi/lib/sbi/sm/{sm.c,bitmap.c,vm.c,kalloc.c}`, `opensbi/include/sbi/sbi_domain.h`, and `agent/src/mem.c`.
  - Inference from code: initial exec/attach detaches existing user leaves and syncs tags, while post-attach anon fault/COW pages still enter through ordinary Linux anon folio paths and current retire clears PFN bitmap tags directly.
  - Runtime evidence observed by log_analyzer: the 2026-05-14 12:21-12:55 T1 build/package plus workload 1..8 batch completed with exit code 0, fresh OpenSBI/Linux/Agent/final image timestamps, all eight VM auto commands exited 0, and QEMU logs contained no `BUG: Bad rss-counter state`, `BUG:`, `Oops`, refcount-arena panic, refcount overflow, private-PFN release failure, or SIGBUS marker.
  - Runtime evidence observed by log_analyzer: every QEMU boot reported 16 PMP entries and `The Agent is loaded into PMP protection region, and the original part is cleared.` No log line directly prints the private refcount arena base/size/PMP entry or individual PFN acquire/release ref values.
  - Runtime evidence observed by log_analyzer: private-data trap/census summaries appeared in all eight QEMU logs, with nonzero `PRIVATE_DATA context` updates/clears/hits and `context_overflow=0`; fork-sensitive runs logged child table validation (`Child user page tables validated; inherited private refs came from fork-copy.`).
  - Inference from runtime evidence: the fresh image is acceptable for this T1 smoke/runtime tier and the dominant event pattern is expected noisy private-data trap/stat diagnostics plus root tag/retire churn. Actual per-PFN trusted-refcount balance is not directly proven by the current logs because acquire/release values are not emitted.
  - Planner route decision: accept the completed T1 build/runtime smoke as sufficient evidence for this prototype tier, with the direct per-PFN balance proof recorded as an observability caveat rather than a current coder repair trigger.
- Reconciliation Required: no
- Post-Run Analysis Required: no
- Human Checkpoint Required: hard
- Continuation Mode: manual
- Preflight Resolved: yes
- Commit Policy: manual
- Definition Of Done:
  - Agent-region PFN refcount metadata exists in a fixed protected carve-out and the Agent allocator cannot hand those pages out.
  - OpenSBI has minimal private-data acquire/release semantics backed by that metadata; `PRIVATE_DATA` is cleared only when trusted PFN refcount reaches zero.
  - Existing attach/tag sync and post-attach private leaf installation paths acquire metadata for private user-data PFNs.
  - Fork-copy sharing, COW old-page replacement, and zap/teardown removal paths update trusted metadata without relying on Linux refcount as authority.
  - Anonymous fault and COW new pages for active NaCC protected user-data ranges do not remain untagged ordinary Linux private pages after installation.
  - New anonymous fault and COW replacement leaves in NaCC protected private-data ranges are installed directly as `pte_special` detached 4 KiB leaves.
  - RSS/rmap accounting remains sufficient to avoid reopening the repaired RSS-counter failure class.
  - Coder records exact files changed, route chosen, residual risks, and a bounded compile/check result or explicitly defers heavy validation to `test_runner`.
- Related State:
  - task-local artifacts only; do not list `CURRENT_STATE.md`, `HYPOTHESES.md`, or `NEXT_STEPS.md` here unless the human explicitly says they are current authority for this packet
- Related Ticket / Plan: follows `TASK_20260513_180601_nacc_rss_fix` as a separate tag-lifecycle/security boundary; do not reopen that RSS packet solely for residual tag diagnostics.
- Branch / Worktree: current worktree `/home/link/NaCC`
- Validation Tier: T1

## Reference Values

- Priority: `P0` / `P1` / `P2` / `P3`
- Lane: `A` / `B` / `C`
- Packet Type: `execution` / `planning` / `analysis`
- Owner Role: `human` / `planner` / `coder` / `reviewer` / `test_runner` / `log_analyzer`
- Status: `draft` / `in_progress` / `needs_review` / `changes_requested` / `needs_test` / `needs_analysis` / `test_failed` / `blocked` / `done`
- Validation Tier: `T0` / `T1` / `T2` / `T3`
- Reconciliation Required: `yes` / `no`
- Post-Run Analysis Required: `yes` / `no`
- Human Checkpoint Required: `no` / `soft` / `hard`
- Continuation Mode: `manual` / `marathon`
- Preflight Resolved: `yes` / `no`
- Commit Policy: `manual` / `commit_each_completed_unit`

## Required Artifacts

- Patch or commit: manual patch or commit with changed Linux/OpenSBI/Agent paths listed
- Minimal compile result: bounded coder sanity only; if the only useful proof is a heavy Linux / OpenSBI / QEMU / image rebuild, write `deferred to test_runner`
- Test command or batch plan: build/package the touched components with `make linux-update`, `make opensbi`, and `make agent-update` as needed for a fresh runtime image, then run exactly one bounded workload 1..8 validation batch using the repo debug-batch workflow. Use `config/debug-batch.private_baseline_t1.txt` if it is still the current workload 1..8 command file; otherwise stop and record the exact missing workload file rather than inventing commands. The run must cover RSS-regression-sensitive fork/COW/zap behavior and capture private-data tag/refcount diagnostics from the workload 1..8 QEMU/VM logs.
- Primary log path: `logs/test_runner_batch_TASK_20260514_103148_20260514_122601.log`
- Log path if validation fails: n/a for this completed test_runner turn; batch command exited 0. See `logs/test_runner_batch_TASK_20260514_103148_20260514_122601.log`.

## Latest Summary

- Intent is now clarified. Build a minimal Agent-resident PFN refcount prototype so OpenSBI owns private-data tag retirement, while Linux continues required accounting and brings post-attach anon fault/COW user leaves into the NaCC private lifecycle.
- Human approved coder handoff. Prototype choices are fixed: direct `pte_special` install for new fault/COW private leaves, 4 KiB/order-0 only, and workload 1..8 only for task validation.
- Reviewer approved the bounded OpenSBI build-failure repair on 2026-05-14 11:59:59 +0800. The `sm_nacc_attach_child_common()` cast now wraps the full `SATP_PA(satp)` macro expansion before converting to `pgtbl_t`, matching the established pattern and preserving the already-reviewed child-attach no-resync model.
- Log_analyzer reduced the fresh 2026-05-14 12:21-12:55 T1 evidence: OpenSBI/Linux/Agent/final image rebuilds succeeded, workload 1..8 ran once with all eight entries `status=ok`, all VM auto commands exited 0, private-data lifecycle activity and fork-child validation appeared, and failure searches found no RSS/refcount/panic/Oops markers.
- Planner accepts that result as adequate T1 smoke evidence for the minimal PFN-global refcount prototype. The evidence is not a direct per-PFN acquire/release balance proof; explicit bounded refcount logging should be a separate diagnostics follow-up only if the human wants stronger observability.
- Human reviewed the implementation flow interactively and accepted the current task state as close enough for this packet. The remaining SUM-off private-data trap surface is explicitly split out as future security-boundary convergence work, not a blocker for this refcount lifecycle packet.
- SUM on/off trap census from the T1 workload 1..8 run is recorded in `record/20260514_nacc_refcount_t1_sum_trap_readout.md`: workloads 1 and 2 had `sum_off=0`, while workloads 3 through 8 still had SUM-off private-data load traps concentrated in `__pi___memcpy`.
- This packet is closed as done for the minimal PFN-global refcount prototype, with residual risks documented as follow-up boundaries.

## Next Handoff

- Next owner: none; archive packet.
- Trigger: human accepted the current implementation and T1 evidence as sufficient for this task and requested commit/push plus task/pane archival.
- Exact artifact to read first: n/a.
- Exact task for next owner: n/a.
- Expected deliverable: archived packet and active human report, with related agent panes retired by `scripts/archive_task_packet.sh`.
- Stop condition: packet moved to `docs/workflow/tasks/completed/` and active report moved to `docs/workflow/tasks/reports/completed/` if present.
- If blocked: record the exact archive/commit/push failure and leave the packet active.
- Do not do in this turn: do not expand validation beyond the completed workload 1..8 T1 run; do not implement the future SUM-off convergence work in this packet.

## Coder Result

- Implementation summary: Added a fixed 4 MiB Agent-tail PFN refcount arena, excluded it from the Agent allocator, protected it with an M-only PMP entry, and made OpenSBI acquire/release private-data PFN refs under the bitmap lock. Initial sync now acquires refs instead of directly setting tags; release clears `PRIVATE_DATA` only when the trusted count reaches zero. Linux now acquires refs for fork-copy child mappings and new protected anon/COW leaves, installs new protected anon/COW leaves as `pte_special` order-0 PTEs, and releases old special PFNs after COW/zap clears the mapping. Repair update: `linux/mm/mmap.c` now marks active protected private anonymous `mmap()` and `brk` ranges with `VM_MIXEDMAP` before VMA merge/new-VMA creation, so post-attach anonymous VMAs can enter the existing special-leaf lifecycle. Build-failure repair update: `opensbi/lib/sbi/sm/sm.c` now casts `(SATP_PA(satp))` in `sm_nacc_attach_child_common()`, preventing the `pgtbl_t` cast from binding before the macro shift.
- Commit or patch: manual patch in `linux/mm/memory.c`, `linux/mm/mmap.c`, `linux/arch/riscv/kernel/sys_riscv.c`, `linux/arch/riscv/include/asm/{nacc.h,sbi.h}`, `opensbi/lib/sbi/sm/{bitmap.c,sm.c,vm.c}`, `opensbi/lib/sbi/sbi_ecall_nacc.c`, `opensbi/lib/sbi/sbi_domain.c`, `opensbi/include/{sm/bitmap.h,sm/sm.h,sbi/sbi_domain.h}`, and `agent/include/params.h`.
- Route chosen and why: PFN-global `u32` counters are stored in a protected Agent-region carve-out and accessed directly by OpenSBI, matching the packet's minimal trusted-metadata model without adding cid/pid/root ownership. The existing retire SBI ID is treated as release; one new acquire SBI ID was added. Child attach avoids a second sync acquire because fork-copy already accounts inherited mappings before the child can run. The VM flag repair keeps the fault/COW gate in `linux/mm/memory.c` unchanged and instead ensures eligible new anonymous VMA creation paths receive the same `VM_MIXEDMAP` prerequisite that attach already gives walked VMAs.
- Escalations made: none to human; one nontrivial implementation assumption was recorded in `Key Assumptions`.
- Remaining risks: no full Linux/OpenSBI/Agent rebuild or QEMU workload was run by coder; heavy proof is deferred. Bounded sanity for the build-failure repair passed with `git diff --check -- opensbi/lib/sbi/sm/sm.c` and a targeted `sm.c` compile using the OpenSBI compile command captured from the failed build. Reviewer should re-check the repaired `VM_MIXEDMAP` marking for active anonymous `mmap()`/`brk` ranges, child attach no-resync semantics, release-underflow handling (`ret=2` means no trusted ref was present and does not clear the tag), the VM_MIXEDMAP dependency for installing/recognizing direct special leaves, and the single OpenSBI cast/macro-precedence fix.

## Review Result

- Approval status: approve
- Spec fidelity: acceptable. This turn reviewed the bounded OpenSBI build-failure repair only. In `sm_nacc_attach_child_common()`, the repaired call now uses `(pgtbl_t)(SATP_PA(satp))`, so the cast applies after the `SATP_PA` macro expands to `SATP_PPN(satp) << 12`. That matches the established pattern elsewhere in `sm.c`, fixes the pointer-shift compile failure from the prior `make opensbi` log, and does not change the already-reviewed child-attach no-resync lifecycle semantics.
- Risk review: acceptable for test_runner handoff, with full build/runtime proof still required. The fix is syntactic precedence repair, not a semantic route change. It preserves the packet's minimal PFN-global trusted metadata model, keeps Linux as lifecycle reporter/layout/accounting participant, keeps OpenSBI as private-data tag-retirement authority, and does not add owner records, batch teardown ABI, large-folio policy, or new workload scope.
- Risk findings:
  - Reviewer did not rerun full `make opensbi`; the next test_runner turn must prove the repaired build in the normal build/package path.
  - Test_runner must still confirm the Agent-tail refcount carve-out is excluded from the Agent allocator and protected by the M-only PMP entry in the built runtime image.
  - Test_runner must still confirm boot does not hit the refcount-arena size panic and that workload 1..8 logs show private-data acquire/release/refcount/tag behavior rather than direct single-event tag clearing.
  - Test_runner must preserve RSS-regression-sensitive fork/COW/zap evidence; reviewer did not rerun the RSS workload proof.
- Can proceed to test: yes
- Key files reviewed: `docs/workflow/tasks/active/TASK_20260514_103148_nacc_fix_refcount_metadata.md`; `docs/workflow/tasks/reports/active/TASK_20260514_103148_nacc_fix_refcount_metadata_human_report.md`; `opensbi/lib/sbi/sm/sm.c`; `opensbi/include/sm/vm.h`; `logs/test_runner_build_opensbi_TASK_20260514_103148_20260514_115213.log`.
- Human-facing code explanation: `SATP_PA(satp)` is a macro that extracts the SATP PPN and shifts it left to recover the page-table physical address. The repaired code casts the completed macro result to `pgtbl_t`, instead of casting the PPN operand before the shift. This removes the OpenSBI compile error without changing the lifecycle logic.
- Why this route still fits the packet: the repair is the smallest route that restores the intended build while preserving the previously reviewed control model. Child attach still validates secure non-leaf PTPs and relies on fork-copy as the private-leaf acquire event, so it does not silently reintroduce double-counting or Linux-authoritative tag retirement.
- Requirements checked directly from code: the failing build log points to `sm.c:490` with a cast binding before `SATP_PA`'s shift; current `sm.c` now uses `(pgtbl_t)(SATP_PA(satp))` at that site; the same parenthesized cast pattern is already used elsewhere in `sm.c`; `git -C opensbi diff --check -- lib/sbi/sm/sm.c` passed.
- Human-facing summary: approve for `test_runner`. This bounded OpenSBI build fix is faithful and non-invasive, but it is not runtime validation and does not replace the packet's T1 build/QEMU/workload proof.
- Next handoff: test_runner should rebuild/package Linux, OpenSBI, and Agent as needed for a fresh runtime image, then run exactly one bounded workload 1..8 validation batch. Preserve build logs, launcher logs, QEMU/VM logs, owner/freshness evidence, private-data refcount/tag diagnostics, and RSS/fork/COW/zap-sensitive evidence. Route completed runtime artifacts to log_analyzer for evidence reduction.

## Test Result

- Command run:
  - `make opensbi`
  - `make linux-update`
  - `make agent-update`
  - `config/debug-batch.sh --cmd-file config/debug-batch.private_baseline_t1.txt --tag-prefix TASK_20260514_103148_nacc_refcount_t1 --ssh-auto-timeout 600 --wait-after-auto 400`
- Build actions:
  - `make opensbi` completed successfully; log: `logs/test_runner_build_opensbi_TASK_20260514_103148_20260514_122101.log`.
  - `make linux-update` completed successfully and rebuilt `final_image.bin`; log: `logs/test_runner_build_linux_update_TASK_20260514_103148_20260514_122117.log`.
  - `make agent-update` completed successfully and rebuilt `final_image.bin`; log: `logs/test_runner_build_agent_update_TASK_20260514_103148_20260514_122533.log`.
  - Fresh artifact evidence after builds:
    - `opensbi/build/platform/generic/firmware/fw_jump.elf` timestamp `2026-05-14 12:21:11 +0800`, size `2061472`.
    - `opensbi/build/platform/generic/firmware/fw_jump.bin` timestamp `2026-05-14 12:21:11 +0800`, size `273272`.
    - `riscv-linux/arch/riscv/boot/Image` timestamp `2026-05-14 12:24:21 +0800`, size `24226816`.
    - `agent/agent.elf` timestamp `2026-05-14 12:25:41 +0800`, size `67432`.
    - `agent/agent.bin` timestamp `2026-05-14 12:25:41 +0800`, size `24656`.
    - `final_image.bin` timestamp `2026-05-14 12:25:42 +0800`, size `26214400`.
- Runtime batch actions:
  - Batch wrapper log: `logs/test_runner_batch_TASK_20260514_103148_20260514_122601.log`.
  - Batch session: `nacc-batch-20260514_122601`.
  - Workload file used: `config/debug-batch.private_baseline_t1.txt`.
  - SSH ready timeout: `VM_SSH_READY_TIMEOUT_SECONDS=180`.
  - SSH auto timeout: `VM_SSH_AUTO_TIMEOUT_SECONDS=600` via `--ssh-auto-timeout 600`.
  - Batch wait-after-auto: `--wait-after-auto 400`.
  - `[NaCC] Auto-running:` appeared for every run according to wrapper progress.
  - No `code=255` retry loop, SSH readiness failure, or `[NaCC][ssh-auto-timeout]` was reported by the wrapper.
- Outcome: completed. T1 build/package and exactly one bounded workload 1..8 batch ran; all eight batch entries ended with `status=ok`. Test output is preserved evidence and is not a workflow closeout decision.
- Artifact / log path:
  - Primary runtime wrapper log: `logs/test_runner_batch_TASK_20260514_103148_20260514_122601.log`.
  - Build logs:
    - `logs/test_runner_build_opensbi_TASK_20260514_103148_20260514_122101.log`
    - `logs/test_runner_build_linux_update_TASK_20260514_103148_20260514_122117.log`
    - `logs/test_runner_build_agent_update_TASK_20260514_103148_20260514_122533.log`
  - Workload 1 logs: `logs/TASK_20260514_103148_nacc_refcount_t1_01_20260514_122601_qemu_20260514_122936.log`, `logs/TASK_20260514_103148_nacc_refcount_t1_01_20260514_122601_vm_20260514_122936.log`.
  - Workload 2 logs: `logs/TASK_20260514_103148_nacc_refcount_t1_02_20260514_122937_qemu_20260514_123313.log`, `logs/TASK_20260514_103148_nacc_refcount_t1_02_20260514_122937_vm_20260514_123313.log`.
  - Workload 3 logs: `logs/TASK_20260514_103148_nacc_refcount_t1_03_20260514_123313_qemu_20260514_123657.log`, `logs/TASK_20260514_103148_nacc_refcount_t1_03_20260514_123313_vm_20260514_123657.log`.
  - Workload 4 logs: `logs/TASK_20260514_103148_nacc_refcount_t1_04_20260514_123658_qemu_20260514_124043.log`, `logs/TASK_20260514_103148_nacc_refcount_t1_04_20260514_123658_vm_20260514_124043.log`.
  - Workload 5 logs: `logs/TASK_20260514_103148_nacc_refcount_t1_05_20260514_124044_qemu_20260514_124433.log`, `logs/TASK_20260514_103148_nacc_refcount_t1_05_20260514_124044_vm_20260514_124433.log`.
  - Workload 6 logs: `logs/TASK_20260514_103148_nacc_refcount_t1_06_20260514_124434_qemu_20260514_124816.log`, `logs/TASK_20260514_103148_nacc_refcount_t1_06_20260514_124434_vm_20260514_124816.log`.
  - Workload 7 logs: `logs/TASK_20260514_103148_nacc_refcount_t1_07_20260514_124817_qemu_20260514_125157.log`, `logs/TASK_20260514_103148_nacc_refcount_t1_07_20260514_124817_vm_20260514_125157.log`.
  - Workload 8 logs: `logs/TASK_20260514_103148_nacc_refcount_t1_08_20260514_125157_qemu_20260514_125535.log`, `logs/TASK_20260514_103148_nacc_refcount_t1_08_20260514_125157_vm_20260514_125535.log`.

## Analysis Result

- Observed symptom: No failure symptom in the completed T1 run. Dominant pattern is noisy but coherent NaCC private-data trap/stat output, root tag/retire churn, fork-child validation, and normal VM command completion.
- Verdict: acceptable for the requested T1 build/runtime smoke, with an observability caveat. The run is not failed. It is mildly incomplete as direct refcount proof because the logs do not emit individual PFN acquire/release counts.
- Key evidence:
  - Build/package succeeded: `make opensbi` ended `EXIT_CODE=0` at 2026-05-14 12:21:12; `make linux-update` ended `EXIT_CODE=0` at 12:25:28; `make agent-update` ended `EXIT_CODE=0` at 12:25:42.
  - Fresh artifacts after builds: `fw_jump.elf` and `fw_jump.bin` timestamp 12:21:11, Linux `Image` 12:24:21, `agent.elf`/`agent.bin` 12:25:41, and `final_image.bin` 12:25:42.
  - Batch wrapper `logs/test_runner_batch_TASK_20260514_103148_20260514_122601.log` ran workload 1..8 once, ended `EXIT_CODE=0`, and recorded all eight entries as `status=ok`.
  - VM logs show SSH readiness and `[NaCC][ssh-auto-exit] code=0` for all eight runs. Workload-visible completion markers appeared for the named shell workloads: `kernel_read_done`, `kernel_write_done`, `fork_private_done`, `done`, `alpha`, or `6` where expected by the wrapper command.
  - QEMU logs show boot-level protection evidence in every run: `Boot HART PMP Count : 16` and `The Agent is loaded into PMP protection region, and the original part is cleared.`
  - QEMU logs show private-data runtime activity in every run. Last-summary examples: run 1 `updates=62 clears=61 hits=760`, run 3 `updates=62 clears=60 hits=1072`, run 5 `updates=130 clears=126 hits=2722`, run 7 `updates=133 clears=129 hits=2217`, all with `context_overflow=0`.
  - Fork/COW-sensitive coverage is present indirectly: run 3 completed `fork_private_done`; runs 3/4/6/8 each logged one child validation, runs 5/7 logged two child validations, and child validation text explicitly says inherited private refs came from fork-copy.
  - Failure searches found zero matches for refcount-arena panic, refcount overflow, private PFN release failure, SIGBUS, `BUG: Bad rss-counter state`, `BUG:`, or `Oops` across the eight QEMU logs.
  - Caveat: current diagnostics do not print per-PFN trusted refcount acquire/release values. Therefore the log proves no visible underflow/overflow/failure and shows private-data lifecycle activity, but it does not directly prove exact PFN refcount balance.
- Likely cause: The batch is a successful noisy bring-up run. The private-data stats reflect expected monitor instrumentation during container exec/fork/syscall/teardown paths. The missing direct refcount evidence is an observability gap in diagnostics, not an observed runtime failure.
- Confidence: High for build/package freshness and workload completion; high that the RSS-counter failure class did not reappear in this T1 batch; medium that the trusted PFN refcount lifecycle is behaving exactly as intended, because evidence is indirect.
- Human-facing summary: The fresh image built and ran workload 1..8 without runtime failure. The logs show private-data activity, root tag/retire activity, fork-child validation, and no RSS/refcount/panic/Oops failure signatures. The remaining uncertainty is diagnostic: the run does not print exact per-PFN acquire/release refcount values, so this is acceptable T1 evidence but not a precise refcount-balance proof.
- Recommended next owner: planner
- Recommended next step: Planner should decide closeout/reviewer route. If stronger proof is required, open a narrow follow-up to add explicit bounded PFN acquire/release/refcount diagnostics; there is no concrete first-bad runtime point requiring direct coder repair from this batch.

## Open Questions

- Resolved by human: choose direct `pte_special` install for new fault/COW private leaves.
- Resolved by human: choose 4 KiB/order-0 only for the minimal prototype; defer large folio/mTHP handling.
