# Task Packet

- Task ID: TASK_20260419_115218_private_baseline
- Created: 2026-04-19 11:52:18 +0800
- Priority: P0
- Lane: A
- Packet Type: execution
- Owner Role: human
- Status: done
- Goal: Build a strict default-private startup baseline. At pre-user-entry activation, all ordinary present user leaf pages under the NACC protected subtree should be marked `PRIVATE_DATA` with no bitmap-off exceptions for user-data leaves. Linux VMA information may still be synced and logged as an attribution hint, but it must not decide whether a page is protected. Every ordinary present user leaf should still have attribution/provenance categorization so the run-end output can point directly to where the hot trapped text/data came from. The phase target is to measure the fail-closed trap upper bound and identify the true hot paths with differentiated end-of-run trap categories.
- Critical Intent: This phase intentionally overrides the older VMA-guided selective-private baseline as the enforcement authority. For ordinary present user leaves, the rule is fail-closed default-private, not VMA-class-selected private. Linux VMA / region semantics may explain and attribute traps, but may not silently deprotect ordinary candidate leaves.
- Preferred Shape: Reuse the existing `ROOT_L0` lifecycle, `sm_prepare_user_pt()` reconcile point, `sm_nacc_set_ptes()` install point, and existing `PRIVATE_DATA` trap mediation path. Keep Linux-side sync as attribution-only and keep the final evidence on the existing `sm_pgtbl_debug()` dump path.
- Disallowed Shape: Do not use VMA / region class as the protection authority. Do not widen this into a richer metadata system, a monitor-owned pathname database, or a new policy ABI. Do not optimize hot paths in this phase; the goal is upper-bound measurement plus source attribution.
- Allowed Freedom: Coder may keep the existing Linux region-sync path with reduced semantics, may add one narrow Linux-to-monitor attribution hint if needed, and may choose any bounded category-counter representation as long as ordinary user leaves stay fail-closed private.
- Scope: Planner route, coder implementation, review, test, and analysis for the strict default-private startup baseline plus its final attribution output. Main touchpoints were Linux region sync and provenance logging, OpenSBI leaf-tag selection, and final trap reporting.
- Constraints: Every ordinary present user leaf under the protected subtree must be tagged `PRIVATE_DATA` at reconcile and install. There are no bitmap-off exceptions for user-data leaves in this phase. Secure non-leaf PTP pages and agent-resident private region mappings may remain outside bitmap scope because they are not ordinary user data leaves.
- Open Semantic Questions: None blocking for this packet.
- Human Concern: The older selective-private baseline could understate the real trap burden and hide the true hot paths by leaving many ordinary pages non-private based on Linux VMA semantics. The human wanted the fail-closed upper bound first, with enough category and provenance information to see where the dominant trap cost actually comes from.
- Reconciliation Required: no
- Post-Run Analysis Required: no
- Definition Of Done: Every ordinary present user leaf under the protected subtree is tagged `PRIVATE_DATA` during pre-user-entry reconcile and follow-on leaf install, independent of Linux VMA class or synced region class. A focused validation batch runs far enough to expose the dominant trap categories and concrete hot-source provenance so later work can choose optimization or sharing targets from real evidence.
- Related State:
  - `docs/workflow/CURRENT_STATE.md`
  - `docs/workflow/HYPOTHESES.md`
  - `docs/workflow/NEXT_STEPS.md`
- Related Ticket / Plan:
  - `docs/workflow/tasks/completed/TASK_20260414_113719_private_bitmap.md`
  - `docs/workflow/tasks/completed/TASK_20260415_154406_vma_guided_bitmap.md`
- Branch / Worktree:
- Validation Tier: T1

## Required Artifacts

- Patch or commit: fail-closed enforcement plus attribution/reporting changes in `opensbi/include/sm/region.h`, `opensbi/lib/sbi/sm/region.c`, `opensbi/lib/sbi/sbi_trap_ldst.c`, `linux/arch/riscv/mm/nacc.c`, and `config/debug-batch.private_baseline_t1.txt`
- Minimal compile result: `make opensbi` and `make linux-update`
- Test command or batch plan: `config/debug-batch.private_baseline_t1.txt`
- Primary log path: `logs/private_baseline_t1_01_20260419_181934_qemu_20260419_182419.log`
- Log path if validation fails: earlier suspicious family `logs/private_baseline_t1_*_20260419_155129*`

## Latest Summary

- Phase 1 landed in the intended shape: ordinary present user leaves now fail closed to `PRIVATE_DATA`, while Linux VMA / region information remains attribution-only.
- The initial packet-owned run family (`155129`) was successful but not yet decision-grade because the final hot-bucket reporting still collapsed too much provenance into kernel-helper PCs.
- A narrow follow-up changed only the reporting surface in `opensbi/lib/sbi/sbi_trap_ldst.c`: the final dump now adds bounded `provenance[]` rows keyed by `root_pfn + range + class + flags`, and hot `mepc[]` samples can refresh when a later hit has better user-side attribution.
- The authoritative rerun family is `181934`: all eight probes completed successfully, the dominant path class remained `syscall_buffer_path` with `teardown_mapping_update` second, and file/COW/shared hot sources became joinable through `provenance[]` plus Linux `region provenance` lines.
- Intermediate duplicate `log_analyzer` appends from the organizer duplicate-dispatch incident were intentionally collapsed into the final summary below.

## Next Handoff

- Next owner: human
- Trigger: the `181934` rerun family produced decision-grade Phase-1 evidence and no longer needs another coder / analyzer round.
- Exact artifact to read first: `logs/private_baseline_t1_01_20260419_181934_qemu_20260419_182419.log`
- Exact task for next owner: accept or archive this Phase-1 baseline packet, or open a fresh planner packet for follow-on optimization work.
- Expected deliverable: human closeout, packet archive, or a new follow-on planning packet.
- Stop condition: this packet should not receive more coder / reviewer / log-analyzer turns unless a new concrete defect is discovered in the accepted `181934` evidence family.
- If blocked: if the accepted evidence is disputed, open a fresh analysis or planning packet that references the `181934` artifacts instead of appending more history here.
- Do not do in this turn: do not send this packet back to `coder` merely to restate the same helper-heavy but acceptable Phase-1 result.

## Coder Result

- Implementation summary:
  - `opensbi/lib/sbi/sm/region.c` was rewritten so ordinary candidate leaves now fail closed to `PRIVATE_DATA` for lookup misses, `PRIVATE_FILE_COW`, `SHARED_EXPLICIT`, ambiguous `SPECIAL_EXCLUDED`, and missing region state under a tagged `ROOT_L0`.
  - A read-only attribution helper was added in `opensbi/include/sm/region.h` and `opensbi/lib/sbi/sm/region.c` so trap reporting can use region metadata without turning Linux sync back into policy.
  - `opensbi/lib/sbi/sbi_trap_ldst.c` was extended twice: first to add bounded path-category counters and richer hot-`mepc` samples, then to add bounded `provenance[]` rows and hot-sample refresh so helper-dominated runs still preserve joinable user-side sources.
  - `linux/arch/riscv/mm/nacc.c` kept Linux classification as hint-only and emits bounded file-backed provenance logs; `config/debug-batch.private_baseline_t1.txt` was added as the focused T1 batch for this phase.
- Commit or patch:
  - Uncommitted working-tree changes in:
    - `opensbi/include/sm/region.h`
    - `opensbi/lib/sbi/sm/region.c`
    - `opensbi/lib/sbi/sbi_trap_ldst.c`
    - `linux/arch/riscv/mm/nacc.c`
    - `config/debug-batch.private_baseline_t1.txt`
- Route chosen and why:
  - The route stayed packet-shaped: keep `nacc_pte_private_data_candidate()` as the ordinary-leaf gate, move enforcement only through the existing reconcile/install selector, and reuse the existing `sm_pgtbl_debug()` dump path instead of widening ABI or building a monitor-owned pathname database.
- Escalations made:
  - None.
- Remaining risks:
  - The accepted Phase-1 result is still helper-heavy at run end, so later optimization work should target syscall-buffer/helper cost or the joined file-backed/shared hot ranges in a new packet rather than treating this as a policy bug.
  - File identity remains a `root + range` join through Linux provenance lines, not an inline pathname in the final SBI block.

## Review Result

- Approval status: approve-with-conditions, later satisfied by the accepted `181934` rerun family
- Spec fidelity: pass
- Fidelity findings:
  - The packet's fail-closed control model stayed intact: enforcement authority remained in OpenSBI leaf-tag selection at reconcile/install, Linux sync stayed attribution-only, and the `ROOT_L0` lifecycle plus existing `PRIVATE_DATA` mediation path were preserved.
  - The later provenance follow-up also stayed inside packet scope: it strengthened only the final reporting surface and did not widen bitmap semantics, policy state, or Linux ABI.
- Risk review: pass for this packet after the `181934` rerun; remaining concerns are follow-on prioritization, not packet-blocking defects.
- Risk findings:
  - The top category table still primarily describes path class rather than source class, so anon/file/COW distinctions remain most useful through `provenance[]` plus Linux provenance joins.
  - Helper-heavy `mepc[]` rows remain expected in this phase; the evidence is accepted because the final provenance table recovers the underlying user/file/shared source identity well enough for decision-making.
- Can proceed to test: yes; satisfied by the accepted `181934` rerun family
- Key files reviewed:
  - `opensbi/include/sm/region.h`
  - `opensbi/lib/sbi/sm/region.c`
  - `opensbi/lib/sbi/sm/vm.c`
  - `opensbi/lib/sbi/sm/sm.c`
  - `opensbi/lib/sbi/sbi_trap_ldst.c`
  - `linux/arch/riscv/mm/nacc.c`
  - `config/debug-batch.private_baseline_t1.txt`
- Human-facing code explanation:
  - The patch keeps the same `ROOT_L0` lifecycle and ordinary-leaf gate, but flips ordinary user-leaf enforcement to fail closed and expands the final report so hot kernel helper PCs no longer erase the underlying user-side provenance.
- Why this route still fits the packet:
  - It changes only the policy selector and the existing end-of-run dump path. It does not widen policy scope into a richer metadata system, and it does not move enforcement authority back into Linux semantics.
- Requirements checked directly from code:
  - unconditional fail-closed enforcement for ordinary present user leaves under a tagged root
  - unchanged exclusion of secure non-leaf PTP pages from the ordinary user-leaf candidate set
  - bounded category counters plus bounded `provenance[]` output in the existing final dump path
  - Linux VMA / region class retained as hint-only attribution
  - dedicated `private_baseline` T1 batch file present
- Human-facing summary:
  - The landed tree faithfully measures the strict default-private baseline through the approved control points. After the provenance follow-up and the accepted rerun, the remaining questions are about what to optimize next, not whether the packet route was correct.

## Test Result

- Command run:
  - `make opensbi`
  - `make linux-update`
  - `config/debug-batch.sh --session-name <private-baseline-t1-*> --tag-prefix private_baseline_t1 --wait-after-auto 180 --cmd-file config/debug-batch.private_baseline_t1.txt`
- Build actions:
  - rebuilt OpenSBI with `make opensbi`
  - rebuilt Linux and regenerated `final_image.bin` with `make linux-update`
  - no packet-owned agent source rebuild was required
- Outcome:
  - Two packet-owned T1 families matter:
    - `155129`: successful 8/8 run family, but final attribution was still too opaque and therefore routed to a narrow reporting follow-up
    - `181934`: successful 8/8 rerun family, accepted as the authoritative Phase-1 baseline evidence after provenance joinability was rechecked
- Artifact / log path:
  - authoritative launcher log: `logs/private-baseline-t1-20260419_181934.launcher.log`
  - authoritative primary log path: `logs/private_baseline_t1_01_20260419_181934_qemu_20260419_182419.log`
  - additional representative logs:
    - `logs/private_baseline_t1_04_20260419_183426_qemu_20260419_183913.log`
    - `logs/private_baseline_t1_06_20260419_184357_qemu_20260419_184844.log`
    - `logs/private_baseline_t1_07_20260419_184844_qemu_20260419_185343.log`
    - `logs/private_baseline_t1_08_20260419_185343_qemu_20260419_185832.log`

## Analysis Result

- Observed symptom:
  - The accepted `181934` family is not failing. All eight runs completed successfully, runs 1 through 7 remain `syscall_buffer_path`-dominant with `teardown_mapping_update` second, and the shared-memory repro is teardown-heavy under `munmap`.
  - The earlier `155129` family was correctly marked suspicious because final attribution still collapsed too much into kernel-helper `mepc[]` rows. That suspicion led to the narrow reporting-only follow-up and is now historical, not current.
- Verdict: acceptable
- Key evidence:
  - launcher summary at `logs/private-baseline-t1-20260419_181934.launcher.log:85` through `:92` reports all eight runs `status=ok`
  - run 1 final block at `logs/private_baseline_t1_01_20260419_181934_qemu_20260419_182419.log:11607` through `:11618` shows the stable helper-heavy top-level shape plus joinable anon/COW `provenance[]`
  - run 4 final provenance at `logs/private_baseline_t1_04_20260419_183426_qemu_20260419_183913.log:25679` joins through Linux provenance lines to `/lib/ld-linux-riscv64-lp64d.so.1` and keeps `/bin/cat` visible nearby
  - run 6 final provenance at `logs/private_baseline_t1_06_20260419_184357_qemu_20260419_184844.log:9923` preserves a dedicated `file_fault` bucket that joins to `/lib/libc.so.6`
  - run 7 final provenance at `logs/private_baseline_t1_07_20260419_184844_qemu_20260419_185343.log:32454` joins to `/lib/ld-linux-riscv64-lp64d.so.1` and keeps `/bin/wc` visible nearby
  - run 8 final provenance at `logs/private_baseline_t1_08_20260419_185343_qemu_20260419_185832.log:6818` through `:6824` separates `/nacc_shm_repro` from `/dev/shm/nacc-mini-shm-1`
- Likely cause:
  - Fail-closed enforcement is behaving as intended, and the dominant burden now reads as a real S-mode helper-dominated upper bound rather than as a remaining attribution bug.
- Confidence:
  - high on execution success, dominant event pattern, and provenance joinability in the accepted `181934` artifacts
  - medium on what optimization target should be chosen next, because that is a human / planner prioritization decision
- Human-facing summary:
  - This packet achieved the Phase-1 goal. The strict default-private baseline runs successfully, the dominant helper-heavy trap burden is visible, and the final evidence is no longer opaque because hot file/COW/shared sources can now be recovered through `provenance[]` plus Linux provenance lines.
- Recommended next owner:
  - `human`
- Recommended next step:
  - treat `181934` as the accepted Phase-1 baseline evidence; if follow-on work is desired, open a fresh planner packet around syscall-buffer/helper cost or the joined file-backed/shared hot ranges instead of appending more turns here

## Open Questions

- No blocking semantic questions remain for this packet.
- Remaining uncertainty is follow-on prioritization only: whether the next packet should target syscall-buffer/helper cost first or focus on specific joined file-backed/shared hot ranges.
