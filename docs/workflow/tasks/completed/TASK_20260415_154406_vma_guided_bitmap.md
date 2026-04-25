# Task Packet

- Task ID: TASK_20260415_154406_vma_guided_bitmap
- Created: 2026-04-15 15:44:06 +0800
- Priority: P1
- Lane: A
- Packet Type: execution
- Owner Role: human
- Status: done
- Goal: Turn the current all-protected-leaf baseline into a VMA-guided selective-private baseline where region policy is decided at VMA/region level and enforced when leaf pages are actually installed or first touched.
- Critical Intent: Replace the current uniform user-leaf treatment with region class as the only policy source for user-data leaf handling. The first landing must make the monitor aware of coarse region policy, then use that policy when present leaves are reconciled or newly installed, collapsing that policy into the leaf bitmap as the frozen enforcement result for the installed leaf while leaving early `ROOT_L0` registration and late root retirement intact. Trap profiling in this stage exists only to attribute runtime paths for user data page traps, not to learn page policy dynamically. Access traps caused by Secure PTP handling are explicitly out of scope for this attribution effort. This stage is now closed on the clean rerun evidence: any follow-on work must treat the conservative selective-private baseline as fixed rather than reopen region-policy semantics or widen private coverage first.
- Preferred Shape: Introduce explicit region classes (`PRIVATE_STRICT_ANON`, `PRIVATE_FILE_COW`, `SHARED_EXPLICIT`, `SPECIAL_EXCLUDED`), register them to SBI/monitor on the specified Linux MM lifecycle events through a coarse range-based ABI, enforce policy at leaf-page install/first-touch by collapsing the current region decision into the leaf bitmap (`PRIVATE_DATA` on/off), preserve the existing early `ROOT_L0` registration and two-phase teardown behavior, and produce attribution data that can drive the next design decision. A full-mm snapshot sync on slow MM events is preferred over delicate per-event delta surgery if it is simpler and correct. The decision gate is now resolved in favor of keeping this baseline conservative and, if work resumes, prioritizing an explicit shared-buffer / agent-managed window follow-on for the dominant copy-heavy paths instead of broader private coverage.
- Disallowed Shape: Do not keep treating all user leaf pages as one protected class. Do not leave `sm_prepare_user_pt()` or `sm_nacc_set_ptes()` as blind "tag every user leaf candidate" helpers. Do not infer runtime policy from trap frequency. Do not auto-convert hot pages from private to shared. Do not collapse semantic region boundaries into per-page heuristics. Do not treat the 2-bit bitmap as a full region-class database or try to encode the whole four-class VMA taxonomy directly in bitmap bits alone. Do not include Secure PTP access traps in the attribution target set. Do not use the rerun evidence to justify widening `PRIVATE_FILE_COW`, relaxing `SPECIAL_EXCLUDED` / `LOOKUP_MISS_OR_UNKNOWN` conservatism, or silently declassifying hot private leaves into shared buffers.
- Allowed Freedom: Planner and coder may choose the exact kernel / OpenSBI touchpoints and logging shape needed to implement the required workstreams, as long as the resulting design remains VMA-guided, leaf-enforced, region-based, and consistent with the stated non-goals. The first cut may prefer full-mm snapshot registration over fine-grained update ABI. `PRIVATE_FILE_COW` must remain separately visible in region records and logs, but it must not become private by region class alone; `PRIVATE_DATA` may be set there only for a leaf that Linux can explicitly identify as a post-COW anonymous-private install, otherwise the conservative first-cut fallback is to leave `PRIVATE_DATA` unset and log the case. Unknown or ambiguous mappings may conservatively fall into `SPECIAL_EXCLUDED` for the first cut, but must be logged rather than silently treated as private. After this stage closes, allowed follow-on freedom is only around the narrow explicit shared-buffer / agent-managed window route and the minimal attribution hint it may need; region-policy coverage itself stays frozen until a later packet explicitly changes it.
- Scope: This stage covers trap attribution, VMA classification plus SBI registration, leaf-page enforcement for the listed region classes, bounded decision counters for how region policy collapses into leaf bitmap state, preservation of `ROOT_L0` and teardown invariants, and recording the post-attribution decision gate for the next stage.
- Constraints: Policy is decided at VMA/region level. Enforcement happens only at leaf-page installation / first-touch time. Trap profiling is for path attribution only. Do not auto-convert hot pages from private to shared. Shared/private boundary must remain semantic and region-based. Keep early `ROOT_L0` registration. Keep two-phase teardown. Do not clear `ROOT_L0` at `exit_mmap` entry. Focus attribution on user data page traps; traps caused by accessing Secure PTP are excluded.
- Open Semantic Questions: Stage-1 semantics are closed on the clean rerun: full-mm snapshot sync is sufficient for this landing, `PRIVATE_FILE_COW` widening is unsupported by current evidence and stays bitmap-off, and repeated `SPECIAL_EXCLUDED` / `LOOKUP_MISS_OR_UNKNOWN` cases remain conservative watchpoints rather than next-stage targets. The only remaining follow-on semantic question is whether an explicit shared-buffer / agent-managed window experiment needs one extra narrow path hint to separate dominant `syscall-buffer path` traffic from `teardown / mapping update`; if not, the next packet should start directly with the narrow shared-buffer route rather than more attribution-only work.
- Human Concern: User leaf-page trap cost needs semantic attribution so the system can move from all-protected leaves to a selective-private baseline without drifting into per-page heuristics or monitor-owned shadow-MM designs.
- Reconciliation Required: no
- Post-Run Analysis Required: no
- Definition Of Done: Linux and monitor expose attribution that buckets relevant user data page traps into `anonymous fault`, `file fault`, `COW`, `syscall-buffer path`, and `teardown / mapping update`; Linux classifies VMAs into `PRIVATE_STRICT_ANON`, `PRIVATE_FILE_COW`, `SHARED_EXPLICIT`, and `SPECIAL_EXCLUDED`; region policy is registered to SBI/monitor on `exec`, `mmap`, `brk`, `mprotect`, `mremap`, `munmap`, `fork`, and `exit_mmap`; leaf-page enforcement follows the region policy with `PRIVATE_STRICT_ANON` applied only when leaf pages become present, `PRIVATE_FILE_COW` kept distinct for profiling and leaving `PRIVATE_DATA` unset unless Linux can explicitly identify a post-COW anonymous-private leaf install, `SHARED_EXPLICIT` leaving `PRIVATE_DATA` unset, and `SPECIAL_EXCLUDED` left outside ordinary confidential-private handling; bounded counters expose how many leaf decisions at `reconcile` and `install` became `PRIVATE_DATA` or stayed non-private under each region class, plus lookup-miss / ambiguous-exclude cases; `ROOT_L0` and two-phase teardown invariants are preserved; the resulting logs or measurements are sufficient to decide whether the next step should expand private coverage or prioritize an explicit shared-buffer / agent-managed window abstraction. This packet is complete only once that decision gate is recorded explicitly from the clean rerun evidence.
- Related State:
  - `docs/workflow/CURRENT_STATE.md`
  - `docs/workflow/NEXT_STEPS.md`
- Related Ticket / Plan:
  - `docs/workflow/tasks/completed/TASK_20260414_113719_private_bitmap.md`
  - `docs/workflow/PLAN_20260322_filemap_fault_wedge.md`
- Branch / Worktree: `main` workspace with local subrepo edits expected
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

## Required Artifacts

- Patch or commit:
- Minimal compile result: Kernel/OpenSBI/agent components touched by the route build successfully or the exact compile blocker is documented.
- Test command or batch plan: A focused validation run that exercises anonymous fault, file-backed fault, COW, syscall-buffer path, and teardown/mapping-update paths and records attribution logs.
- Primary log path: Trap attribution and enforcement logs for the validation scenario.
- Log path if validation fails: Build and runtime logs capturing the first failing stage.
- Counter summary: A bounded summary of leaf-decision counters showing, at minimum, `touchpoint x region_class x enforcement_action` totals for the validation run.

## Latest Summary

- Workflow state and current code path have been reviewed against this packet.
- The current all-protected-leaf baseline is now concretely identified: `sm_prepare_user_pt()` still calls a blind `nacc_sync_private_tags()` walk, and `sm_nacc_set_ptes()` still blindly tags every user leaf candidate without VMA/region policy.
- The chosen route is to replace that blind tagging with coarse region registration plus region-aware leaf enforcement at the two real leaf touchpoints: present-leaf reconcile during attach/exec/fork-child preparation, and secure `set_ptes` leaf installation with a VA-bearing SBI path.
- `pgd_alloc()` early `ROOT_L0` tagging, `pgd_free()` late root retirement, and the two-phase `exit_mmap()` teardown contract are confirmed as invariants and must stay unchanged.
- Trap attribution remains limited to user-data `PRIVATE_DATA` traps; the first cut should reuse bounded monitor-side `mepc` stats and symbolization before adding any broader Linux-side path-hint ABI.
- The first implementation cut is now frozen as a conservative route: ambiguous VMAs default to logged `SPECIAL_EXCLUDED`, region sync is replace-style snapshot-first, and coder work should land in ordered slices rather than mixing ABI expansion with attribution experiments.
- The packet now explicitly freezes the intended representation split: VMA/region class remains the policy source, while the bitmap only stores the frozen leaf-level enforcement outcome produced from that policy when a present leaf is reconciled or installed.
- `PRIVATE_FILE_COW` is now frozen in the stricter conservative form: keep it as a distinct region class, but do not set `PRIVATE_DATA` from region class alone; only a Linux-visible post-COW anonymous-private leaf install may turn the bitmap on there, otherwise the first cut leaves it off.
- The packet now explicitly asks for bounded counters on the region-to-bitmap collapse so validation can answer which semantic classes are actually producing `PRIVATE_DATA` leaves, without turning the bitmap into a metadata database.
- Coder landed the frozen first-cut route across Linux and OpenSBI: replace-style region snapshot ABI, Linux VMA classification plus sync on the required MM events, region-aware present-leaf reconcile and secure leaf-install handling, and bounded `touchpoint x region_class x enforcement_action` counters dumped from the monitor region state.
- Minimal compile checks completed in this coder pass: `make linux-update` succeeded after the Linux-side route landed, and `make opensbi` succeeded again after the bounded-counter refinement. No runtime batch was run here because packet-owned validation remains with reviewer/test_runner.
- Reviewer-found fidelity blockers have now been addressed in code without widening scope: `munmap` and `mremap` refresh the region snapshot before dropping `mmap_lock` on the NaCC-managed path, so leaf-touch enforcement no longer has the post-unlock stale-policy window identified in review.
- Missing-root leaf decisions in the monitor are no longer silent: the leaf-selection path now logs the event and records it conservatively under `LOOKUP_MISS_OR_UNKNOWN`, lazily attaching the miss to the root state when the root is already `ROOT_L0`-tagged but has not received its first successful snapshot yet.
- This follow-up coder pass ran only minimal compile sanity checks for the touched files: targeted Linux rebuild of `mm/mmap.o` and `mm/mremap.o`, plus an OpenSBI rebuild after the `region.c` change. No packet-owned runtime batch was run here.
- Reviewer re-review now accepts the implementation route for test: the two prior fidelity blockers are fixed, the region-policy control model remains packet-aligned, and the remaining concerns are runtime-proof watchpoints rather than code-shape blockers.
- Test-runner completed the packet-owned T1 batch command set after rebuilding the changed components with `make opensbi`, `make linux-update`, and `make agent-update`.
- The visible workload markers are present in the T1 VM artifacts: `kernel_read_done`, `kernel_write_done`, `fork_private_done`, `done` for the split file/pipeline probes, and `ping` for the shared-memory repro.
- Long QEMU artifacts with `region: decisions ...` and `PRIVATE_DATA trap stats` are present for the detached batch execution and need log reduction / attribution by `log_analyzer`; the direct unrestricted rerun was kept only to capture a reliable harness summary after the initial launcher log stopped before the final summary block.
- Log analysis reduced the detached batch and found a runtime-quality blocker despite the visible workload markers: every detached run carries monitor-side `region: alloc failed` / Linux-side `region sync range failed` events, with the first bad point in detached run 1 during `reason=invoke` on a `PRIVATE_FILE_COW` range.
- The bounded region-decision evidence is still directionally consistent with the packet: across the eight detached run-end blocks, `PRIVATE_STRICT_ANON` is the only class that ever sets `PRIVATE_DATA` (`reconcile set=10`, `install set=50`), while `PRIVATE_FILE_COW` always stays bitmap-off (`reconcile leave_off=15`, `install leave_off=1428`), `SPECIAL_EXCLUDED` stays off (`install leave_off=6`), and `LOOKUP_MISS_OR_UNKNOWN` remains materially present (`install leave_off=1931`).
- The trap profile is dominated by syscall-buffer/usercopy-style PCs rather than file/COW-specific signatures: summed detached run-end `PRIVATE_DATA trap stats` are `load=16937 store=35262 total=52199`, and the recurring top `mepc` symbols are `fallback_scalar_usercopy` (`0xffffffff80a2098e/88/7a`) plus `do_strncpy_from_user` (`0xffffffff804d1122`), with `clear_page` (`0xffffffff80a1fb54`) appearing strongly only in the shared-memory repro.
- Current logs only partially separate `syscall-buffer path` from `teardown / mapping update`: syscall-buffer is identifiable from the bounded `mepc` summaries, but teardown currently relies on local `zap_pte_range` windows with `set_pmd` / `raw_atomic64_xchg` context rather than an equally clean bounded bucket.
- Coder root-caused the sync failure to monitor-side region-record allocation churn on the generic OpenSBI heap, not to the VMA-policy collapse itself: the failing path allocated and freed tiny snapshot nodes through `sbi_zalloc()` / `sbi_free()` on each `BEGIN/RANGE/END` cycle, while OpenSBI only had a 37 KB firmware heap with a small bookkeeping-node budget.
- OpenSBI region snapshots now keep the same replace-style control model but allocate range records from an internal bounded pool instead of the generic heap; `begin`, `end`, and root retirement recycle those records under the existing region lock, so detached T1 should no longer depend on generic heap fragmentation or housekeeping-node availability just to register six-ish merged ranges.
- The `alloc failed` log now carries pool context (`active`, `staging`, `pool_free`, `pool_cap`) if the new bounded pool ever exhausts, which keeps future runtime failures attributable without widening the packet scope.
- This coder pass ran only the minimal touched-component sanity check required for the new route: `make opensbi` succeeded after the pool conversion. The detached T1 rerun was intentionally left for reviewer/test_runner because the previous failure already came from a packet-owned test-runner loop.
- Reviewer follow-up accepts the allocator route on spec fidelity, but blocks test because [opensbi/lib/sbi/sm/region.c](/home/link/NaCC/opensbi/lib/sbi/sm/region.c:54) initializes the shared record pool without serialization; concurrent first use can corrupt `free_record_head` / `records[i].next` before the snapshot path consumes the pool.
- The same review records a non-blocking footprint watchpoint from the current build artifacts: `fw_payload.elf` now reports `bss=1349616`, and `nacc_region_db` accounts for about `0x132020` bytes in local `nm` output, so follow-up fixes should stay narrow and avoid growing monitor-side state further.
- Coder has now tightened that bootstrap fix narrowly in [opensbi/lib/sbi/sm/region.c](/home/link/NaCC/opensbi/lib/sbi/sm/region.c:56): `nacc_region_init_once()` still builds the free list under `nacc_region_db.lock`, and its one-time `initialized` guard now uses `__smp_load_acquire()` / `__smp_store_release()` so the lockless fast path does not observe `initialized=true` before the record-pool state is fully published.
- This follow-up coder pass reran only the touched-component compile sanity check after the acquire/release guard fix: `make -C opensbi PLATFORM=generic CROSS_COMPILE=/home/link/NaCC/riscv-tools/bin/riscv64-unknown-linux-gnu- all -j8` succeeded. No packet-owned detached T1 rerun was performed here.
- Reviewer targeted recheck now accepts the bootstrap fix for test: `nacc_region_init_once()` no longer relies on a plain unlocked publication path, the bounded-pool `BEGIN/RANGE/END` control model is unchanged, and only the existing footprint/debug-dump watchpoints remain before the packet-owned detached T1 rerun.
- Log-analyzer has now reduced the clean detached T1 rerun and confirmed the old allocator failure is gone: runs 1 through 8 complete with the expected VM markers, and the rerun QEMU logs do not contain `region: alloc failed` or `region sync range failed`.
- The rerun leaf-policy collapse stays packet-aligned in the final run-end blocks: summed across the eight rerun QEMU logs, `PRIVATE_STRICT_ANON` is the only class that sets `PRIVATE_DATA` (`reconcile set=11`, `install set=126`), while `PRIVATE_FILE_COW` stays bitmap-off (`reconcile leave_off=15`, `install leave_off=3195`), `SHARED_EXPLICIT` stays off (`install leave_off=1`), `SPECIAL_EXCLUDED` stays off (`install leave_off=16`), and `LOOKUP_MISS_OR_UNKNOWN` remains bounded but present (`install leave_off=53`).
- The rerun trap burden is dominated by copy/helper paths rather than file/COW-specific signals: summed final `PRIVATE_DATA trap stats` are `load=31402 store=42531 total=73933`, and the hottest symbolized PCs are `fallback_scalar_usercopy`, `__pi___memset`, and `__pi___memcpy`, with only a smaller early `rseq` / futex-cleanup cluster in the short kernel read/write cases.
- Remaining watchpoints are runtime-visible but not failure-grade in this rerun: the logs repeatedly register the same conservative `SPECIAL_EXCLUDED` ambiguous ranges (`187` `region sync ambiguous VMA` events total, mostly `mmap=101` and `mprotect=56`), and the final root summaries report `lookup_miss=53`, but those cases stay logged and bitmap-off instead of widening private coverage.
- The rerun evidence is now sufficient for the packet's decision gate, so the next hop should be planner rather than coder: current data does not justify widening `PRIVATE_FILE_COW`, and any next-stage optimization decision should start from the observed copy-heavy trap profile rather than from the stale allocator failure path.
- Planner decision gate is now closed on the clean rerun evidence: this packet's baseline is accepted as the conservative selective-private landing, `PRIVATE_FILE_COW` widening is explicitly rejected for the next step, and any future optimization work must start from the dominant copy-helper / syscall-buffer profile rather than reopen region-policy semantics.

## Next Handoff

- Next owner: human
- Handoff type: hold-point after planner decision gate; packet contains a parked follow-on seed but must not be handed directly to coder until the human has caught up
- Trigger: the clean detached T1 rerun has closed the stage-1 decision gate, and the next move is now a human review of the frozen baseline plus the parked follow-on route
- Exact artifact to read first: [TASK_20260415_154406_vma_guided_bitmap.md](/home/link/NaCC/docs/workflow/tasks/active/TASK_20260415_154406_vma_guided_bitmap.md)
- Human focus:
  - confirm that this packet is closed as the conservative selective-private baseline and should not be reopened for broader private coverage
  - review the parked follow-on seed below before authorizing any coder work
  - keep `PRIVATE_FILE_COW`, `SPECIAL_EXCLUDED`, and `LOOKUP_MISS_OR_UNKNOWN` semantics frozen unless a later packet explicitly changes them

## Coder Result

- Implementation summary:
  - Tightened `nacc_region_init_once()` in `opensbi/lib/sbi/sm/region.c` so the fast-path guard now uses `__smp_load_acquire()` / `__smp_store_release()` around `initialized`, while keeping the existing spinlock-protected free-list construction intact. This closes the remaining publication hole in the shared pool bootstrap without changing the snapshot model or record-pool layout.
  - Replaced heap-backed region snapshot records in `opensbi/lib/sbi/sm/region.c` with a bounded internal pool (`NACC_REGION_RECORD_MAX`) so `nacc_region_sync_range()` no longer depends on repeated `sbi_zalloc()` calls for each emitted range.
  - Made `nacc_region_sync_begin()`, `nacc_region_sync_end()`, and `nacc_region_retire_root()` recycle staging/active records back into that pool under the existing region lock, preserving the current replace-style `BEGIN/RANGE/END` model instead of inventing a new incremental ABI.
  - Kept failure observability narrow and packet-aligned: if the bounded pool ever does exhaust, the monitor now logs `active`, `staging`, `pool_free`, and `pool_cap` with the existing `region: alloc failed` line so reviewer/test_runner can attribute the next failure without changing policy shape.
- Commit or patch:
  - working tree patch only in this coder pass
  - touched files:
    - `opensbi/lib/sbi/sm/region.c`
    - this packet
- Route chosen and why:
  - followed the same narrow reviewer-requested route all the way through the init fix: make the existing one-time bootstrap publication safe instead of redesigning initialization ownership or widening runtime state
  - followed the packet/requested narrow fix route instead of widening Linux/OpenSBI semantics: preserve the existing region-class control model and only remove the unstable allocator dependency in the monitor snapshot path.
  - chose a bounded internal pool over more architectural changes because the failing mechanism was allocator churn, while the runtime counters already showed the region-to-bitmap collapse itself was directionally correct.
  - intentionally did not rerun the detached T1 batch here; the prior failure came from a packet-owned test-runner loop, so this pass stops at code fix plus minimal compile sanity and hands back for review/test.
- Escalations made:
  - none
- Remaining risks:
  - runtime packet-owned validation is still pending; this coder pass confirms the allocator-route change compiles, not that the detached T1 rerun is clean
  - the bounded pool size is intentionally conservative rather than dynamically sized; if a future workload genuinely exceeds it, the new failure log should show whether that is a real capacity issue instead of generic heap churn
  - `PRIVATE_FILE_COW` intentionally stays bitmap-off in this first cut unless a future stage lands a narrow post-COW anonymous-private leaf-install signal
  - attribution still relies on the existing bounded monitor `mepc` statistics plus symbolization to separate dominant runtime paths; if reviewer/test_runner cannot distinguish `syscall-buffer path` from `teardown / mapping update`, the next stage should add only the narrowest additional hint
  - huge-leaf or unusual install paths should be watched in runtime review; this cut applies region policy by VA at the approved leaf touchpoints but does not introduce separate metadata for huge-page ancestry

## Review Result

- Approval status: approve-with-conditions
- Spec fidelity: acceptable; the current bootstrap fix is the narrow publication/serialization repair requested by review and it stays inside the already-approved snapshot-first, region-based route
- Fidelity findings:
  - [opensbi/lib/sbi/sm/region.c](/home/link/NaCC/opensbi/lib/sbi/sm/region.c:57) now keeps free-list construction serialized under `nacc_region_db.lock` and gates the lockless fast path with `__smp_load_acquire()` / `__smp_store_release()`. That closes the earlier unlocked-publication hole without widening ABI surface or changing region semantics.
  - The bounded-pool route is still a storage/recycling change, not a policy change. [opensbi/lib/sbi/sm/region.c](/home/link/NaCC/opensbi/lib/sbi/sm/region.c:325), [opensbi/lib/sbi/sm/region.c](/home/link/NaCC/opensbi/lib/sbi/sm/region.c:364), [opensbi/lib/sbi/sm/region.c](/home/link/NaCC/opensbi/lib/sbi/sm/region.c:436), and [opensbi/lib/sbi/sm/region.c](/home/link/NaCC/opensbi/lib/sbi/sm/region.c:486) still preserve the same replace-style `BEGIN/RANGE/END` snapshot model and recycling behavior across `begin`, `range`, `end`, failed mid-sync retries, and `nacc_region_retire_root()`.
  - Leaf enforcement remains packet-aligned and still happens only at the approved touchpoints. [opensbi/lib/sbi/sm/sm.c](/home/link/NaCC/opensbi/lib/sbi/sm/sm.c:155) keeps `sm_prepare_user_pt()` as a reconcile step, [opensbi/lib/sbi/sm/sm.c](/home/link/NaCC/opensbi/lib/sbi/sm/sm.c:537) still routes leaf installs through `nacc_tag_private_ptes()`, and [opensbi/lib/sbi/sm/vm.c](/home/link/NaCC/opensbi/lib/sbi/sm/vm.c:272) plus [opensbi/lib/sbi/sm/region.c](/home/link/NaCC/opensbi/lib/sbi/sm/region.c:546) still collapse region policy into bitmap state only at reconcile/install while keeping `PRIVATE_FILE_COW` bitmap-off in the first cut.
  - Early `ROOT_L0` registration and late root retirement remain intact. [opensbi/lib/sbi/sm/sm.c](/home/link/NaCC/opensbi/lib/sbi/sm/sm.c:575) still retires region state only through `sm_nacc_retire_root()`, and the region-sync ABI surface stays unchanged in [opensbi/lib/sbi/sbi_ecall_nacc.c](/home/link/NaCC/opensbi/lib/sbi/sbi_ecall_nacc.c:80) and [opensbi/lib/sbi/sm/sm.c](/home/link/NaCC/opensbi/lib/sbi/sm/sm.c:584).
- Risk review: acceptable to proceed to packet-owned detached T1 validation; the previous bootstrap race is closed, and the remaining concerns are watchpoints rather than pre-test blockers
- Risk findings:
  - The prior blocker is closed in code: [opensbi/lib/sbi/sm/region.c](/home/link/NaCC/opensbi/lib/sbi/sm/region.c:57) now uses acquire/release publication around `initialized`, and the underlying lock implementation already provides the expected acquire/release semantics in [opensbi/lib/sbi/riscv_locks.c](/home/link/NaCC/opensbi/lib/sbi/riscv_locks.c:48).
  - Watchpoint: the current build still carries a large static footprint from the bounded pool. Local reviewer inspection of `opensbi/build/platform/generic/firmware/fw_payload.elf` reports `bss=1349616`, and local `nm -S --size-sort` output shows `nacc_region_db` at `0x132020` bytes. That remains packet-acceptable for this rerun, but follow-up fixes should stay narrow and avoid growing monitor-side state further without runtime proof.
  - Watchpoint: [opensbi/lib/sbi/sm/region.c](/home/link/NaCC/opensbi/lib/sbi/sm/region.c:650) still uses `sbi_zalloc()` under the region lock for debug-only root dumps. That is outside the hot sync path and was not the source of the earlier `alloc failed` logs, but if a future debug-heavy rerun still shows heap pressure, preserve the first failing artifact rather than broadening the design during review or test.
- Can proceed to test: yes, with conditions: rerun the packet-owned detached T1 batch, confirm the earlier `region: alloc failed` / `region sync range failed` signature is gone, and preserve the first failing artifact immediately if any pool-capacity or heap-pressure symptom remains
- Key files reviewed:
  - `opensbi/lib/sbi/sm/region.c`
  - `opensbi/lib/sbi/riscv_locks.c`
  - `opensbi/include/sm/region.h`
  - `opensbi/lib/sbi/sbi_ecall_nacc.c`
  - `opensbi/lib/sbi/sm/sm.c`
  - `opensbi/lib/sbi/sm/vm.c`
  - `docs/workflow/CURRENT_STATE.md`
  - `docs/workflow/tasks/active/TASK_20260415_154406_vma_guided_bitmap.md`
- Human-facing code explanation:
  - The latest patch does not redesign region policy. It only makes the monitor-local record pool safe to publish on first use, while keeping the same `BEGIN/RANGE/END` snapshot flow and the same rule that region policy is collapsed into bitmap state only when a present leaf is reconciled or a new leaf is installed.
- Why this route still fits:
  - The route still uses VMA/region class as the only policy source, keeps the bitmap as frozen leaf-level enforcement state, and preserves early `ROOT_L0` plus late retirement semantics.
  - The accepted fix remains an internal OpenSBI allocator/publication repair. It does not add per-page heuristics, trap-learned policy, or a monitor-owned Linux-MM shadow, and it does not widen the Linux/OpenSBI ABI beyond the already-reviewed snapshot interface.
- Next handoff:
  - next owner: test_runner
  - exact first artifact: [config/debug-batch.vma_guided_bitmap_t1.txt](/home/link/NaCC/config/debug-batch.vma_guided_bitmap_t1.txt)
  - required next step: rerun the packet-owned detached T1 batch against the current OpenSBI build, verify that the previous `region: alloc failed` / `region sync range failed` path no longer appears in detached QEMU logs, and hand the resulting log set to `log_analyzer` if clean or back to `coder` with the first failing artifact if not

## Test Result

- Command run:
  - `make -C /home/link/NaCC/opensbi PLATFORM=generic CROSS_COMPILE=/home/link/NaCC/riscv-tools/bin/riscv64-unknown-linux-gnu- all -j8`
- Build actions:
  - rebuilt only the touched OpenSBI component after the bounded-pool route and the follow-up acquire/release bootstrap guard fix in `lib/sbi/sm/region.c`
- Outcome:
  - the OpenSBI rebuild succeeded in this coder pass
  - no packet-owned runtime batch was rerun here; reviewer/test_runner still owns the detached T1 validation loop after this review handoff
- Artifact / log path:
  - local terminal build output only in this coder pass; no dedicated runtime log path yet

## Test Runner Result

- Command run:
  - `make opensbi`
  - `make linux-update`
  - `make agent-update`
  - `tmux new-session -d -s codex-vma-guided-launch-20260415_174329 "cd /home/link/NaCC && config/debug-batch.sh --session-name vma-guided-bitmap-t1-20260415_174329 --tag-prefix vma_guided_bitmap_t1 --wait-after-auto 180 --cmd-file config/debug-batch.vma_guided_bitmap_t1.txt > logs/vma_guided_bitmap_t1_20260415_174329.launcher.log 2>&1"`
  - `config/debug-batch.sh --session-name vma-guided-bitmap-t1-direct-20260415_174650 --tag-prefix vma_guided_bitmap_t1 --wait-after-auto 180 --cmd-file config/debug-batch.vma_guided_bitmap_t1.txt`
- Build actions:
  - rebuilt all dirty packet-relevant components found by runner inspection before the runtime loop
  - `make opensbi`: success
  - `make linux-update`: success
  - `make agent-update`: success
- Outcome:
  - packet-owned T1 runtime loop was executed over the batch plan in [config/debug-batch.vma_guided_bitmap_t1.txt](/home/link/NaCC/config/debug-batch.vma_guided_bitmap_t1.txt)
  - the unrestricted direct batch completed with harness summary `status=ok` for runs 1 through 8
  - the detached batch execution produced the long QEMU artifacts that contain the `region: decisions ...` and `PRIVATE_DATA trap stats` lines needed for attribution reduction
  - VM completion markers are present in the detached batch VM logs for all requested probes:
    - run 1: `kernel_read_done`
    - run 2: `kernel_write_done`
    - run 3: `fork_private_done`
    - run 4: `done` after `cat /etc/hostname`
    - run 5: `alpha` then `done`
    - run 6: `13 /etc/hostname` then `done`
    - run 7: `done` after `echo alpha | wc -c`
    - run 8: `ping`
  - the direct rerun QEMU captures are short duplicate artifacts and at least one includes `Failed to get "write" lock` on `NaCC.qcow2`, so they are not the primary analysis set
  - packet-level result for this pass: `needs_analysis`
- Primary log path:
  - `logs/vma_guided_bitmap_t1_01_20260415_174338_qemu_20260415_174829.log`
- Exact log path for `log_analyzer` handoff:
  - detached launcher:
    - `logs/vma_guided_bitmap_t1_20260415_174329.launcher.log`
  - detached batch run 1:
    - `logs/vma_guided_bitmap_t1_01_20260415_174338_qemu_20260415_174829.log`
    - `logs/vma_guided_bitmap_t1_01_20260415_174338_vm_20260415_174829.log`
  - detached batch run 2:
    - `logs/vma_guided_bitmap_t1_02_20260415_174829_qemu_20260415_175312.log`
    - `logs/vma_guided_bitmap_t1_02_20260415_174829_vm_20260415_175312.log`
  - detached batch run 3:
    - `logs/vma_guided_bitmap_t1_03_20260415_175313_qemu_20260415_175906.log`
    - `logs/vma_guided_bitmap_t1_03_20260415_175313_vm_20260415_175906.log`
  - detached batch run 4:
    - `logs/vma_guided_bitmap_t1_04_20260415_175906_qemu_20260415_180503.log`
    - `logs/vma_guided_bitmap_t1_04_20260415_175906_vm_20260415_180503.log`
  - detached batch run 5:
    - `logs/vma_guided_bitmap_t1_05_20260415_180504_qemu_20260415_181104.log`
    - `logs/vma_guided_bitmap_t1_05_20260415_180504_vm_20260415_181104.log`
  - detached batch run 6:
    - `logs/vma_guided_bitmap_t1_06_20260415_181104_qemu_20260415_181701.log`
    - `logs/vma_guided_bitmap_t1_06_20260415_181104_vm_20260415_181701.log`
  - detached batch run 7:
    - `logs/vma_guided_bitmap_t1_07_20260415_181701_qemu_20260415_182303.log`
    - `logs/vma_guided_bitmap_t1_07_20260415_181701_vm_20260415_182303.log`
  - detached batch run 8:
    - `logs/vma_guided_bitmap_t1_08_20260415_182304_qemu_20260415_182901.log`
    - `logs/vma_guided_bitmap_t1_08_20260415_182304_vm_20260415_182901.log`
  - direct rerun harness-summary set:
    - `logs/vma_guided_bitmap_t1_01_20260415_174706_qemu_20260415_175011.log`
    - `logs/vma_guided_bitmap_t1_01_20260415_174706_vm_20260415_175011.log`
    - `logs/vma_guided_bitmap_t1_02_20260415_175011_qemu_20260415_175334.log`
    - `logs/vma_guided_bitmap_t1_02_20260415_175011_vm_20260415_175334.log`
    - `logs/vma_guided_bitmap_t1_03_20260415_175334_qemu_20260415_175907.log`
    - `logs/vma_guided_bitmap_t1_03_20260415_175334_vm_20260415_175907.log`
    - `logs/vma_guided_bitmap_t1_04_20260415_175907_qemu_20260415_180503.log`
    - `logs/vma_guided_bitmap_t1_04_20260415_175907_vm_20260415_180503.log`
    - `logs/vma_guided_bitmap_t1_05_20260415_180503_qemu_20260415_181104.log`
    - `logs/vma_guided_bitmap_t1_05_20260415_180503_vm_20260415_181104.log`
    - `logs/vma_guided_bitmap_t1_06_20260415_181105_qemu_20260415_181704.log`
    - `logs/vma_guided_bitmap_t1_06_20260415_181105_vm_20260415_181704.log`
    - `logs/vma_guided_bitmap_t1_07_20260415_181704_qemu_20260415_182302.log`
    - `logs/vma_guided_bitmap_t1_07_20260415_181704_vm_20260415_182302.log`
    - `logs/vma_guided_bitmap_t1_08_20260415_182302_qemu_20260415_182900.log`
    - `logs/vma_guided_bitmap_t1_08_20260415_182302_vm_20260415_182900.log`
- Counter summary:
  - bounded counter lines are present in the detached batch QEMU logs with the expected `[SBI] region: decisions touch=... class=... set=... leave_off=...` and `[SBI] PRIVATE_DATA trap stats: ...` formats
  - this test-runner pass did not reduce or interpret those counters; packet remains `needs_analysis` for `log_analyzer`

## Analysis Result

- Observed symptom:
  - the detached T1 batch is workload-successful but runtime-suspicious: all requested VM-side completion markers are present, yet every detached QEMU run also contains monitor-side `region: alloc failed` followed by Linux-side `region sync range failed` on snapshot registration paths
- Run verdict:
  - suspicious
- First bad point:
  - detached run 1 hits the first concrete internal failure at `logs/vma_guided_bitmap_t1_01_20260415_174338_qemu_20260415_174829.log:11167-11170`
  - the sequence is:
    - `[SBI] region: alloc failed root_pfn=102a2c [2acc415000,2acc50e000) class=PRIVATE_FILE_COW flags=40`
    - `[Linux]: region sync range failed: root=102a2c000 range=[2acc415000,2acc50e000) class=PRIVATE_FILE_COW flags=40 err=-1 val=0`
    - `[Linux]: nacc_invoke region sync failed for mm=ffffffd682c46280`
- Evidence:
  - workload-level pass evidence is present in the detached VM logs:
    - run 1 `kernel_read_done`
    - run 2 `kernel_write_done`
    - run 3 `fork_private_done`
    - runs 4 to 7 `done` with the expected intermediate output
    - run 8 `ping`
  - the region-policy collapse itself still matches the packet direction:
    - across the eight detached run-end blocks, `PRIVATE_STRICT_ANON` is the only class that sets `PRIVATE_DATA` (`reconcile set=10`, `install set=50`)
    - `PRIVATE_FILE_COW` never sets `PRIVATE_DATA` in the observed run-end blocks (`reconcile leave_off=15`, `install leave_off=1428`)
    - `SPECIAL_EXCLUDED` stays non-private (`install leave_off=6`)
    - `LOOKUP_MISS_OR_UNKNOWN` remains materially present (`install leave_off=1931`)
  - the trap burden is dominated by syscall-buffer / usercopy style PCs, not by a clean file-fault / COW bucket:
    - summed detached run-end `PRIVATE_DATA trap stats`: `load=16937 store=35262 total=52199`
    - recurring top `mepc` symbols from `riscv-linux/vmlinux`:
      - `0xffffffff80a2098e`, `0xffffffff80a20988`, `0xffffffff80a2097a`: `fallback_scalar_usercopy`
      - `0xffffffff804d1122`: `do_strncpy_from_user`
      - `0xffffffff80a1fb54`: `clear_page`
  - teardown / mapping-update evidence exists, but mostly as local context rather than as an equally clean bounded bucket:
    - detached run 1 shows `zap_pte_range` with `tcntx->regs.mepc=0xffffffff80191ee8`, symbolized to `set_pmd`, at `logs/vma_guided_bitmap_t1_01_20260415_174338_qemu_20260415_174829.log:7301-7316`
    - detached run 5 shows `zap_pte_range` with `0xffffffff80191c4c` / `0xffffffff80191ee8`, symbolized to `raw_atomic64_xchg` / `set_pmd`, at `logs/vma_guided_bitmap_t1_05_20260415_180504_qemu_20260415_181104.log:50904-50920`
    - detached run 8 shows `sys_munmap` / `zap_pte_range` interleaving with other syscall traffic immediately before a `SHARED_EXPLICIT` sync failure at `logs/vma_guided_bitmap_t1_08_20260415_182304_qemu_20260415_182901.log:4404-4450`
- Likely cause:
  - the immediate failing mechanism is explicit in the logs: monitor-side region-record allocation or acceptance is failing during snapshot range registration, and Linux then continues with a failed region sync on invoke / fork / exec / munmap paths
  - the logs do not prove the exact allocator bug or capacity rule, so that deeper cause still needs code investigation
- Bucketability assessment:
  - `syscall-buffer path`: yes, strong signal
  - `teardown / mapping update`: only partially; visible in contextual windows, not as a comparably clean bounded `mepc` bucket
  - `anonymous fault`: partial; `clear_page` is a real signal in the shared-memory repro
  - `file fault` versus `COW`: not cleanly separated from current bounded `mepc` evidence
- Confidence:
  - high on the first bad point and on the repeated allocation/sync-failure pattern
  - medium on the semantic bucket split beyond syscall-buffer dominance, because part of that split still depends on contextual symbolization rather than a single bounded summary line
- Human-facing summary:
  - The selective-private collapse looks directionally correct: only `PRIVATE_STRICT_ANON` is turning on `PRIVATE_DATA`, while `PRIVATE_FILE_COW` stays off as intended. But this T1 batch is not clean acceptance evidence yet, because every detached run also shows region snapshot allocation failures. The current logs are already enough to say syscall-buffer/usercopy dominates the trap burden, but they are not clean enough to use as the sole planning gate until the region-sync failure path is fixed.
- Recommended next owner:
  - coder
- Recommended next step:
  - debug and fix the `region: alloc failed` / `region sync range failed` path first, rerun the same detached batch, and only then use the same counter + `mepc` format to decide whether the next semantic move is broader private coverage or an explicit shared-buffer / agent-managed window design

## Test Runner Result (2026-04-15 detached T1 rerun)

- Supersedes:
  - this rerun supersedes the stale failed-run recommendation immediately above for current packet owner/status purposes
- Command run:
  - `make opensbi`
  - `make linux-update`
  - `make agent-update`
  - detached launcher via `tmux`: `config/debug-batch.sh --session-name vma-guided-bitmap-t1-rerun-20260415_192402 --tag-prefix vma_guided_bitmap_t1_rerun --wait-after-auto 180 --cmd-file config/debug-batch.vma_guided_bitmap_t1.txt`
- Build actions:
  - rebuilt dirty packet-relevant components in runner order before the rerun
  - `make opensbi`: success
  - `make linux-update`: success
  - `make agent-update`: success
- Outcome:
  - packet-owned detached T1 rerun completed through launcher session `codex-vma-guided-launch-20260415_192402` and batch session `vma-guided-bitmap-t1-rerun-20260415_192402`
  - the launcher summary reports `status=ok` for runs 1 through 8
  - the earlier `region: alloc failed` / `region sync range failed` signature is absent in the rerun QEMU logs
  - VM completion markers are present in the rerun VM logs for all requested probes:
    - run 1: `kernel_read_done`
    - run 2: `kernel_write_done`
    - run 3: `fork_private_done`
    - run 4: `done` after `cat /etc/hostname`
    - run 5: `alpha` then `done`
    - run 6: `13 /etc/hostname` then `done`
    - run 7: `6` then `done`
    - run 8: `ping`
  - bounded counter lines are present in all rerun QEMU logs with the expected `[SBI] region: decisions ...` and `[SBI] PRIVATE_DATA trap stats ...` formats
  - packet-level result for this pass: `needs_analysis`
- Primary log path:
  - `logs/vma_guided_bitmap_t1_rerun_01_20260415_192402_qemu_20260415_192859.log`
- Exact log path for `log_analyzer` handoff:
  - detached launcher:
    - `logs/vma-guided-bitmap-t1-rerun-20260415_192402.launcher.log`
  - detached batch run 1:
    - `logs/vma_guided_bitmap_t1_rerun_01_20260415_192402_qemu_20260415_192859.log`
    - `logs/vma_guided_bitmap_t1_rerun_01_20260415_192402_vm_20260415_192859.log`
  - detached batch run 2:
    - `logs/vma_guided_bitmap_t1_rerun_02_20260415_192859_qemu_20260415_193344.log`
    - `logs/vma_guided_bitmap_t1_rerun_02_20260415_192859_vm_20260415_193344.log`
  - detached batch run 3:
    - `logs/vma_guided_bitmap_t1_rerun_03_20260415_193344_qemu_20260415_193831.log`
    - `logs/vma_guided_bitmap_t1_rerun_03_20260415_193344_vm_20260415_193831.log`
  - detached batch run 4:
    - `logs/vma_guided_bitmap_t1_rerun_04_20260415_193831_qemu_20260415_194320.log`
    - `logs/vma_guided_bitmap_t1_rerun_04_20260415_193831_vm_20260415_194320.log`
  - detached batch run 5:
    - `logs/vma_guided_bitmap_t1_rerun_05_20260415_194321_qemu_20260415_194804.log`
    - `logs/vma_guided_bitmap_t1_rerun_05_20260415_194321_vm_20260415_194804.log`
  - detached batch run 6:
    - `logs/vma_guided_bitmap_t1_rerun_06_20260415_194804_qemu_20260415_195247.log`
    - `logs/vma_guided_bitmap_t1_rerun_06_20260415_194804_vm_20260415_195247.log`
  - detached batch run 7:
    - `logs/vma_guided_bitmap_t1_rerun_07_20260415_195248_qemu_20260415_195731.log`
    - `logs/vma_guided_bitmap_t1_rerun_07_20260415_195248_vm_20260415_195731.log`
  - detached batch run 8:
    - `logs/vma_guided_bitmap_t1_rerun_08_20260415_195731_qemu_20260415_200214.log`
    - `logs/vma_guided_bitmap_t1_rerun_08_20260415_195731_vm_20260415_200214.log`
- Counter summary:
  - the runner confirmed presence of the bounded counter formats in all eight rerun QEMU logs
  - this runner pass did not reduce or interpret the long counter/trap logs; the handoff remains `needs_analysis` for `log_analyzer`

## Analysis Result (2026-04-15 detached T1 rerun)

- Supersedes:
  - this section supersedes the stale failed-run analysis above for current packet status and next-owner purposes
- Observed symptom:
  - the rerun is workload-successful and allocator-clean; the earlier `region: alloc failed` / `region sync range failed` signature does not appear in the rerun QEMU logs, and all eight VM-side workload markers are present
- Run verdict:
  - acceptable
- First bad point:
  - none in the rerun artifact set
- Dominant trap / event pattern:
  - the dominant runtime pattern is copy-helper traffic on already-private anon leaves, not file/COW-specific private expansion
  - early short runs are dominated by `rseq_get_rseq_cs`, `clear_rseq_cs`, and `rseq_update_cpu_node_id` plus some `fallback_scalar_usercopy`
  - the heavier split file/pipeline runs are dominated by `fallback_scalar_usercopy` and then `__pi___memset`
  - the shared-memory repro ends with `SHARED_EXPLICIT leave_off=1` and a load-heavy `__pi___memcpy` cluster rather than private expansion of that shared mapping
- Evidence:
  - workload markers are present in the rerun VM logs:
    - run 1: `kernel_read_done`
    - run 2: `kernel_write_done`
    - run 3: `fork_private_done`
    - run 4: `done`
    - run 5: `alpha` then `done`
    - run 6: `13 /etc/hostname` then `done`
    - run 7: `6` then `done`
    - run 8: `ping`
  - the old failure signature is absent from the rerun QEMU set:
    - no `region: alloc failed`
    - no `region sync range failed`
  - the final run-end decision counters across the eight rerun QEMU logs stay aligned with the packet's conservative policy:
    - `reconcile PRIVATE_STRICT_ANON`: `set=11 leave_off=0`
    - `reconcile PRIVATE_FILE_COW`: `set=0 leave_off=15`
    - `install PRIVATE_STRICT_ANON`: `set=126 leave_off=0`
    - `install PRIVATE_FILE_COW`: `set=0 leave_off=3195`
    - `install SHARED_EXPLICIT`: `set=0 leave_off=1`
    - `install SPECIAL_EXCLUDED`: `set=0 leave_off=16`
    - `install LOOKUP_MISS_OR_UNKNOWN`: `set=0 leave_off=53`
  - the final run-end root summaries align with those counters:
    - `leaf_private=137`
    - `lookup_miss=53`
    - `cow_skip=3210`
    - `shared_skip=1`
    - `special_skip=16`
  - the final `PRIVATE_DATA` trap totals summed across the eight rerun QEMU logs are:
    - `load=31402`
    - `store=42531`
    - `total=73933`
  - the hot symbolized PCs from `riscv-linux/vmlinux` are:
    - `0xffffffff80a20988`, `0xffffffff80a2098e`, `0xffffffff80a2097a`, `0xffffffff80a208fa`: `fallback_scalar_usercopy`
    - `0xffffffff80a20580` through `0xffffffff80a2059c`: `__pi___memset`
    - `0xffffffff80a202ca` through `0xffffffff80a202d8`: `__pi___memcpy`
    - `0xffffffff80157bd2`, `0xffffffff80157b2a`, `0xffffffff80157dea` through `0xffffffff80157e10`: `rseq_get_rseq_cs`, `clear_rseq_cs`, and `rseq_update_cpu_node_id`
    - `0xffffffff800b13be`, `0xffffffff800b13f0`, `0xffffffff800b144e`: futex robust-list cleanup (`fetch_robust_entry`, `exit_robust_list`)
  - the rerun still logs repeated conservative `SPECIAL_EXCLUDED` handling, but as bounded non-private evidence rather than failure:
    - `187` `region sync ambiguous VMA` / `region: ambiguous range` events total
    - reason split: `mmap=101`, `mprotect=56`, `fork=16`, `invoke=8`, `exec=4`, `munmap=2`
    - those ambiguous ranges stay logged and shared, with only `special_skip=16` in the final run-end summaries
- Likely cause:
  - the dominant trap cost in this rerun is most likely coming from copy-heavy user-buffer and memory-helper paths after `PRIVATE_STRICT_ANON` leaves are installed, not from `PRIVATE_FILE_COW` promotion or from a fresh monitor-side region-sync failure
  - the repeated ambiguous-range logs appear to be the conservative `SPECIAL_EXCLUDED` path doing what this packet allows: logging one recurring special mapping range across multiple MM lifecycle resyncs while leaving it non-private
- Confidence:
  - high on the rerun verdict, the absence of the old allocator failure, and the final region-collapse totals
  - high on the dominant copy-helper attribution because the hottest rerun PCs were symbolized directly against `riscv-linux/vmlinux`
  - medium on any finer semantic split between `syscall-buffer path`, `anonymous fault`, and `teardown / mapping update`, because the bounded `mepc` summaries are stronger for copy-helper attribution than for a full five-bucket separation
- Human-facing summary:
  - The clean rerun is good enough to move the packet forward. The selective-private policy is behaving conservatively as intended: only `PRIVATE_STRICT_ANON` produces private leaves, `PRIVATE_FILE_COW` remains off, the old region-sync allocator failure is gone, and the largest remaining runtime signal is copy-helper traffic rather than file/COW-specific pressure. The main residual watchpoints are repeated logged `SPECIAL_EXCLUDED` ranges and a bounded but non-zero lookup-miss count, not a fresh correctness break.
- Recommended next owner:
  - planner
- Recommended next step:
  - use this rerun as the packet's decision-gate evidence and choose the next semantic route from the observed copy-heavy profile
  - do not reopen coder work for the old allocator path, because that failure is absent in the rerun
  - if a follow-on packet wants more precise separation between `syscall-buffer path` and `teardown / mapping update`, add only the narrowest extra attribution hint instead of broadening region policy or bitmap meaning

## Open Questions

- Does the follow-on shared-buffer / agent-managed window experiment need one extra narrow path hint to separate dominant `syscall-buffer path` traffic from `teardown / mapping update`, or are the current bounded `mepc` stats already sufficient?
- Should the first optimization cut target explicit syscall-buffer sharing first, or an agent-managed transient window, if both preserve the current four-class region-policy baseline?
- Can the follow-on reuse the existing conservative region classes and lifecycle hooks entirely, or does it need one narrowly-scoped explicit-buffer ABI that still leaves ordinary VMA classification unchanged?

## Reconciliation Notes

- Reconciliation has been closed for this first cut.
- `docs/workflow/CURRENT_STATE.md` and `docs/workflow/NEXT_STEPS.md` still carry older framing where bitmap work is either later hardening or still described through the prior all-protected-leaf baseline, but this packet now stands as the settled execution artifact for the narrow scope of VMA-guided selective-private work.
- This settled override is intentionally narrow. It does not authorize a monitor-owned Linux MM shadow, per-page owner/refcount/COW metadata, or any weakening of the existing early `ROOT_L0` and late-retire teardown invariants.
- Any later optimization pass should be spawned under a new packet that cites this one as the frozen baseline, not by reopening this packet's stage-1 semantics while the human is still catching up.

## Planner Route

### Route Chosen And Why

- Keep the current 2-bit PFN tag model and existing `ROOT_L0` lifecycle unchanged.
- Add a small monitor-side region table keyed by the already-tracked root PFN / CID identity, and fill it from Linux with coarse range records rather than leaf records.
- Prefer full-mm region snapshots on the required slow MM events instead of trying to design a rich incremental update ABI up front.
- Replace the current blind leaf-tagging path with region-aware decisions at the two points that already matter:
  - present-leaf reconcile during invoke / exec / fork-child attach preparation
  - secure `set_ptes` leaf installation, after extending the SBI path to carry starting VA
- Reason:
  - this is the narrowest route that removes the current meaning-level bug
  - it preserves the existing `ROOT_L0` and secure-PTP control model
  - it avoids a monitor-owned shadow MM while still making region semantics explicit

### Semantic Freeze

- `PRIVATE_STRICT_ANON`:
  - private anonymous user VMAs such as stack, `brk`, anonymous `mmap`, and ordinary anonymous private regions
  - these are the primary selective-private target in this stage
  - `PRIVATE_DATA` may be set only when a present leaf exists
  - once such a leaf is present, the bitmap is the frozen enforcement form for that leaf until a later mapping update removes or replaces it
- `PRIVATE_FILE_COW`:
  - private file-backed VMAs remain a distinct region class and must not set `PRIVATE_DATA` from region class alone
  - classification follows VMA semantics, not trap frequency
  - `PRIVATE_DATA` may be set there only when Linux can explicitly identify the installed leaf as a post-COW anonymous-private result
  - if the first implementation cannot surface that narrow signal cleanly, keep `PRIVATE_FILE_COW` bitmap-off for this stage instead of widening metadata
- `SHARED_EXPLICIT`:
  - normal `VM_SHARED` / shared-shmem / shared-file mappings
  - leave `PRIVATE_DATA` unset
- `SPECIAL_EXCLUDED`:
  - start with a conservative exclude set such as `VM_NACC`, `VM_IO`, `VM_PFNMAP`, `VM_MIXEDMAP`, and similar helper/device/special VMAs
  - leave `PRIVATE_DATA` unset and keep these mappings outside ordinary confidential-private enforcement
- Unknown or ambiguous user VMA semantics:
  - first-cut default is `SPECIAL_EXCLUDED`, not a private class
  - the classifier must log these cases so the next stage can decide whether coverage should expand
  - do not silently "best effort" them into `PRIVATE_STRICT_ANON` or `PRIVATE_FILE_COW`

### Monitor Region Model

- Maintain minimal per-root region records, for example:
  - `valid`
  - `start_va`
  - `end_va`
  - `region_class`
  - optional coarse flags if they help debugging
- Key the region set by the already-existing root record identity:
  - `root_pfn`
  - `cid`
- Non-goals of the region table:
  - no per-page owner/refcount/COW metadata
  - no full Linux `vm_flags` mirror
  - no Linux VMA pointer storage in the monitor
  - no leaf presence accounting
- Missing region lookup for a user VA must not silently fall back to "private". Log it as an error or conservative miss and leave the leaf untagged rather than recreating the old blind behavior.
- The bitmap result is derived state:
  - region lookup decides whether a present leaf becomes private or not
  - the bitmap records that decision for the leaf
  - the bitmap alone is not the source of truth for why the decision was made
- What should be counted:
  - how many leaf decisions by touchpoint and region class turned `PRIVATE_DATA` on
  - how many left `PRIVATE_DATA` off
  - how many hit lookup miss / conservative exclude
- What should not be counted in this stage:
  - no full live residency census derived only from bitmap state
  - no per-PFN or per-VMA persistent accounting database
  - no per-access counters

### Registration Shape

- Preferred Linux-to-SBI shape is a replace-style full snapshot:
  - `REGION_SYNC_BEGIN(root_pgd_pa, cid, reason)`
  - repeated `REGION_SYNC_RANGE(start, end, class, flags)`
  - `REGION_SYNC_END(root_pgd_pa)`
- `reason` is for bounded logs/debug only, with values covering at least:
  - `invoke`
  - `exec`
  - `mmap`
  - `brk`
  - `mprotect`
  - `mremap`
  - `munmap`
  - `fork`
  - `exit_mmap`
- Full snapshot is preferred because these are slow MM events and correctness matters more than minimizing SBI calls in this stage.
- Disallowed registration shapes:
  - per-leaf region registration
  - passing Linux VMA pointers into OpenSBI
  - trying to mirror the whole Linux VMA tree in monitor-owned structures

### Work Slices

- Slice 1: Linux VMA classification and snapshot sync
  - add a single VMA classifier that maps current VMAs into the four packet classes
  - add one helper to emit a full snapshot for the current/provided mm under stable VMA locking
  - wire the helper to:
    - initial protected invoke preamble
    - exec attach preamble
    - fork-child attach preamble
    - successful `mmap`
    - successful `brk`
    - successful `mprotect`
    - successful `mremap`
    - successful `munmap`
    - `exit_mmap` phase-1 teardown

- Slice 2: OpenSBI region table and snapshot ecall handling
  - add the minimal per-root region storage and lookup helpers
  - associate region records with the existing root PFN / CID model
  - `exit_mmap` phase 1 should clear region records for that root, but must not retire `ROOT_L0`
  - `pgd_free()` remains the only final root-retire point

- Slice 3: Region-aware leaf enforcement
  - remove the current blind user-leaf tagging assumption from:
    - `sm_prepare_user_pt()`
    - `nacc_sync_private_tags()` / `nacc_tag_private_ptes()` call paths
  - replace it with region-aware leaf decisions at:
    - present-leaf reconcile during invoke / exec / fork-child attach preparation
    - secure `set_ptes` leaf install after extending the SBI path to carry starting VA
  - accepted first-cut leaf behavior:
    - `PRIVATE_STRICT_ANON`: set `PRIVATE_DATA` when the leaf becomes present
    - `PRIVATE_FILE_COW`: keep separate in logs/region table; leave `PRIVATE_DATA` unset unless Linux explicitly identifies the leaf install as post-COW anonymous-private
    - `SHARED_EXPLICIT`: do not set `PRIVATE_DATA`
    - `SPECIAL_EXCLUDED`: do not set `PRIVATE_DATA`
  - intent:
    - coder should explicitly materialize the region decision into bitmap state at these leaf touchpoints
    - coder should not try to preserve the full four-class reason in bitmap bits alone
  - bounded counters required in this slice:
    - key counters by `touchpoint`:
      - `present_leaf_reconcile`
      - `secure_leaf_install`
    - key counters by `region_class`:
      - `PRIVATE_STRICT_ANON`
      - `PRIVATE_FILE_COW`
      - `SHARED_EXPLICIT`
      - `SPECIAL_EXCLUDED`
      - `LOOKUP_MISS_OR_UNKNOWN`
    - key counters by `enforcement_action`:
      - `PRIVATE_DATA_SET`
      - `PRIVATE_DATA_LEFT_CLEAR`
    - a small aggregate matrix is preferred over verbose event logs

- Slice 4: Trap attribution
  - keep the existing bounded OpenSBI `PRIVATE_DATA` trap stats and top-`mepc` buckets
  - validation must symbolize those PCs against the built kernel image and collapse them into:
    - `anonymous fault`
    - `file fault`
    - `COW`
    - `syscall-buffer path`
    - `teardown / mapping update`
  - only if symbolization leaves the dominant contributors ambiguous may coder add one narrow extra path-hint mechanism; do not start with a broad per-access Linux ABI

### Recommended Implementation Order

1. Define the shared region-class enum / reason enum / replace-style sync ABI shape between Linux and OpenSBI.
2. Add the minimal monitor-side per-root region table plus `BEGIN/RANGE/END` handling and `exit_mmap` phase-1 clear behavior, without touching `ROOT_L0` lifecycle.
3. Add the Linux-side four-class VMA classifier and one full-mm snapshot emitter under stable VMA locking.
4. Wire the snapshot emitter to the required MM lifecycle events before changing leaf enforcement, so region records are already authoritative when enforcement lands.
5. Extend the secure leaf-install SBI path to carry starting VA, then make `sm_nacc_set_ptes()` region-aware.
6. Narrow `sm_prepare_user_pt()` / present-leaf reconcile so it follows registered region policy instead of the old blind leaf walk.
7. Reuse existing bounded trap stats first, symbolize them after the code path lands, and only add a narrow extra hint if one dominant bucket is still ambiguous.

### Event To Action Mapping

- Confidential container registration:
  - trigger: `nacc_register`
  - action: keep the current CID/PID registration path; no user-leaf policy is chosen yet

- Root `ROOT_L0` tagging:
  - trigger: `pgd_alloc()` for an mm already in the NaCC root lifecycle
  - action: keep the current `nacc_tag_root_sbi()` path unchanged
  - non-action: do not move first root tagging later into invoke / exec / attach

- Initial protected invoke / exec attach:
  - trigger: immediately before `SBI_EXT_NACC_INVOKE` / `SBI_EXT_NACC_REEXEC`
  - action:
    - sync a full region snapshot for the target mm
    - let OpenSBI confirm `ROOT_L0`
    - reconcile already-present user leaves against the registered region policy

- Secure leaf install:
  - trigger: `set_pte_at()` / `set_ptes()` on secure PTP pages when a user leaf becomes present
  - action:
    - pass starting VA into the SBI helper
    - OpenSBI looks up the region class for each leaf VA
    - apply the class-specific `PRIVATE_DATA` decision there

- `mmap` / `brk` / `mprotect` / `mremap` / `munmap`:
  - trigger: after successful VMA tree mutation while the VMA view is still stable
  - action:
    - resync the full region snapshot for the mm
    - if the event already creates or relocates present leaves that need immediate policy convergence, run a bounded present-leaf reconcile for the affected mm rather than restoring any blind global leaf walk

- Same-CID fork:
  - trigger: child mm exists and the child is about to use the current attach path
  - action:
    - keep early PID/CID registration unchanged
    - sync the child mm region snapshot before `SBI_EXT_NACC_ATTACH_FORKED_CHILD`
    - reconcile already-present child leaves against the child region table
  - rule: same-CID inherited private mappings remain allowed; do not add parent/child page-ownership metadata

- `exit_mmap` phase 1:
  - trigger: `exit_mmap(mm)`
  - action:
    - preserve the current two-phase teardown
    - clear monitor region records for that mm/root
    - keep `ROOT_L0` active until the later physical root free path
  - non-action: do not clear `ROOT_L0` at `exit_mmap` entry

- Final root free:
  - trigger: `pgd_free()`
  - action: keep the current `nacc_retire_root_sbi()` path as the phase-2 teardown point

### Execution Rules

- Region class is the only policy source for private/shared user-leaf handling in this stage.
- The bitmap is the frozen leaf-enforcement form of that policy, not an independent policy oracle.
- `PRIVATE_FILE_COW` must not become private from region class alone; it may become private only at an explicitly identified post-COW anonymous-private leaf install, otherwise it stays bitmap-off in this stage.
- Counters in this stage are for bounded decision attribution, not for reconstructing a full shadow state of all pages.
- Trap frequency, heat, or historical access count must not decide policy.
- Secure PTP protection remains out of bitmap scope and out of attribution scope for this packet.
- `ROOT_L0` lifecycle stays exactly where it is now:
  - early tag in `pgd_alloc()`
  - late retire in `pgd_free()`
- The monitor region table is allowed to be coarse and range-based; it is not allowed to grow into a Linux MM shadow.
- If a first-cut implementation needs better performance later, that is a later optimization task. Do not trade away semantic clarity now.

### Stop And Replan Triggers

- Correctness appears to require per-page owner/refcount/COW metadata or a monitor-owned full VMA shadow.
- Supporting the desired `PRIVATE_FILE_COW` post-COW-only rule would require a broad new ABI or metadata model rather than a narrow leaf-install signal.
- The required attribution buckets cannot be recovered from bounded `mepc` stats plus symbolization, and any fallback would require a broad new Linux-side per-access hint ABI.
- Preserving the packet would require moving or weakening early `ROOT_L0` tagging or late root retirement.
- The first viable implementation would need to reintroduce blind "tag every user leaf" behavior because region lookup cannot be made authoritative.

### Likely File Entry Points

- `linux/arch/riscv/include/asm/nacc.h`
- `linux/arch/riscv/include/asm/pgtable.h`
- `linux/arch/riscv/include/asm/sbi.h`
- `linux/arch/riscv/kernel/sys_riscv.c`
- `linux/mm/mmap.c`
- `linux/mm/mprotect.c`
- `linux/mm/mremap.c`
- `linux/mm/vma.c`
- `opensbi/include/sm/bitmap.h`
- `opensbi/include/sm/sm.h`
- `opensbi/lib/sbi/sbi_ecall_nacc.c`
- `opensbi/lib/sbi/sm/bitmap.c`
- `opensbi/lib/sbi/sm/sm.c`
- `opensbi/lib/sbi/sm/vm.c`
- `opensbi/lib/sbi/sbi_trap_ldst.c`

### Validation Order

- Build the touched components first:
  - `make linux-update`
  - `make opensbi`
  - `make qemu` only if QEMU is touched unexpectedly
- Reuse the existing private-bitmap kernel-read and kernel-write repros first so the usercopy / syscall-buffer bucket is grounded early.
- Then run split file/COW probes rather than only one broad smoke:
  - `docker run --security-opt seccomp=unconfined --rm busybox sh -c "cat /etc/hostname; echo done"`
  - `docker run --security-opt seccomp=unconfined --rm busybox sh -c "echo alpha | cat; echo done"`
  - `docker run --security-opt seccomp=unconfined --rm busybox sh -c "wc -c /etc/hostname; echo done"`
  - `docker run --security-opt seccomp=unconfined --rm busybox sh -c "echo alpha | wc -c; echo done"`
- Keep the existing shared-memory regression repro in the batch:
  - `docker run --security-opt seccomp=unconfined --rm -v /root/nacc_shm_repro:/nacc_shm_repro:ro busybox /nacc_shm_repro`
- Add one tiny targeted mapping-update repro if needed so `munmap` / teardown behavior is explicit rather than inferred only from full exit logs.
- Preserve the first symbolized trap-attribution summary in the packet or logs; do not leave the bucket result implicit in raw PCs alone.

### Acceptance Checklist For Coder / Reviewer

- Linux has one explicit four-class VMA classifier matching this packet.
- Unknown / ambiguous VMAs default to logged `SPECIAL_EXCLUDED` instead of silently becoming private.
- Linux registers region policy to OpenSBI for `exec`, `mmap`, `brk`, `mprotect`, `mremap`, `munmap`, `fork`, and `exit_mmap`.
- OpenSBI stores coarse per-root region records without becoming a shadow MM.
- Region policy is explicitly collapsed into bitmap state at present-leaf reconcile and secure leaf install points.
- `sm_prepare_user_pt()` no longer blindly tags all user leaves.
- `sm_nacc_set_ptes()` / `nacc_set_ptes_sbi()` carry enough VA/context to make region-aware leaf decisions.
- `SHARED_EXPLICIT` and `SPECIAL_EXCLUDED` leave `PRIVATE_DATA` unset.
- `PRIVATE_FILE_COW` does not set `PRIVATE_DATA` from region class alone; it only turns on there for an explicitly identified post-COW anonymous-private leaf install, or stays off in the conservative first cut.
- The implementation does not rely on the bitmap alone to reconstruct the original four-class VMA meaning.
- Validation artifacts include bounded leaf-decision counters for `touchpoint x region_class x enforcement_action`, plus lookup-miss / conservative-exclude totals.
- Early `ROOT_L0` tag and late root retire behavior remain intact.
- Validation artifacts can bucket dominant user-data traps into the required semantic categories without counting Secure PTP access traps.

### Decision Gate Closure

- This packet is closed as accepted on the clean detached T1 rerun evidence.
- The stage-1 route is now fixed as the conservative selective-private baseline:
  - `PRIVATE_STRICT_ANON` is the only observed class that turns on `PRIVATE_DATA`
  - `PRIVATE_FILE_COW` widening is not supported by current evidence and stays bitmap-off
  - `SHARED_EXPLICIT`, `SPECIAL_EXCLUDED`, and `LOOKUP_MISS_OR_UNKNOWN` remain conservative non-private outcomes in this stage
- The next optimization route must start from the measured copy-helper / syscall-buffer burden, not from reopening region-policy coverage.

### Parked Follow-On Seed

- Goal:
  - reduce the dominant copy-helper / syscall-buffer `PRIVATE_DATA` trap burden without changing the accepted VMA-guided selective-private baseline
- Critical Intent:
  - keep ordinary VMA/region policy, bitmap meaning, early `ROOT_L0`, and late root retirement fixed
  - optimize only the explicit data-exchange path that is now dominating traps
  - do not reinterpret hot private anon leaves as proof that broader private coverage was wrong
- Preferred Shape:
  - start with a narrow explicit shared-buffer or agent-managed transient window route aimed at syscall-buffer / usercopy-heavy traffic
  - add at most one bounded path hint if current `mepc` attribution is still too coarse to separate syscall-buffer traffic from teardown / mapping-update traffic confidently
  - preserve the existing four-class region taxonomy for ordinary VMAs
- Disallowed Shape:
  - do not widen `PRIVATE_FILE_COW`
  - do not relax `SPECIAL_EXCLUDED` or `LOOKUP_MISS_OR_UNKNOWN` into private coverage by default
  - do not auto-declassify hot private pages into shared buffers
  - do not grow the monitor into a Linux MM shadow or a per-page metadata database
- Allowed Freedom:
  - the follow-on may choose either an explicit shared-buffer ABI or an agent-managed transient window first
  - Linux/OpenSBI touchpoints may be chosen pragmatically if they preserve the frozen baseline semantics above
  - one narrow attribution hint is allowed only if needed to keep the optimization target semantically explicit
- Definition Of Done For The Follow-On:
  - the targeted copy-helper / syscall-buffer path is isolated behind an explicit mechanism
  - validation shows the targeted traffic no longer dominates generic private-anon `PRIVATE_DATA` traps in the same way
  - the accepted stage-1 region-policy behavior remains unchanged for ordinary VMAs
- Ready State:
  - parked only; do not hand directly to coder until the human confirms this follow-on route
