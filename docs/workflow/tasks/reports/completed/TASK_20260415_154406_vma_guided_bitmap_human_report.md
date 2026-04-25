# Human Progress Report

- Task ID: TASK_20260415_154406_vma_guided_bitmap
- Task Packet: `docs/workflow/tasks/active/TASK_20260415_154406_vma_guided_bitmap.md`
- Created: 2026-04-18 19:46:55 +0800
- Purpose: cumulative human-readable updates appended by coder, reviewer, and log_analyzer
- Append Rule: add a new timestamped section for each new turn; do not rewrite older entries
- Reading Hint: newest updates are appended at the end of this file

## 2026-04-18 20:05:00 +0800 - coder

- Note: backfilled from the existing task packet after the separate human report workflow was introduced.
- What changed:
  - landed the VMA-guided selective-private baseline instead of the old all-protected-leaf behavior
  - added coarse region registration plus region-aware leaf reconcile / install handling
  - kept `PRIVATE_FILE_COW` conservative and bitmap-off unless a future packet proves a narrower post-COW signal
  - later fixed the monitor-side region-record path with a bounded pool and a narrow publication/serialization repair instead of broadening policy
- Key files:
  - `opensbi/lib/sbi/sm/region.c`
  - `opensbi/lib/sbi/sm/vm.c`
  - `opensbi/lib/sbi/sm/sm.c`
  - Linux-side VMA classification and region-sync touchpoints used by the packet
- Why this was needed:
  - move policy ownership to VMA / region semantics while keeping the bitmap as the frozen leaf-enforcement result
  - remove the blind "tag every user leaf" route without introducing per-page heuristics or a monitor-owned MM shadow
- Minimal validation in coder turns:
  - compile-focused sanity only
  - packet-owned detached runtime reruns were intentionally left to reviewer / test_runner
- Remaining watchpoints from coder perspective:
  - repeated `SPECIAL_EXCLUDED` / lookup-miss cases stayed conservative by design
  - any next-stage work should be a new bounded packet, not an opportunistic widening of this baseline

## 2026-04-18 20:06:00 +0800 - reviewer

- Note: backfilled from the existing task packet after the separate human report workflow was introduced.
- Review verdict:
  - the route was ultimately accepted for the packet-owned rerun after the narrow allocator/bootstrap fix
- What was checked directly:
  - the implementation stayed inside the packet's region-based control model
  - early `ROOT_L0` and late retirement semantics were preserved
  - the later OpenSBI fix repaired record-pool publication/serialization without widening ABI or policy
- Plain-English code explanation:
  - the final review-stage fix was not a redesign of region policy
  - it made the monitor's internal region-record pool safe to initialize and publish, while keeping the same snapshot-style `BEGIN/RANGE/END` behavior
- Main watchpoints that remained after review:
  - monitor-side static footprint stayed large enough to watch
  - debug-only root-dump allocation was still something to preserve if failures reappeared
- What the human should know next:
  - by the end of review, the packet was considered ready for the detached rerun
  - the interesting question had shifted from "is the code shape faithful?" to "what does the rerun evidence imply about the next design step?"

## 2026-04-18 20:07:00 +0800 - log_analyzer

- Note: backfilled from the existing task packet after the separate human report workflow was introduced.
- Run verdict:
  - the clean detached T1 rerun was acceptable
- Dominant signal:
  - the remaining cost signal is copy-helper / usercopy-heavy traffic on already-private anonymous leaves
  - it is not evidence that `PRIVATE_FILE_COW` should be widened or that file/COW-specific private expansion is the main issue
- Key evidence:
  - all eight rerun probes completed with the expected VM-side markers
  - the old `region: alloc failed` / `region sync range failed` signature disappeared
  - final counters stayed conservative: only `PRIVATE_STRICT_ANON` set `PRIVATE_DATA`, while `PRIVATE_FILE_COW`, `SHARED_EXPLICIT`, and `SPECIAL_EXCLUDED` remained off
- What this means for the next decision:
  - this packet is good enough to close as the conservative selective-private baseline
  - if work continues, the more promising next semantic route is an explicit shared-buffer / agent-managed window idea for the copy-heavy paths, not broader private coverage
- What remains uncertain:
  - the rerun evidence is strong on dominant copy-helper attribution
  - it is only medium-confidence on a finer split between syscall-buffer traffic and teardown / mapping-update traffic without one narrower extra hint
