# Linux-Friendly Fork Plan

## Problem Statement

- Earlier NaCC fork prototypes worked around secure page-table visibility by skipping parts of the standard Linux fork path and relying on OpenSBI to copy the child user page-table tree.
- That prototype path helped overcome the initial secure-PTP visibility barrier, but it steadily exposed Linux semantic gaps:
  - missing `pgtables_bytes` closure for child page-table pages
  - missing child leaf-accounting equivalents for `rss`, `rmap`, and `refcount`
- If fork keeps depending on "raw page-table copy + scattered patch-up logic", Ubuntu-class workloads will amplify the semantic debt and debugging burden.

## Current Understanding

- Existing evidence shows that the 8 child `ptp_list` page-table pages can now be registered correctly; `ptdesc->ptl` initialization is no longer the primary fault.
- The stronger current problem is that metadata and accounting normally established by `copy_page_range()` have not been restored equivalently in the prototype path.
- `non-zero pgtables_bytes on freeing mm: -32768` strongly suggests missing accounting for eight 4 KiB PTP pages.
- `Bad rss-counter state` followed by `Bad page map / state` strongly suggests missing Linux accounting for child leaf mappings.
- Multi-process shared memory is part of the paper motivation, so `mmap`, `MAP_SHARED`, and shared-memory semantics are required parts of the long-term path.
- Ubuntu-class workloads will magnify any remaining gaps in fork / exec / `mmap` / shared-library / teardown behavior.

## Constraints

- The long-term model should become more Linux-friendly, not more dependent on prototype-only bypass logic.
- Correctness should not depend on large amounts of runtime traps; traps should remain only for unavoidable secure ownership, page fault, and monitor cooperation boundaries.
- Linux should stay on native fork read, walk, and accounting paths whenever possible, rather than replaying a parallel fork semantic layer afterward.
- OpenSBI should converge toward "write secure page-table pages on Linux's behalf", not "own the whole fork semantic stack".
- Near-term focus remains fork; do not widen scope simultaneously to reexec or init-to-exit cleanup.
- There is already a local project precedent for this division of labor: Linux can read secure page-table-related information and use OpenSBI only for the actual secure write.

## Candidate Paths

### Path A: Keep the prototype bypass and patch only the current accounting holes

Pros:

- smallest short-term patch
- fastest route for the current fork+exec case

Cons:

- every new workload may expose another missing semantic
- fork risks turning into a heavily specialized branch implementation
- poor fit for Ubuntu-scale goals

### Path B: Return completely to standard Linux fork with minimal OpenSBI involvement

Pros:

- closest to upstream semantics

Cons:

- conflicts with secure page-table ownership and visibility boundaries
- likely unrealistic under the current NaCC structure

### Path C: Linux-native fork path plus OpenSBI secure-write assistance

- Keep Linux as close as possible to the standard fork path, especially `copy_page_range()` and its accounting / COW / rmap semantics.
- When Linux must modify secure page-table pages, let OpenSBI perform or assist the write.
- The target is not post-fork semantic replay. The target is to keep the native Linux fork path alive.

## Chosen Path

- Path C is the accepted long-term direction.
- External description: **Linux-friendly fork**

Definition:

- Linux should stay on the standard fork read, walk, accounting, and invariant-establishment paths whenever possible.
- OpenSBI should provide secure-write assistance only where Linux truly needs to modify secure page-table pages.
- The long-term goal is not semantic replay. The goal is that the native Linux path should not be permanently displaced by prototype-only bypass logic.
- Runtime traps should not become the primary source of correctness.

## Rejected Alternatives

- Reject "raw copy + scattered patch-up" as the long-term model:
  - it is short-term convenient but turns every workload into another semantic hole-patching exercise
- Reject "solve fork mainly with many runtime traps":
  - it spreads correctness across many runtime paths and degrades performance, complexity, and debuggability
- Reject "completely remove OpenSBI from the fork story":
  - current secure page-table ownership makes that unrealistic

## Staged Plan

### Stage 0: Converge the current fork-accounting root cause

Goal:

- identify exactly what is missing for child page-table-page accounting and leaf-page accounting

Outputs:

- focused observability logs
- a repair boundary list

Exit criteria:

- answer clearly:
  - whether `ptp_list` registration is missing `mm_inc_nr_ptes/mm_inc_nr_pmds`
  - whether child leaf mappings are missing `rss` / `rmap` / `refcount`
  - which fork substeps can return directly to Linux-native logic and which still need OpenSBI write assistance

### Stage 1: Restore page-table-page accounting

Goal:

- close the Linux-side accounting loop for child PTP pages

Focus:

- `pgtables_bytes`
- `mm_inc_nr_ptes`
- `mm_inc_nr_pmds`

Exit criteria:

- no remaining `pgtables_bytes` residue that matches the child PTP page count

### Stage 2: Restore child leaf fork accounting

Goal:

- restore the minimum Linux accounting semantics for child leaf mappings

Priority items:

- `rss`
- `rmap`
- `folio/page refcount`
- validate COW write-protection behavior where required

Design rule:

- prefer to let Linux continue through the standard `copy_page_range()`-side logic
- if a step is blocked only by secure page-table writes, replace that write point with OpenSBI assistance instead of bypassing the whole semantic step
- avoid runtime trap-heavy accounting repair

### Stage 2.5: Restore shared-memory / `mmap` semantics needed for containers

Goal:

- validate and converge shared-memory, `MAP_SHARED`, and file-backed `mmap` semantics in container scenarios

Why it is a separate stage:

- this is not an optional feature
- it is part of the project motivation
- real container workloads will expose these gaps early

Pass criteria:

- shared writes are visible across parent/child or peer processes
- teardown does not corrupt accounting or page state

### Stage 3: Converge to a stable Linux-native fork + OpenSBI write-assist model

Goal:

- turn the current prototype branch behavior into a maintainable long-term model

Form:

- Linux: keep the native fork mainline alive
- OpenSBI: assist only at secure page-table write points

Exit criteria:

- fork+exec no longer depends on a fragile demo-only happy path
- planner can shift fork from "prototype bring-up" to "semantic stabilization"

### Stage 4: Expand to reexec / init-to-exit / Ubuntu-class workloads

Goal:

- audit other lifecycle paths only after the fork mainline becomes stable

Note:

- Ubuntu is not a near-term target
- Ubuntu is a later validation workload

### Stage 5: Security hardening

Goal:

- add explicitly security-oriented hardening after base semantics and container workloads are stable

Known item:

- `bitmap` protection

Ordering requirement:

- do not pull this ahead of fork / `mmap` / shared-memory semantic stabilization

## Minimal Semantic Set To Restore

- page-table-page level:
  - child PTP metadata
  - `pgtables_bytes`
- leaf-page level:
  - `rss`
  - `rmap`
  - `refcount`
- shared / COW level:
  - confirm that current NaCC behavior matches the prototype goal
  - extend further only when targeting Ubuntu-scale workloads
- container shared-memory level:
  - `MAP_SHARED`
  - file-backed `mmap`
  - anonymous shared mappings
  - multi-process shared memory

## Native-Path Principle

- The first question is not "which semantics should be replayed later?"
- The first question is "why did the Linux-native fork step stop progressing here?"
- If Linux can already read the secure page-table-related information, preserve that read path and preserve upstream-like semantics.
- Introduce OpenSBI only when Linux truly must modify secure page-table pages and cannot do that directly in S-mode.
- Default requirement for coder:
  - first ask whether more of `copy_page_range()` / `copy_pte_range()` / related accounting can be restored directly
  - then replace only the secure write points
  - do not default to a parallel "fix accounting after fork" mechanism

## Immediate Next Actions

- Keep current P0/P1 work focused on fork accounting observability and minimal repairs.
- Do not widen coder scope to Ubuntu, reexec, or init-to-exit yet.
- After Stage 1/2 observability, planner should choose how much of the Linux-native fork path can be restored:
  - A. restore more `copy_page_range()` subpaths directly
  - B. preserve Linux walk/accounting but delegate secure writes to OpenSBI
  - C. keep a temporary bypass only at the very few points that still cannot be restored

## Notes For Other Agents

- coder:
  - the target is not "maintain the prototype bypass" and not "build a replay layer"
  - the target is to converge fork back toward the Linux-native path
  - think first about how Linux can continue through `copy_page_range()` semantics and only outsource secure writes to OpenSBI
  - do not build the fix around lots of new traps
- log analyzer:
  - keep using the first fork-accounting anomaly as the main anchor; do not return to the old `ptdesc->ptl` issue as the primary root cause
- planner:
  - compare future fork options mainly by asking:
    - does this move closer to the Linux-native fork path?
    - does this depend on OpenSBI only at necessary secure write points?
