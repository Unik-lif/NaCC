# 2026-05-18 NaCC PTE-first SUM-off Regression Readout

## Context

This note records the SUM-bit trap-count concern raised after committing the
current PTE-first Linux/OpenSBI state.

Related committed sub-repo baselines:

- Linux: `c308506ae9a7 nacc: switch private leaf identity to PTE_NACC`
- OpenSBI: `1f17e72 nacc: mediate secure PTE updates with PTE_NACC`

Primary comparison artifacts:

- Pre-PTE-first refcount/lifecycle readout:
  `record/20260514_nacc_refcount_t1_sum_trap_readout.md`
- PTE-first identity task:
  `docs/workflow/tasks/completed/TASK_20260515_104414_nacc_consistency.md`
- VM bookkeeping / resolver follow-up:
  `docs/workflow/tasks/completed/TASK_20260516_160823_nacc_pte_bitmap_convergence.md`
- Current T3 launcher:
  `logs/TASK_20260516_160823_nacc_pte_bitmap_convergence_t3_batch_20260516_171302.launcher.log`

The important distinction is that the 2026-05-14 prototype had already moved
new NaCC private leaves toward a detached lifecycle using `pte_special`-style
Linux handling, while the 2026-05-15/16 route moved identity and authority to
`PTE_NACC` / OpenSBI-mediated PTE updates.

## Baseline: 2026-05-14 Refcount/Lifecycle Prototype

The 2026-05-14 T1 run was not perfect, but it had substantially narrowed the
SUM-off private-data trap surface. Workloads 1 and 2 had no SUM-off traps, and
workloads 3 through 8 had smaller, load-only SUM-off counts concentrated in
`__pi___memcpy`.

| Workload | Shape | Private total | SUM-on | SUM-off | SUM-off load | SUM-off store |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | `printf alpha >/dev/null` | 1,318 | 1,318 | 0 | 0 | 0 |
| 2 | `read </etc/hostname` | 1,907 | 1,907 | 0 | 0 | 0 |
| 3 | fork/COW shell repro | 7,075 | 1,955 | 5,120 | 5,120 | 0 |
| 4 | `cat /etc/hostname` | 7,052 | 2,956 | 4,096 | 4,096 | 0 |
| 5 | `echo alpha | cat` | 12,356 | 3,652 | 8,704 | 8,704 | 0 |
| 6 | `wc -c /etc/hostname` | 7,147 | 3,051 | 4,096 | 4,096 | 0 |
| 7 | `echo alpha | wc -c` | 12,893 | 3,677 | 9,216 | 9,216 | 0 |
| 8 | shared-memory repro | 2,566 | 518 | 2,048 | 2,048 | 0 |

## Current PTE-first T3 Result: 2026-05-16

The 2026-05-16 T3 run passed functionally, but the SUM-off census changed
shape dramatically. The final `private-sum-census-total` and
`private-sumoff-profile-total` snapshots show large SUM-off counts in every
workload, including workloads 1 and 2.

| Workload | Shape | Private total | SUM-on | SUM-off | SUM-off load | SUM-off store |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | `printf alpha >/dev/null` | 20,408 | 1,864 | 18,544 | 7,564 | 10,980 |
| 2 | `read </etc/hostname` | 20,781 | 2,321 | 18,460 | 6,196 | 12,264 |
| 3 | fork/COW shell repro | 44,790 | 2,550 | 42,240 | 15,720 | 26,520 |
| 4 | `cat /etc/hostname` | 50,245 | 4,109 | 46,136 | 18,639 | 27,497 |
| 5 | `echo alpha | cat` | 73,204 | 5,024 | 68,180 | 29,327 | 38,853 |
| 6 | `wc -c /etc/hostname` | 59,074 | 4,427 | 54,647 | 20,971 | 33,676 |
| 7 | `echo alpha | wc -c` | 76,093 | 4,874 | 71,219 | 29,667 | 41,552 |
| 8 | shared-memory repro | 4,609 | 1,021 | 3,588 | 3,584 | 4 |

## Direct Comparison

| Workload | 2026-05-14 SUM-off | 2026-05-16 SUM-off | Delta |
| --- | ---: | ---: | ---: |
| 1 | 0 | 18,544 | +18,544 |
| 2 | 0 | 18,460 | +18,460 |
| 3 | 5,120 | 42,240 | +37,120 |
| 4 | 4,096 | 46,136 | +42,040 |
| 5 | 8,704 | 68,180 | +59,476 |
| 6 | 4,096 | 54,647 | +50,551 |
| 7 | 9,216 | 71,219 | +62,003 |
| 8 | 2,048 | 3,588 | +1,540 |

This is too large to treat as routine noise. It is a material regression in
the observed SUM-off private-data access surface.

## Interpretation

The PTE-first direction is still the right authority cleanup:

- `PTE_NACC` should be the private-leaf identity visible in PTE state.
- `VM_NACC_APP` should be Linux-side app VMA bookkeeping.
- OpenSBI should remain the authority for `PTE_NACC`, private bitmap, and
  trusted private PFN refcount transitions.

However, the implementation appears to have lost an important property from
the 2026-05-14 prototype: NaCC private user leaves should not be handed back to
the broad ordinary Linux anonymous-page lifecycle.

The suspicious code-shape change is that Linux now identifies private leaves
with `pte_nacc()`, but the new anonymous fault path still largely follows the
ordinary path:

```text
do_anonymous_page()
  -> alloc_anon_folio()
  -> add_mm_counter()
  -> folio_add_new_anon_rmap()
  -> folio_add_lru_vma()
  -> set_ptes()
  -> OpenSBI adds PTE_NACC / bitmap refs
```

That makes the security authority cleaner, but it does not preserve the
detached lifecycle behavior that had reduced SUM-off trap exposure. The current
result is consistent with NaCC private leaves again being touched by ordinary
Linux copy/clear/COW/file/pipe paths through kernel-high mappings.

The most concerning change is not just higher counts. The 2026-05-14 residual
SUM-off accesses were load-only, while the 2026-05-16 run has many SUM-off
stores in workloads 1 through 7.

## Evidence Boundary

Observed:

- The 2026-05-14 readout reports low or zero SUM-off counts after the refcount
  lifecycle prototype.
- The 2026-05-16 T3 logs report much higher SUM-off counts after the PTE-first
  identity and VM bookkeeping changes.
- Both batches completed their workload 1-8 runs successfully.

Inference:

- The PTE-first implementation likely regressed the detached private-leaf
  lifecycle boundary.
- The current implementation should not be accepted as preserving the
  lifecycle narrowing achieved by the 2026-05-14 prototype.

Not proven by this note:

- The exact call sites for every new SUM-off store.
- Whether every new trap is caused by ordinary anonymous-page lifecycle paths.
- A complete fix design.

## Next Repair Direction

The next repair should not roll back the PTE-first authority model. Instead it
should restore the lifecycle boundary underneath that model.

Design target:

```text
PTE_NACC is the authoritative private-leaf identity.
VM_NACC_APP is non-authoritative Linux app bookkeeping.
OpenSBI owns tag/bitmap/refcount transitions.
Linux must not treat NaCC private leaves as broad ordinary anonymous leaves.
```

Concrete questions for the next code slice:

- Should Linux still use a `pte_special`-like or detached-MM mechanism as a
  compatibility/lifecycle hint, while no longer treating `pte_special` as the
  security identity?
- Should `do_anonymous_page()` and COW replacement have a NaCC-private install
  path that avoids re-entering broad anon LRU/rmap/copy/clear behavior?
- Which 2026-05-16 SUM-off store PCs dominate the regression?
- Can the validation gate require the 2026-05-14 SUM-off shape as a baseline:
  workload 1/2 near zero, workload 3-8 not exploding to tens of thousands, and
  no broad SUM-off store surface?

Suggested acceptance gate for the follow-up:

- Workloads 1-8 still pass.
- `PTE_NACC` / private bitmap/refcount authority remains in OpenSBI.
- `VM_NACC_APP` remains the explicit app VMA marker.
- SUM-off counts are compared against the 2026-05-14 readout, not merely
  checked for nonzero success.
- Any remaining SUM-off stores are explained by exact PCs and paths.
