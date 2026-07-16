# PVT Slot-Pool Empty-Page Reclaim Follow-Up

Date: 2026-06-08
Related task: TASK_20260607_220435_dynamic_metadata

## Current Status

The current OpenSBI V1 metadata patch is functionally acceptable for the bounded T1 smoke target:
- CID/PID membership is no longer limited by the old fixed per-container array shape.
- `nacc_thread_ctx` is no longer limited by `NACC_THREAD_CTX_MAX`.
- Small metadata records no longer consume one full `pvt_mem` page each.

The current implementation achieves this by layering typed slot pools on top of the existing page-granularity `pvt_mem` allocator:
- page allocator interface: `opensbi/lib/sbi/sm/kalloc.c`
- typed slot-pool interface: `opensbi/include/sm/kalloc.h`
- current typed-pool users: `opensbi/lib/sbi/sm/cid.c`, `opensbi/lib/sbi/sm/thread_ctx.c`

## Current Problem

The current typed slot-pool design improves allocation granularity but does not reclaim fully empty slot pages back to the global `pvt_mem` freelist.

Observed current shape:
- each metadata type owns its own `pvt_slot_pool_t`
- when a pool runs out of free slots, it allocates one whole `pvt_mem` page
- that page is carved into fixed-size slots for exactly one record type
- on free, the slot is returned to the pool free-list
- fully empty pages remain owned by that typed pool and are not returned to the global `pvt_mem` allocator

This is acceptable for the current V1 closeout, but it creates follow-up risk:
- memory can become stranded in the wrong typed pool after a workload peak
- `pid_hash_entry` / `nacc_process` / `nacc_thread_ctx_entry` demand may vary over time
- a later workload may need more slots of one type while free pages remain trapped inside a different type's pool
- the current design therefore improves per-object efficiency but does not maximize cross-type memory reuse

## Why The Current Design Behaves This Way

The issue is not merely that the page header is too small. The deeper reason is that the current free-slot topology is pool-global rather than page-local.

Current allocator shape:
- pool metadata contains one pool-global `free_list`
- slot pages are tracked only as a linked list of allocated pages
- freed slots from different pages are mixed together in the same pool-global `free_list`

Consequence:
- when the last live slot in one page is freed, the allocator does not have enough local page-state to cheaply reclaim the page
- the page's other free slots may already be mixed into the pool-global `free_list`
- reclaiming that page would therefore require removing all of that page's free slots from the global free-list, which the current structure does not support cleanly

## Practical Impact

For the bounded workload-3 smoke run, this is not a blocker.

For future work, this matters most under:
- long-running workloads with bursty PID/TID churn
- repeated phase changes where one metadata type peaks and then another type peaks
- larger pressure targets such as the deferred 2000-TID Hackbench validation
- explicit `pvt_mem` pressure or exhaustion experiments

The most important pools to watch are:
- `nacc_process`
- `pid_hash_entry`
- `nacc_thread_ctx_entry`

`nacc_container` is less likely to dominate memory usage because container count is expected to stay much smaller than PID/TID count.

## Recommended Follow-Up Direction

Do not revert to the old direct `pvt_mem_alloc()`-per-object shape. That model reclaimed pages immediately, but only because each tiny object wasted one full page.

Instead, evolve the current typed pool into a small reclaim-capable mini-slab design.

Recommended minimum design changes:
- extend each slot-page header with:
  - live-object count
  - page-local free-slot list
  - page-local slot count or equivalent invariant
- change allocation to prefer a page from a pool-maintained partial-page list
- change free to:
  - recover the owning page from the freed slot pointer
  - return the slot to that page's local free list
  - decrement the page live-object count
  - if live-object count reaches zero, detach the page from the pool and return it to `pvt_mem_free()`

This keeps the current typed-pool idea while restoring whole-page reuse across metadata types.

## Recommended Scope For The Next Task

Goal:
- add reclaim of fully empty typed slot-pool pages back to the global `pvt_mem` allocator

Stay in scope:
- `opensbi/include/sm/kalloc.h`
- `opensbi/lib/sbi/sm/kalloc.c`
- minimal caller adjustments only if the pool API needs small local changes

Stay out of scope:
- no broad allocator rewrite
- no generic Linux-style slab subsystem
- no ROOT_L0/root-record dynamicization
- no Linux registration failure propagation changes
- no Agent-owned metadata redesign
- no 2000-TID validation in the same packet unless the human explicitly couples them

## Suggested Validation For The Follow-Up

Minimum:
- rebuild OpenSBI
- rerun the existing workload-3 smoke target to ensure allocator semantics did not regress

If the human wants pressure evidence:
- add a targeted allocator-pressure experiment or a larger PID/TID churn workload
- specifically observe whether fully freed pages become reusable across different typed pools through the shared `pvt_mem` allocator

## Closeout

The current slot-pool implementation is a good V1 compromise:
- it fixes the page-per-small-object waste
- it keeps code size and allocator complexity under control

It should not be treated as the final allocator shape if larger PID/TID pressure testing is planned. The next allocator-focused packet should target reclaim of fully empty typed-pool pages.
