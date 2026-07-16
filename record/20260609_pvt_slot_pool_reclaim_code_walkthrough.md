# PVT Slot-Pool Reclaim Code Walkthrough

Date: 2026-06-09
Related task: TASK_20260608_110148_free_formalize
Related code:
- `opensbi/include/sm/kalloc.h`
- `opensbi/lib/sbi/sm/kalloc.c`
- `opensbi/lib/sbi/sm/sm.c`

## Purpose

This note captures the code-level explanation behind the current OpenSBI typed slot-pool reclaim patch so the reasoning does not stay only in the ask-window discussion.

## What Changed In `kalloc.h`

The slot-pool structure changed from a pool-global free-slot model to a page-aware model.

Old mental model:
- one typed pool owns a list of pages
- freed slots are mixed in one pool-global `free_list`

New mental model:
- one typed pool still owns a list of pages
- each page owns its own slot `free_list`
- the pool tracks a `partial_pages` list containing only pages that still have at least one free slot

Practical meaning:
- allocation no longer pops from one pool-global free-slot chain
- allocation now chooses a page from `partial_pages` and then pops one slot from that page

## What Changed In `kalloc.c`

### 1. Each slot page now carries its own allocator state

`struct pvt_slot_pool_page` now stores:
- `next`: all pages owned by the typed pool
- `next_partial`: pages that still have free slots
- `free_list`: free slots inside this page
- `live_count`: number of live objects still allocated from this page

This is the key enabler for reclaim. Without page-local state, the allocator cannot cheaply decide when one page has become completely empty.

### 2. Slot layout is prepared once per pool

`pvt_slot_pool_prepare_nolock()` computes:
- `aligned_slot_size`
- `slots_per_page`

This keeps the page layout stable:
- page header at the front
- fixed-size slot area after the header

The slot size is forced to be at least pointer-sized because a free slot temporarily stores the next free-slot pointer.

### 3. Partial-page helpers were added

The new helpers:
- `pvt_slot_pool_add_partial_nolock()`
- `pvt_slot_pool_remove_partial_nolock()`

These maintain the pool's "pages that can still satisfy allocation" list.

State intuition:
- a newly grown page starts as partial
- a fully consumed page leaves `partial_pages`
- a formerly full page re-enters `partial_pages` after one slot is freed

### 4. Free-time validation is now page-aware

`pvt_slot_pool_valid_slot_nolock()` checks that:
- the rounded-down page actually belongs to the provided pool
- the pointer is inside the slot region rather than the page header
- the offset matches slot alignment
- the computed slot index is within the page's slot capacity

This is the main guard against wrong-pool frees and obviously invalid slot pointers under the allocator contract.

### 5. Grow now builds a page-local free list

`pvt_slot_pool_grow_nolock()` still allocates one `pvt_mem` page, but instead of feeding slots into one pool-global list, it:
- initializes one page header
- carves the page into fixed-size slots
- links those slots into `page->free_list`
- adds the page to `partial_pages`

This is the moment where one raw `pvt_mem` page becomes a typed mini-slab page.

### 6. Allocation now consumes one slot from one partial page

`pvt_mem_slot_alloc()` now does the following:
- prepare pool geometry if needed
- skip stale head entries in `partial_pages` that no longer have free slots
- grow a new page if no partial page exists
- pop one slot from the chosen page's `free_list`
- increment that page's `live_count`
- remove the page from `partial_pages` if the allocation made it full

This is the main topology change: allocation is now page-first, slot-second.

### 7. Free now chooses between slot return and whole-page reclaim

`pvt_mem_slot_free()` is the real reclaim path.

It now:
- rounds the slot pointer down to find the owning page
- validates the slot against pool ownership and slot geometry
- decrements the page's `live_count`

Then it branches:

If `live_count > 0`:
- clear the slot
- push it back to that page's `free_list`
- if the page had been full, add it back to `partial_pages`

If `live_count == 0`:
- detach the page from the pool's `pages` list
- remove it from `partial_pages` if present
- release the pool lock
- return the whole page to global `pvt_mem`

This preserves the intended invariant:
- live pages remain single-type
- only fully empty pages become globally reusable

### 8. Locking detail worth remembering

The page is returned to `pvt_mem_free()` only after the typed pool lock is released.

That matters because reclaim is split into two phases:
- detach from the typed pool while holding the typed pool lock
- return to the global page allocator after unlocking

This keeps allocator ownership transitions explicit and avoids a more tangled lock path.

## What Changed In `sm.c`

The `sm.c` change is small but worth grouping with this OpenSBI state:
- two informational `sbi_printf()` calls were downgraded to `nacc_debug()`

Current locations:
- ready-agent first-full-init completion message
- ready-agent lightweight attach message

Why this matters:
- these are high-frequency informational traces rather than user-facing hard errors
- keeping them at debug level reduces console noise during stress runs
- this change is conceptually separate from slot-pool reclaim correctness, but it still belongs to the same current OpenSBI debugging/observability pass

## Validation Boundary To Remember

The current evidence supports:
- OpenSBI build sanity
- workload-3 baseline success
- no observed baseline regression from the reclaim patch

The current evidence does not directly prove:
- cross-type reuse of a reclaimed typed slot page under pressure
- the final behavior of the reopened Hackbench thread-mode validation

## Commit Grouping Recommendation

If we commit this work, the clean split is:

Option A:
- one OpenSBI code commit for `include/sm/kalloc.h`, `lib/sbi/sm/kalloc.c`, and `lib/sbi/sm/sm.c`
- one root-repo documentation commit for this `record/` note and any task-packet/report updates

Why this split is cleaner:
- `opensbi/` is a nested repository with its own history
- `record/` belongs to the outer NaCC repository
- mixing them conceptually is fine, but version-control boundaries are still separate

## Short Summary

The reclaim patch did not introduce a general-purpose slab allocator. It added the minimum page-local bookkeeping needed so a typed slot pool can:
- allocate from partially used pages
- detect when one page becomes fully empty
- detach that page from the typed pool
- return the empty page to global `pvt_mem`

That is the smallest change set that restores cross-type whole-page reuse without allowing mixed-type live pages.
