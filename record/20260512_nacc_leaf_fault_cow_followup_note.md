# NaCC Leaf Data Follow-up: Post-Attach Fault and COW

Date: 2026-05-12

This note records deferred understanding from the discussion around
`TASK_20260512_230124_nacc_leaf_data_page_new_way_fix`. It is not the immediate
repair route.

## Current State

The previous implementation protects the initial post-layout user leaf set by:

- letting Linux build the NaCC process address space normally during exec/fork;
- converting current present NaCC user leaf PTEs to `pte_special()`;
- setting walked VMAs `VM_MIXEDMAP`;
- then letting OpenSBI sync private bitmap tags over user VPN2 slots `0..255`.

That staged attach path is functionally useful, but it only covers leaves that
exist at attach time.

## Deferred Gap

After attach, Linux can create or replace user leaf mappings through normal
fault machinery. The important cases include:

- demand faults that allocate new anonymous or file-backed user pages;
- write-protect/COW faults through `do_wp_page()` / `wp_page_copy()`;
- mmap-driven population or later page table updates;
- other mm paths such as mprotect, mremap, fork/copy_page_range, munmap, and
  exit/zap interactions.

Because eager private tagging was removed from the OpenSBI `SET_PTES` /
`UPDATE_PTE` path, a newly faulted leaf after attach may be installed as an
ordinary Linux page and may not automatically enter the private bitmap. COW is a
priority subcase because Linux may allocate a new anonymous page and install a
fresh normal PTE after a write fault.

## Boundary From Immediate Repair

The immediate next repair should focus on teardown/lifecycle cleanup for the
already detached special private leaves. It should not try to solve the full
post-attach fault/COW policy unless the task is explicitly expanded.

For a later task, the design question is: when a NaCC-active mm creates or
replaces a user leaf in VPN2 `0..255`, how should Linux and OpenSBI coordinate
so that:

- the new leaf enters private bitmap protection;
- any old leaf being replaced has correct Linux accounting/rmap/refcount cleanup;
- COW does not silently recreate an ordinary unprotected anonymous page;
- the solution avoids VMA semantic filtering and preserves full user-leaf
  coverage in VPN2 `0..255`.

## Open Design Point

The later route should decide whether post-attach leaf transitions are handled
near generic fault/PTE installation points, through NaCC-specific wrappers, by a
post-fault sync/tag pass, or by another explicit lifecycle state transition. The
choice must keep Linux-owned accounting separate from Monitor-owned private
bitmap/root/PTP metadata.
