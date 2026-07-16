# NaCC PTE-First Lifecycle Notes

Date: 2026-05-17

Related task:
- `docs/workflow/tasks/completed/TASK_20260516_160823_nacc_pte_bitmap_convergence.md`
- Prior PTE-first task: `docs/workflow/tasks/completed/TASK_20260515_104414_nacc_consistency.md`

Purpose: capture the practical mental model for the current PTE-first private
leaf route, especially the three lifecycle cases that are hard to reconstruct
from scattered Linux/OpenSBI call sites.

## Core Model

Linux does not directly write secure PTP PTEs. Linux builds a requested PTE
using normal MM logic, then the RISC-V PTE helpers route the write through
OpenSBI when the target PTE page is a NaCC secure PTP.

OpenSBI is the authority for:
- deciding whether the requested PTE is a NaCC private-data candidate;
- setting or clearing `PTE_NACC`;
- acquiring or retiring the private PFN bitmap/refcount;
- writing the final prepared PTE into the secure PTP.

Linux is still responsible for:
- VMA bookkeeping, now via `VM_NACC_APP`;
- page allocation and normal MM accounting;
- rmap/folio/COW mechanics;
- observing `PTE_NACC` when it needs to treat a NaCC private leaf as a normal
  refcounted Linux page for fork/COW/zap accounting.

The central OpenSBI state transition is:

```text
nacc_prepare_secure_pte_update(old_pte, requested_pte, &prepared_pte)
```

Think of it as:

```text
old committed PTE + Linux requested PTE
  -> OpenSBI prepared PTE
  -> bitmap/refcount delta
```

Important behavior:
- Linux/requested `PTE_NACC` is stripped first.
- OpenSBI re-adds `PTE_NACC` only if the requested PTE is a private-data
  candidate.
- Old `PTE_NACC` says this PTE slot already contributed a private PFN ref.
- Same-PFN permission changes keep the refcount unchanged.
- PFN replacement retires the old PFN and acquires the new PFN.

## Case 1: Existing Address Space Sync

This is the attach/exec-style path after Linux has already built a user address
space. OpenSBI must synchronize existing resident private leaves with
`PTE_NACC` and the private bitmap.

Main OpenSBI walk:
- `opensbi/lib/sbi/sm/vm.c::__nacc_sync_private_leaf_tags()`
- Called through `nacc_sync_private_tags()`.

Range:
- Top-level Sv39 level 2 scans only 256 entries.
- Each VPN2 slot covers 1GB.
- The scanned window is therefore `[0, 256GB)`.
- This matches Linux `NACC_USER_VPN2_PROTECTED_END`:
  `256 * (1UL << 30)`.

Loop behavior:
- If `PTE_V` is clear, it still calls `nacc_apply_private_leaf_tag()`.
  This is intentional because Linux RISC-V PROT_NONE resident PTEs clear
  hardware `PTE_V` while keeping a PFN payload and setting `_PAGE_PROT_NONE`.
- If PTE is valid but non-leaf, it recurses to the next page-table level.
- If PTE is valid leaf, it calls `nacc_apply_private_leaf_tag()`.

Actual tagging happens below the walk:

```text
__nacc_sync_private_leaf_tags()
  -> nacc_apply_private_leaf_tag()
      -> nacc_pte_private_data_candidate()
      -> nacc_prepare_secure_pte_update()
          -> nacc_bitmap_acquire_private_data()
          -> nacc_secure_pte_mark()
      -> *ptep = prepared
```

`nacc_pte_private_data_candidate()` allows resident user private data leaves
and PROT_NONE resident leaves. It rejects empty/non-resident entries, valid
supervisor leaves, and PTEs pointing into the secure PTP physical range.

Why `PTE_G` appears:
- Local RISC-V Linux defines `_PAGE_PROT_NONE` as `_PAGE_GLOBAL`.
- OpenSBI names the same bit `PTE_PROT_NONE PTE_G`.
- In the `PTE_V == 0` case, this bit means Linux PROT_NONE, not a hardware
  global mapping.

## Case 2: Anonymous Page Fault

Linux first marks suitable private anonymous VMAs with `VM_NACC_APP`.

Key Linux points:
- `linux/mm/mmap.c::nacc_should_mark_private_anon_vma()`
- `linux/mm/mmap.c`: mmap path sets `VM_NACC_APP`.
- `linux/mm/mmap.c`: brk path sets `VM_NACC_APP`.

On fault:
- `linux/mm/memory.c::do_anonymous_page()`
- It calls `nacc_should_install_private_leaf(vma, addr)`.

That predicate requires:
- active NaCC mm;
- address below `min(TASK_SIZE, NACC_USER_VPN2_PROTECTED_END)`;
- `VM_NACC_APP`;
- not `VM_PFNMAP`;
- not `VM_MIXEDMAP`;
- not shared.

Linux then allocates a normal anonymous folio and builds a normal requested PTE.
The install point is:

```text
linux/mm/memory.c::do_anonymous_page()
  -> set_ptes(mm, addr, ptep, entry, nr_pages)
```

On a secure PTP, RISC-V `set_ptes()` does not write directly. It calls:

```text
nacc_set_ptes_sbi(__pa(ptep), pte_val(entry), nr, addr, __pa(mm->pgd))
```

OpenSBI dispatches to:

```text
sm_nacc_set_ptes(ptep_pa, pteval, nr_ptes, start_va, root_pgd_pa)
```

For each PTE slot, OpenSBI calls:

```text
nacc_prepare_secure_pte_update(old_pte, requested_pte, &secure_pte)
```

For a new anonymous page fault this is usually:

```text
old PTE: empty
new PTE: valid user leaf pointing to PFN X
```

Result:
- acquire `PFN X` in the private bitmap/refcount;
- add `PTE_NACC` to the final PTE;
- write the final PTE to the secure PTP.

Boundary to remember:
- Linux read faults may temporarily use the global zero page.
- Zero page is not real app-private data.
- The current small-step-B work did not deeply resolve zero-page semantics; this
  remains a lower-priority follow-up review candidate.

## Case 3: COW

COW spans fork-time PTE copying and later write-fault replacement.

### Fork-Time Copy

Main Linux function:

```text
linux/mm/memory.c::copy_present_ptes()
```

Linux first tries:

```text
vm_normal_page(src_vma, addr, pte)
```

If that does not produce a page, NaCC falls back to:

```text
nacc_private_leaf_page(src_vma->vm_mm, src_vma, addr, pte, &nacc_pfn)
```

That helper accepts only:
- active NaCC mm;
- protected user leaf address;
- present PTE;
- `pte_nacc(ptent)`;
- valid PFN;
- not zero PFN;
- not secure PTP PFN.

So Linux observes `PTE_NACC` to recover the normal `struct page` for MM
accounting. Linux does not use `VM_MIXEDMAP` or `_PAGE_SPECIAL` as the private
leaf identity here.

When copying PTEs:

```text
__copy_present_ptes()
  -> wrprotect_ptes(parent)
  -> set_ptes(child)
```

Parent write-protect:
- goes to `sm_nacc_wrprotect_ptes()` on secure PTP;
- calls `nacc_prepare_secure_pte_update(old, old & ~PTE_W, &secure_pte)`;
- same PFN, only permission changes;
- keeps `PTE_NACC`;
- does not change private refcount.

Child PTE install:
- goes to `sm_nacc_set_ptes()`;
- old child PTE is empty;
- requested child PTE points to the same PFN as parent;
- OpenSBI acquires one more private ref and adds `PTE_NACC`.

After fork:

```text
parent -> PFN A, read-only, PTE_NACC
child  -> PFN A, read-only, PTE_NACC
bitmap[PFN A].refcount increased for both mappings
```

### Write Fault

Main Linux function:

```text
linux/mm/memory.c::do_wp_page()
```

It again uses `nacc_private_leaf_page()` if `vm_normal_page()` does not handle
the PTE. This lets Linux treat a `PTE_NACC` private leaf as a normal page for
COW decisions.

There are two common outcomes.

Reuse old page:

```text
do_wp_page()
  -> wp_page_reuse()
  -> ptep_set_access_flags()
  -> __set_pte_at()
  -> nacc_set_ptes_sbi()
```

Same PFN, permission changes only:
- `PTE_NACC` remains;
- private refcount is unchanged.

Copy to a new page:

```text
do_wp_page()
  -> wp_page_copy()
      -> allocate new folio
      -> build requested PTE for new PFN
      -> ptep_clear_flush(old PTE)
      -> set_pte_at(new PTE)
```

The clear step goes through:

```text
ptep_get_and_clear()
  -> nacc_update_pte_sbi(NACC_UPDATE_PTE_XCHG_ONE, operand = 0, ...)
  -> sm_nacc_update_pte()
  -> nacc_prepare_secure_pte_update(old_pte, 0, &new_pte)
```

Result:
- old `PTE_NACC` PFN ref is retired;
- PTE slot is cleared.

The set-new step goes through:

```text
set_pte_at()
  -> nacc_set_ptes_sbi()
  -> sm_nacc_set_ptes()
  -> nacc_prepare_secure_pte_update(empty, requested_new_pte, &secure_pte)
```

Result:
- new PFN is acquired;
- new PTE gets `PTE_NACC`.

After COW copy:

```text
old mapping owner -> PFN A, PTE_NACC
write-fault owner -> PFN B, PTE_NACC
bitmap[PFN A].refcount decremented
bitmap[PFN B].refcount incremented
```

## Root/Ownership Boundary

Linux passes a root PGD physical address to several secure PTE calls:

```text
nacc_set_ptes_sbi(..., start_va, __pa(mm->pgd))
nacc_update_pte_sbi(..., start_va, __pa(mm->pgd), ...)
```

Current OpenSBI code mostly checks that the target PTE slot physical address is
inside the secure PTP region. It does not fully walk `root_pgd_pa + start_va`
to prove that the passed `ptep_pa` belongs to that root and VA.

This is an important future hardening candidate:

```text
For SET_PTES / UPDATE_PTE / WRPROTECT_PTES, OpenSBI could walk from
root_pgd_pa and start_va and verify that the resulting PTE slot address equals
ptep_pa before allowing the write.
```

That is separate from the small-step-B convergence work, which focused on
`VM_NACC_APP`, richer resident leaf resolution, and moving PTE/refcount
authority into OpenSBI secure PTE transitions.

