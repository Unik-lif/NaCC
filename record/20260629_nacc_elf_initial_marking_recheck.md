# NaCC private leaf bootstrap gap

Date: 2026-06-29

This note is a compressed working record for the current security issue:
initial user data leaf inclusion is not fully monitor-owned in the current
implementation.

## Short conclusion

Current code has a strong post-commit boundary:

> Once a user leaf is committed as `PRIVATE_DATA`, protected PTE writes,
> bitmap/refcount transitions, private copies, uaccess, and retirement are
> mediated by OpenSBI.

But current code does not yet prove the stronger malicious-Linux claim:

> A malicious Linux kernel cannot omit a confidentiality-relevant resident user
> leaf from private ownership during ELF/init/fault/COW setup.

The gap is initial inclusion. Linux currently decides which leaves become
private candidates by setting `VM_NACC_APP` and `_PAGE_NACC`; OpenSBI then
validates and commits only those candidates.

## Current code shape

Linux-side candidate selection:

- `linux/mm/mmap.c`: active NaCC mm + private anonymous non-special mappings
  get `VM_NACC_APP`; file-backed, shared, PFNMAP, and MIXEDMAP are excluded.
- `linux/mm/memory.c`: anonymous fault, COW replacement, and fork-copy set or
  preserve `_PAGE_NACC` only for NaCC candidate leaves.
- `linux/arch/riscv/mm/nacc.c`: invoke/exec detach walk scans the protected
  user VA window and upgrades eligible resident anonymous leaves by submitting
  `pte_mknacc(oldpte)` through `nacc_update_pte_sbi()`.

Monitor-side commit:

- Secure PTP writes are routed through OpenSBI.
- `opensbi/lib/sbi/sm/vm.c:nacc_prepare_secure_pte_update()` treats
  `requested_pte & PTE_NACC` as the private candidate signal, acquires the PFN
  in the private bitmap/refcount, strips `PTE_NACC`, and writes the prepared
  secure PTE.
- `sm_prepare_user_pt()` calls `nacc_sync_private_tags()`, but that walk only
  applies private bitmap state to leaves already carrying the private marker.

Therefore OpenSBI is authoritative for the commit, but not yet for deciding the
full set that must be committed.

## Historical answer: was there an all-leaf bitmap route?

Yes. The records show that there was an earlier all-protected / whole-user-leaf
route.

Key evidence:

- `TASK_20260410_111541_bitmap`: Phase A reused invoke/exec/fork-child walks to
  synchronize root plus private-data tags, and secure leaf installs tagged
  target PFNs as `PRIVATE_DATA`.
- `TASK_20260414_113719_private_bitmap`: `PRIVATE_DATA` changed from log-only
  into QEMU/OpenSBI-enforced load/store mediation for Linux S-mode accesses.
- `TASK_20260415_154406_vma_guided_bitmap`: explicitly says the previous
  baseline was all-protected-leaf / uniform user-leaf treatment. It describes
  `sm_prepare_user_pt()` and `sm_nacc_set_ptes()` as blind helpers that tagged
  every user leaf candidate, and then deliberately replaces that with
  VMA-guided selective-private policy.
- `TASK_20260511_010813_recover`: after removing the Region DB/VMA sync path,
  records that OpenSBI whole-user-leaf private bitmap tagging again became the
  surviving semantic path.
- `TASK_20260511_150353_nacc_leaf_data_page`: says current OpenSBI
  whole-user-leaf bitmap tagging protected access at secure PTE install, but
  Linux still treated newly allocated leaves as ordinary anonymous/COW pages.
- `TASK_20260511_213330_nacc_leaf_data_lifecycle_intent`: says the desired
  lifecycle authority was NaCC ownership plus RISC-V user-half leaf structure
  (`VPN2 < 256`), not VMA category, Region DB, runtime use, or bitmap timing.

So the user memory is not imaginary: the project did have an all/whole
user-leaf direction.

## What drifted

The records point to practical fallout, not a clean security rejection of
whole-user-leaf protection.

The intended split should have been:

- OpenSBI keeps the safety baseline: eligible confidential user leaves remain
  `PRIVATE_DATA` in the bitmap.
- Linux may provide hints to reduce cost, choose better lifecycle mechanics, or
  identify explicit public/shared/device exceptions.
- A missing or false Linux hint must not remove bitmap protection from a leaf
  that belongs to the confidential user scope.

What actually drifted is narrower and more dangerous:

- The all-private route exposed many ordinary Linux kernel paths that touch user
  data pages: usercopy, COW/page-copy, clear/zero, helper memcpy/memset,
  rseq/futex-like paths, and teardown/mapping-update work.
- The April 15 VMA-guided packet used VMA classes to reduce that trap/lifecycle
  surface and to separate anonymous/private, file/COW, shared, and special
  mappings.
- That VMA-guided route should have remained a hint/exception mechanism, but it
  effectively became the selector for which leaves receive `PRIVATE_DATA`.
- The May 15 `PTE_NACC` route fixed a different problem: replacing
  `pte_special()`/`VM_MIXEDMAP` identity with an explicit PTE marker and making
  OpenSBI/PTE/bitmap state authoritative after secure PTE commit. It did not
  fully restore monitor-owned scope selection.

The likely drift is this:

> We tried to manage the high trap/lifecycle cost of all-leaf protection by
> adding Linux-side classification. That classification later became a required
> candidate signal for bitmap acquisition, instead of remaining a non-authority
> hint or an explicit-exception mechanism.

That means the current gap is real. It is not proof that the whole design is
lost; it is the missing bootstrap policy that must be repaired or clearly
scoped.

## Paper/security implication

Safe statement for current code:

> Linux prepares candidate private leaves, but OpenSBI performs the trusted
> PTE write, bitmap/refcount transition, copy, uaccess mediation, and
> retirement. After a leaf is committed as `PRIVATE_DATA`, Linux cannot treat it
> as ordinary memory without monitor mediation.

Unsafe statement for current code:

> A malicious Linux kernel cannot choose to leave a secret-bearing user leaf out
> of private ownership.

That stronger statement requires one more design step.

## Likely repair directions

Preferred security repair:

- Make OpenSBI own a confidential user VA scope, probably the existing
  protected user-half window or a manifest-defined subset.
- At invoke/exec/fork attach, OpenSBI scans secure user page tables and
  auto-acquires every eligible resident user leaf inside that scope, or rejects
  the attach on an ineligible mapping.
- Later `SET_PTES` / `UPDATE_PTE` rejects a non-private eligible user leaf
  inside that scope unless it is covered by an explicit monitor-approved
  public/shared/device/agent exception.
- `VM_NACC_APP` remains Linux bookkeeping/optimization only. `_PAGE_NACC` may
  remain a cooperative hint, but omission must not bypass protection.

Alternative paper-only repair:

- State a trusted-launch assumption: Linux's initial candidate classification
  is trusted/measured only until OpenSBI commits private ownership. After that,
  Linux is adversarial with respect to access, PTE mutation, copy, and retire.

The first route is needed if the paper claims malicious Linux from the start of
ELF/user-data classification.

## Open questions for the next code pass

- Should the monitor private scope be all `VPN2 < 256` user leaves, or a
  manifest-defined confidential VA range?
- Which mappings must be explicit exceptions: file-backed text, shared memory,
  device/PFNMAP/MIXEDMAP, VDSO/VVAR, agent apertures, or public syscall buffers?
- Should OpenSBI auto-acquire all eligible resident leaves, or fail attach if
  Linux did not request private status?
- How should non-resident entries, PROT_NONE resident leaves, swap-like entries,
  and huge leaves be handled in the first safe patch?
- Can the existing SUM/uaccess mediation work tolerate private-by-default, or
  do we need staged exceptions before enabling it broadly?
