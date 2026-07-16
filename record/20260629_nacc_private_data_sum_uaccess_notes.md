# NaCC private-data VM/PTE markers and SUM-mediated uaccess path

Date: 2026-06-29

This note summarizes the Linux/OpenSBI mechanism that NaCC uses to keep
confidential user data pages out of ordinary Linux `SUM`-enabled uaccess
paths. The key design is a two-level marker scheme:

- `VM_NACC_APP`: a Linux VMA flag for candidate private anonymous application
  mappings in an active NaCC address space.
- `_PAGE_NACC` / `PTE_NACC`: a software/reserved RV64 PTE bit used as a
  per-leaf private-data marker.

Together they let Linux identify likely private-data mappings cheaply, while
OpenSBI remains the authority that validates and commits protected page table
state and private-data PFN metadata.

## Core implementation claim

NaCC does not rely on broad, ad hoc kernel `SUM` windows to access confidential
container user pages. Linux classifies private anonymous user ranges with
`VM_NACC_APP`, marks concrete resident leaves with `_PAGE_NACC`, and routes
private-data uaccess through explicit SBI handlers. OpenSBI validates these
operations against protected page tables and monitor-maintained PFN
bitmap/refcount state before copying data or committing a PTE update. Normal
Linux uaccess remains the fallback only when OpenSBI reports that the page is
not a NaCC private-data page.

## 1. VMA-level candidate marking

There are two NaCC-related VMA flags, and they should not be confused:

- `VM_NACC` is the fixed agent-region VMA marker
  (`linux/include/linux/mm.h:318`). The agent mapping is created with
  `VM_PFNMAP | VM_IO | VM_DONTEXPAND | VM_DONTDUMP | VM_NACC`
  (`linux/arch/riscv/kernel/sys_riscv.c:146`).
- `VM_NACC_APP` is the application private-data bookkeeping marker
  (`linux/include/linux/mm.h:436`). This is the flag relevant to confidential
  container user pages.

Linux marks new mappings as `VM_NACC_APP` only when they are plausible NaCC
private-data VMAs:

- The mm must be NaCC-active.
- The mapping must be anonymous/private, not file-backed.
- Shared, PFNMAP, and MIXEDMAP mappings are excluded.
- The range must overlap the protected user VPN[2] window.

The policy is implemented in `nacc_should_mark_private_anon_vma()`
(`linux/mm/mmap.c:67`). It is applied in both `mmap` and `brk` paths:

- `__mmap_region()` sets `vm_flags |= VM_NACC_APP`
  (`linux/mm/mmap.c:1419`).
- `do_brk_flags()` sets `flags |= VM_NACC_APP`
  (`linux/mm/mmap.c:1835`).

Existing resident VMAs can also be marked during NaCC activation/detach. The
activation walk uses a conservative private-anonymous hint and sets
`VM_NACC_APP` for eligible VMAs (`linux/arch/riscv/mm/nacc.c:543`,
`linux/arch/riscv/mm/nacc.c:568`).

For paper text, present `VM_NACC_APP` as a coarse Linux-side classification
mechanism. It avoids treating all user mappings as confidential and excludes
file/shared/device/special mappings early.

Threat-model boundary: `VM_NACC_APP` is not a security root against a malicious
Linux kernel. It is Linux-maintained bookkeeping that reduces false positives
and keeps ordinary Linux mapping types out of the protected-data path in the
current implementation. A malicious Linux kernel could deliberately choose not
to mark an anonymous mapping as `VM_NACC_APP`, or could try to construct a
mapping that looks like an excluded class from Linux's own metadata. The monitor
does not trust the VMA flag directly; it only sees protected PTE commit requests
and PFN bitmap/refcount state.

The defensible security claim is therefore narrower:

- Once a PFN has been committed as NaCC private data, Linux cannot directly
  mutate its protected PTE or access/copy/retire it through ordinary paths
  without OpenSBI validation.
- Linux can prepare a candidate mapping, but OpenSBI validates the secure PTE
  slot, the `_PAGE_NACC` candidate, and the resulting PFN metadata transition.
- The current VMA filter is a completeness/performance policy for deciding what
  Linux asks OpenSBI to protect; it is not itself a malicious-kernel-proof
  proof that every possible secret-bearing page has been protected.

If the paper wants a stronger malicious-Linux completeness claim, the monitor
would need an additional range policy, for example rejecting non-`_PAGE_NACC`
user leaves inside the confidential execution window except for explicitly
registered non-private regions. Without that extra monitor-enforced policy, the
safe statement is that Linux may deny service or withhold protection, but it
cannot bypass OpenSBI for pages already committed into private ownership.

Current-code correction on initial tagging: OpenSBI does not read Linux VMA
flags directly during invoke. The initial invoke path is:

- Linux activates the mm and runs `nacc_detach_user_leaf_pages()`
  (`linux/arch/riscv/kernel/sys_riscv.c:223`,
  `linux/arch/riscv/mm/nacc.c:617`).
- That Linux walk uses `nacc_vma_private_anon_hint()` and installs
  `_PAGE_NACC` on selected resident user PTEs through `nacc_update_pte_sbi()`
  (`linux/arch/riscv/mm/nacc.c:543`,
  `linux/arch/riscv/mm/nacc.c:584`).
- OpenSBI invoke validates that the user non-leaf PTP tree is secure and then
  calls `nacc_sync_private_tags(pgd)`
  (`opensbi/lib/sbi/sm/sm.c:191`).
- `nacc_sync_private_tags()` walks the secure page table and only acquires
  leaves that already carry `PTE_NACC`
  (`opensbi/lib/sbi/sm/vm.c:341`,
  `opensbi/lib/sbi/sm/vm.c:363`).

So the monitor does not trust VMA flags directly, but the current prototype
still relies on Linux to request initial private leaves by placing `_PAGE_NACC`
candidate bits before OpenSBI syncs bitmap state. Under a fully malicious Linux
model, that is a completeness gap unless the monitor adds an independent
range/manifest rule.

Stronger monitor-side rule for the malicious-Linux model:

- Define the confidential user VA window or a manifest of private ranges as
  monitor-owned registration state.
- At invoke, OpenSBI walks the secure page table itself and either:
  - auto-acquires every valid `PTE_U` resident leaf in that private window,
    regardless of Linux VMA metadata; or
  - rejects attach if any resident private-window leaf is not marked/eligible
    for private ownership.
- For later `SET_PTES` / `UPDATE_PTE`, OpenSBI rejects any user leaf in the
  private window that is not committed as private data, except for explicitly
  registered shared/I/O/agent ranges.

With that rule, malicious Linux can still cause denial of service by refusing
to create a valid confidential address space, but it cannot silently keep a
secret-bearing private-window leaf outside the private bitmap.

## 2. PTE-level private leaf marking

NaCC uses RV64 PTE bit 54 as a software marker:

- Linux defines `_PAGE_NACC` as `BIT(54)`
  (`linux/arch/riscv/include/asm/pgtable-64.h:72`).
- Linux provides `pte_nacc()` and `pte_mknacc()`
  (`linux/arch/riscv/include/asm/pgtable.h:421`).
- OpenSBI mirrors this as `PTE_NACC`
  (`opensbi/include/sm/vm.h:36`).

This bit is more precise than `VM_NACC_APP`: it marks a concrete leaf PTE whose
PFN should be treated as private data.

Important Linux tagging paths:

- Anonymous page fault: if `nacc_should_install_private_leaf(vma, addr)` is
  true, Linux marks the newly allocated leaf with `pte_mknacc()`
  (`linux/mm/memory.c:5091`, `linux/mm/memory.c:5172`).
- COW/write-protect fault: the copied page preserves or receives the NaCC
  marker when the VMA/address is private or the old PTE was already NaCC-tagged
  (`linux/mm/memory.c:3671`, `linux/mm/memory.c:3723`).
- Fork page copy: if the source PTE was NaCC-tagged, the child's copied PTE is
  tagged too (`linux/mm/memory.c:1019`).
- Activation detach of already-resident pages: Linux updates eligible resident
  leaves by passing a `pte_mknacc(oldpte)` candidate to OpenSBI
  (`linux/arch/riscv/mm/nacc.c:584`, `linux/arch/riscv/mm/nacc.c:601`).

The helper `nacc_should_install_private_leaf()` requires an active NaCC mm,
protected user-leaf address range, `VM_NACC_APP`, no PFNMAP/MIXEDMAP, no shared
mapping, and no file mapping (`linux/mm/memory.c:1621`).

For paper text, describe `_PAGE_NACC` as a Linux/OpenSBI software contract,
not as a hardware permission bit. Linux proposes a private leaf by setting the
bit; OpenSBI validates and commits the trusted state.

## 3. OpenSBI commit authority and PFN metadata

OpenSBI validates NaCC-tagged PTE candidates before updating protected page
tables. The key function is `nacc_prepare_secure_pte_update()`
(`opensbi/lib/sbi/sm/vm.c:307`):

- It treats `requested_pte & PTE_NACC` plus a valid user private-data leaf as a
  new private-data candidate.
- It strips the requested marker, acquires monitor private-data metadata for
  the new PFN, and then reapplies `PTE_NACC` to the prepared PTE.
- If the old PTE was NaCC-tagged but the new PTE no longer refers to the same
  private PFN, it retires the old PFN from private-data metadata.

Candidate filtering rejects supervisor leaves, secure page-table pages,
`PTE_SPECIAL`, and `PTE_DEVMAP` (`opensbi/lib/sbi/sm/vm.c:241`).

The actual metadata changes are in the bitmap/refcount layer:

- `nacc_bitmap_acquire_private_data()` marks/acquires a private-data PFN
  (`opensbi/lib/sbi/sm/bitmap.c:256`).
- `nacc_bitmap_retire_private_data()` drops the private-data reference and
  returns the PFN to normal when the last reference is gone
  (`opensbi/lib/sbi/sm/bitmap.c:295`).

This is the permission boundary: Linux prepares candidate PTE values, but the
monitor owns the protected page-table write and the PFN tag/refcount transition.

## 4. Linux uaccess interception

Linux hooks the common RISC-V uaccess primitives so that private-data access is
attempted through OpenSBI before falling back to normal assembly uaccess:

- `get_user`: calls `nacc_private_data_get_user_read()` first
  (`linux/arch/riscv/include/asm/uaccess.h:93`).
- `put_user`: calls `nacc_private_data_put_user_write()` first
  (`linux/arch/riscv/include/asm/uaccess.h:277`).
- `copy_from_user`: calls `nacc_private_data_copy_from_user()` first
  (`linux/arch/riscv/include/asm/uaccess.h:364`).
- `copy_to_user`: calls `nacc_private_data_copy_to_user()` first
  (`linux/arch/riscv/include/asm/uaccess.h:389`).
- `clear_user`: calls `nacc_private_data_clear_user()` first
  (`linux/arch/riscv/include/asm/uaccess.h:421`).

Each helper returns one of three outcomes:

- handled: OpenSBI copied/read/wrote private data; return the normal uaccess
  result to the caller.
- not supported: the destination/source is not a private-data page; fall back
  to the normal Linux uaccess path.
- denied/fault: report `EFAULT` or remaining bytes.

The backing Linux functions live in `linux/arch/riscv/mm/nacc.c`:

- `nacc_private_data_get_user_read()` (`:806`)
- `nacc_private_data_put_user_write()` (`:863`)
- `nacc_private_data_copy_to_user()` (`:915`)
- `nacc_private_data_copy_from_user()` (`:1014`)
- `nacc_private_data_clear_user()` (`:1086`)

String uaccess helpers are also staged through the scope interface:

- `strnlen_user()` calls `nacc_uaccess_string_read_begin()` before the normal
  string loop (`linux/lib/strnlen_user.c:128`).
- `strncpy_from_user()` does the same for string copy
  (`linux/lib/strncpy_from_user.c:156`).

## 5. SUM handling and COW prefault behavior

Some SBI uaccess handlers require Linux to enter with `SUM` set, because the
operation semantically corresponds to a user access. Linux therefore creates
small, explicit `SUM` windows only around the SBI-mediated operation:

- `nacc_user_access_save_enable()` sets `SR_SUM` only if it was previously off
  (`linux/arch/riscv/mm/nacc.c:680`).
- `nacc_user_access_restore()` restores the previous state
  (`linux/arch/riscv/mm/nacc.c:689`).
- Scope/string begin paths use this bracket before calling OpenSBI
  (`linux/arch/riscv/mm/nacc.c:695`, `linux/arch/riscv/mm/nacc.c:733`).

For writes, a private destination may require a COW or writable prefault before
OpenSBI can complete the copy. NaCC handles that case deliberately:

- OpenSBI can return `SBI_ERR_DENIED_LOCKED` for private write/COW-needed
  cases.
- Linux then calls `nacc_private_data_fault_in_writeable()`, which temporarily
  clears `SR_SUM` before invoking `fault_in_safe_writeable()`
  (`linux/arch/riscv/mm/nacc.c:845`).
- After the fault path installs the proper writable/private leaf, Linux retries
  the SBI-mediated write/copy (`linux/arch/riscv/mm/nacc.c:889`,
  `linux/arch/riscv/mm/nacc.c:952`).

This matters for the paper: even when Linux must trigger a normal fault/COW
path, it avoids doing that under an open `SUM` window that could directly touch
private user data.

## 6. Why `PRIVATE_COPY_PENDING` exists

The COW copy path has a short interval where Linux has allocated a destination
page and OpenSBI has copied confidential bytes into it, but the destination page
has not yet been installed as a committed NaCC private leaf. NaCC marks that
destination PFN as `NACC_PFN_TAG_PRIVATE_COPY_PENDING` during this interval.

The path is:

- Linux COW calls `copy_mc_user_highpage()`
  (`linux/mm/memory.c:3351`).
- RISC-V `copy_mc_user_highpage()` first tries
  `nacc_copy_mc_user_highpage_sbi()` (`linux/include/linux/highmem.h:393`).
- If the source PFN is `PRIVATE_DATA` and the destination PFN is still
  `NORMAL`, OpenSBI marks the destination as `PRIVATE_COPY_PENDING` and copies
  the page in M-mode (`opensbi/lib/sbi/sm/sm.c:890`).
- Linux then installs the COW replacement PTE. Since this is a NaCC private
  leaf, the PTE carries `_PAGE_NACC` (`linux/mm/memory.c:3671`,
  `linux/mm/memory.c:3723`).
- For secure PTPs, `set_pte_at()` / `set_ptes()` routes the write through
  OpenSBI rather than writing the PTE directly
  (`linux/arch/riscv/include/asm/pgtable.h:589`,
  `linux/arch/riscv/include/asm/pgtable.h:611`).
- OpenSBI's protected PTE commit path calls
  `nacc_prepare_secure_pte_update()`, which acquires the destination PFN as
  `PRIVATE_DATA` and updates the private refcount
  (`opensbi/lib/sbi/sm/vm.c:307`,
  `opensbi/lib/sbi/sm/bitmap.c:256`).

The important semantic point is that `PRIVATE_COPY_PENDING` is not a normal
accessible private-data state. OpenSBI private uaccess and trap resolution only
accept PFNs tagged `NACC_PFN_TAG_PRIVATE_DATA`
(`opensbi/lib/sbi/sbi_trap_ldst.c:176`,
`opensbi/lib/sbi/sbi_trap_ldst.c:1400`). A pending page therefore cannot be
resolved as an ordinary confidential user leaf before the protected PTE commit
turns it into `PRIVATE_DATA`.

This explains why the pending marker is useful:

- It prevents a copied confidential page from remaining indistinguishable from
  `NORMAL` memory during the COW handoff.
- It makes unsupported tag combinations fail closed in
  `sm_nacc_copy_user_highpage()` instead of silently copying private data into
  an unexpected PFN state (`opensbi/lib/sbi/sm/sm.c:930`).
- It separates "confidential bytes have been copied here" from "this PFN has a
  committed private PTE/refcount". The former is `PRIVATE_COPY_PENDING`; the
  latter is `PRIVATE_DATA`.

For paper text, this can be described as a two-phase private COW handoff:
trusted copy first quarantines the destination PFN as `PRIVATE_COPY_PENDING`;
protected PTE commit then promotes it to `PRIVATE_DATA` and accounts it in the
monitor refcount.

## 7. How the bitmap takes effect after marking

After a PFN is marked `PRIVATE_DATA`, the bitmap becomes the monitor's fast
authority for private-data decisions:

- SBI private uaccess handlers resolve the user VA through the current `satp`
  and then check that the resolved PFN is `PRIVATE_DATA`
  (`opensbi/lib/sbi/sbi_trap_ldst.c:176`). If the bitmap tag is not private,
  OpenSBI returns not-supported and Linux may fall back to ordinary uaccess.
- Private load/store trap handling uses the same bitmap check before treating a
  faulting address as private data (`opensbi/lib/sbi/sbi_trap_ldst.c:1400`).
  This is what makes direct SUM-on/SUM-off fallback accesses fail closed or be
  narrowly mediated.
- Protected PTE commit updates the bitmap/refcount on mapping changes:
  `nacc_prepare_secure_pte_update()` acquires the new private PFN when a
  `_PAGE_NACC` candidate is installed and retires the old private PFN when a
  tagged PTE is replaced or removed (`opensbi/lib/sbi/sm/vm.c:307`).
- Retirement decrements the private refcount and only returns the PFN to
  `NORMAL` after the last private mapping is gone
  (`opensbi/lib/sbi/sm/bitmap.c:293`).

So the bitmap has two roles. First, it is an access-classification oracle:
OpenSBI uses it to decide whether a resolved PFN is confidential user data.
Second, it is lifecycle metadata: PTE commit/retire paths use the same state to
keep private ownership/refcounts balanced across fork, COW, zap, munmap, exec,
and exit.

## 8. OpenSBI private-data uaccess and trap boundary

OpenSBI validates explicit uaccess requests:

- Scope begin checks previous privilege mode is S-mode, requires `MSTATUS_SUM`,
  validates range/class/direction, and records scope state
  (`opensbi/lib/sbi/sbi_trap_ldst.c:615`).
- Private scalar read validates S-mode, `MSTATUS_SUM`, width, private user PA,
  and scope (`opensbi/lib/sbi/sbi_trap_ldst.c:706`).
- Copy-to-user, copy-from-user, clear-user, and put-user validate the private
  page and copy in M-mode (`opensbi/lib/sbi/sbi_trap_ldst.c:758`,
  `opensbi/lib/sbi/sbi_trap_ldst.c:815`,
  `opensbi/lib/sbi/sbi_trap_ldst.c:876`,
  `opensbi/lib/sbi/sbi_trap_ldst.c:923`).

OpenSBI also handles load/store traps to private-data pages. It resolves the
faulting VA through the current `satp` and only treats the access as private
when the PFN tag is `NACC_PFN_TAG_PRIVATE_DATA`
(`opensbi/lib/sbi/sbi_trap_ldst.c:1400`).

The strict SUM checks are important:

- `nacc_private_data_strict_sumoff_deny_load()` rejects S-mode SUM-off loads
  from the kernel-high private-data alias range
  (`opensbi/lib/sbi/sbi_trap_ldst.c:999`).
- `nacc_private_data_strict_sumon_deny()` rejects SUM-on fallback private-data
  traps (`opensbi/lib/sbi/sbi_trap_ldst.c:1030`).
- The private load/store emulators call these checks before copying data
  (`opensbi/lib/sbi/sbi_trap_ldst.c:1431`,
  `opensbi/lib/sbi/sbi_trap_ldst.c:1612`).

In other words, ordinary delegated traps do not become a broad escape hatch for
Linux to access private data. The intended path is the explicit SBI uaccess or
PTE-commit handler; direct fallback traps are either mediated narrowly or
redirected/denied.

## Suggested paper phrasing

NaCC uses two Linux-visible markers to reduce unnecessary `SUM` windows and to
separate candidate classification from trusted ownership changes. `VM_NACC_APP`
marks private anonymous application VMAs in an active confidential-container
address space, while `_PAGE_NACC` uses an otherwise reserved RV64 PTE bit to
mark concrete private-data leaves. Linux sets `_PAGE_NACC` when installing or
copying anonymous private leaves, but the protected PTE write is committed by
OpenSBI. The monitor validates that the target slot belongs to a protected page
table, checks that the requested leaf is an eligible user private-data mapping,
updates private-data bitmap/refcount metadata, and only then installs the
prepared PTE.

For kernel access to these pages, NaCC hooks RISC-V uaccess primitives
(`get_user`, `put_user`, `copy_{to,from}_user`, and `clear_user`) so they first
attempt an OpenSBI private-data operation. If OpenSBI reports that the page is
not private, Linux falls back to normal uaccess. If it is private, the data move
is performed under monitor validation rather than by an arbitrary S-mode
dereference during a long `SUM`-enabled region. Write/COW cases are prefaulted
with `SUM` cleared and retried through the monitor. This keeps Linux involved
in normal VM policy while making protected ownership, private-copy, and
private-retirement decisions explicit OpenSBI commit points.

## Caveats

- `VM_NACC` and `VM_NACC_APP` are distinct. Use `VM_NACC_APP` when discussing
  confidential application data; reserve `VM_NACC` for the agent mapping.
- `_PAGE_NACC` is not a hardware permission bit. It is a software marker used
  by Linux and OpenSBI to coordinate private-data PTE handling.
- The mechanism applies to active NaCC address spaces, protected user VPN[2]
  slots, and private anonymous mappings. File-backed, shared, device/special,
  PFNMAP, MIXEDMAP, and secure page-table PFNs are intentionally excluded.
- Existing resident pages are tagged during activation/detach; future pages are
  tagged on anonymous fault, COW, and fork-copy paths.
