# NaCC Bitmap Control-Plane Hardening Static Audit

Date: 2026-07-14

Status: historical static-audit baseline, reconciled on 2026-07-16 against the
first bounded hardening iteration.

This document originally verified and extended
`record/20260713_nacc_bitmap_control_plane_security_gaps.md`. The 2026-07-14
planning pass did not select an execution route, modify code, or run a build,
VM, test, or exploit. The reconciliation below records later implementation and
T2 results without rewriting the original findings as though they had been
known during that pass.

## 0. Post-hardening reconciliation (2026-07-16)

The first implementation deliberately covered a smaller containment slice than
the full design proposed later in this audit. It is now committed as:

- QEMU `346924247094f0dc2b15afd64144b8a02f41959f`
  (`riscv: nacc: harden Agent entry controls`)
- OpenSBI `817a09136012294e5f8194d8b863e722fbcf3b39`
  (`nacc: harden control-plane transitions`)
- Linux `aa0801fdfe9214e71aa052bf4687fe0356b8fa1a`
  (`mm: nacc: order PTP teardown before reclaim`)

The Agent subrepository was not changed. The current disposition of the audit
findings is:

| Audit finding | 2026-07-16 status | Reconciled boundary |
| --- | --- | --- |
| Existing-private alias authorization (§5.1) | Open | Generic PTE preparation still lacks an authenticated fork, grant, root, and exact-slot relation for acquiring an already-private PFN. |
| Exact `root + VA + level -> ptep_pa` binding (§5.2) | Open | No PTE ABI or Monitor-walk change was made. |
| Raw private-PFN FIDs (§5.3) | Resolved for the exact public capability | Both retained FIDs now return `SBI_ENOTSUPP` at dispatch and do not reach their mutation handlers. Monitor-internal, PTE-derived acquire/retire remains. |
| Root tag creation/re-tag (§5.4) | Substantially resolved | A fresh root requires no record, `NORMAL`, and zero private refs; exact same-root/same-CID is no-write idempotence; other existing-record tuples fail. Idempotence does not diagnose a pre-existing nonzero refcount. |
| Broader root lifecycle (§5.4) | Open | Generic root-to-private transition concerns, detach/quiescence, retirement, TLB revocation, zeroing, quarantine, and reuse were not redesigned. |
| Last-reference revoke/zero/publish (§5.5) | Open | Ref/tag mutation can still precede PTE commit and there is no trusted revoke-plus-zero transaction before `NORMAL` publication. |
| High-page copy (§4.1) | Partially contained only | The documented raw-FID extraction chain is blocked at steps 3-4, but source/destination authorization, bounds, root/VA binding, and the copy transaction remain unchanged. |
| Secure-PTP reclaim (§4.2) | Partially resolved | The identified `free_pte_range()` honest path now unlinks and completes local teardown before enqueue. Monitor ownership/liveness/replay checks, quiescence, and other enqueue-before-destructor paths remain open. |
| Unbound `PRIVATE_COPY_PENDING` (§4.3) | Open | No one-use binding, rollback, cancellation, or trusted zero path was added. |
| Agent entry CSR ownership (§13.2) | Mostly resolved | Exact Agent state is required for S-mode writes and a zero protected redirect is fail-stop; nonzero target alignment, executable validity, and Agent-window membership are not established. |
| Agent-only FID origin (§13.2) | Resolved for the two scoped FIDs | `AGENT_MMAP` and `AGENT_READY` require Agent state. Trusted Agent mapping arguments remain unchecked by deliberate first-iteration scope. |
| Fork/clone authority (§13.3-§13.5) | Open | No grant, parent/child root relation, alias transaction, or clone-family policy was added. |

Static review establishes the scoped source properties. The later successful
three-component builds and canonical eight-workload batch establish honest-path
compatibility only. They do not directly exercise wrong-origin Agent FIDs,
disabled raw-PFN FIDs, illegal root-tag transitions, zero-entry redirect, queue
saturation, or any broader malicious-Linux lifecycle property. Primary runtime
evidence is preserved at:

`/home/link/NaCC/logs/test_runner/TASK_20260714_164716_harden/validation_evidence_20260715_131523.log`

## 1. Scope and threat-model boundary

This pass asks whether the five control-plane gaps in the 2026-07-13 record are
real in the current implementation, and what additional facts must shape a
hardening task.

The static analysis assumes:

1. Linux S-mode is malicious and may invoke any Linux-facing NaCC SBI function
   with arbitrary arguments, repeat calls, replay stale arguments, and race
   calls across harts.
2. OpenSBI M-mode and the NaCC Agent are trusted. In particular, Agent S-mode
   is currently a system-wide trusted principal for `PRIVATE_DATA` access.
3. QEMU's CPU translation path is part of the enforcement mechanism.
4. DMA, device-originated access, and IOMMU policy are outside this pass. The
   conclusions below are CPU-path conclusions only.
5. Availability is not the main confidentiality goal because a malicious OS
   can deny service. Panic and poisoning paths are still recorded where they
   hide a fail-open transition or break honest execution.

The pass does not assume that a Linux-supplied PID or CID is authenticated. The
current registration syscall stores the supplied CID in Linux and sends
`(cid, pid)` to OpenSBI (`linux/arch/riscv/kernel/sys_riscv.c:686-703`), while
`sm_nacc_register()` records it without an independent root or parent grant
(`opensbi/lib/sbi/sm/sm.c:276-304`). Therefore CID equality is useful metadata,
but is not by itself proof that a mapping operation was authorized.

### Human-confirmed functional boundary

The human clarified the current target semantics on 2026-07-14:

- ordinary private memory remains isolated by root/process even when processes
  have the same CID;
- the only currently allowed way for an existing private PFN to gain another
  process mapping is normal fork inheritance;
- explicit same-CID shared memory, shared grants, cross-container sharing, and
  Agent-managed shared-memory design are outside this hardening round.

This resolves the default-sharing policy. It does not yet resolve how the
Monitor authenticates that a requested alias really came from fork rather than
from a Linux-forged parent/child assertion.

## 2. Executive verdict

All five claims in the seed record were confirmed against the pre-hardening
2026-07-14 tree. Several were more severe than the seed record stated. The last
column records the effect of the later bounded patch; it does not change the
historical verdict.

| Seed claim | Historical verdict | Important qualification | 2026-07-16 status |
|---|---|---|---|
| An existing `PRIVATE_DATA` PFN can gain a new mapping without authorization | Confirmed | The generic PTE path cannot distinguish fork from an arbitrary alias. The trusted high-page copy path also accepts any private source PFN. | Open. |
| `ptep_pa` is not rebound to `root + VA` | Confirmed | A slot need only be inside the broad Secure PTP range. It may be unreachable, free, stale, owned by another root, or at a different level. | Open. |
| Raw private-PFN acquire/retire ecalls remain exposed | Confirmed | They could forge refcounts and force cross-type tag transitions, including `ROOT_L0 -> PRIVATE_DATA -> NORMAL`. | Resolved for the two public raw FIDs; internal PTE-derived lifecycle remains. |
| Root tag/retire lifecycle can be miscalled | Confirmed | Re-tagging cleared `ATTACHED`, permitted CID replacement, and could turn live private data into a Linux-readable `ROOT_L0` page. | Tag creation/idempotence substantially resolved; retirement and broader lifecycle remain open. |
| Last-reference reclaim lacks a trusted revoke/flush/zero/publish transaction | Confirmed | Refcount and tag mutation occurred before the PTE commit, and `PRIVATE_DATA -> NORMAL` occurred without trusted zeroing or proof that the old mapping was unreachable. | Open. |

The narrow positive statement from the seed record also remains true: while a
PFN is stably tagged `PRIVATE_DATA`, the current QEMU CPU path denies Linux
S-mode and ordinary U-mode access. This data-plane property does not authenticate
the code that changes the tag or installs the PTE.

## 3. Confirmed data-plane baseline

The existing mechanism is worth preserving, but its claim must remain narrow.

1. QEMU permits a `PRIVATE_DATA` access only from M-mode or from U/S-mode while
   `nacc_state` is Agent state
   (`qemu/target/riscv/cpu_helper.c:101-109`, `1022-1035`). It does not compare
   the current CID with PFN metadata.
2. `ROOT_L0` is a weaker policy: U-mode is denied, but ordinary Linux S-mode
   may read the whole page and may write the upper half
   (`qemu/target/riscv/cpu_helper.c:1007-1021`).
3. `PRIVATE_COPY_PENDING` is M-mode-only
   (`qemu/target/riscv/cpu_helper.c:1036-1043`).
4. A bitmap tag write is published before QEMU synchronously invalidates
   cached physical aliases on all CPUs in TCG
   (`qemu/hw/riscv/nacc_bitmap.c:21-56`). This is a real cache-revocation
   primitive, but it cannot prove that a state transition was authorized or
   that a PTE was removed.
5. Secure PTP memory is M-mode read/write and S/U read-only through the OpenSBI
   domain policy (`opensbi/lib/sbi/sbi_domain.c:885-890`). Linux cannot directly
   write it, but Linux can ask OpenSBI to write or reclaim it through an ecall.

The supported conclusion is therefore:

> If trusted code keeps a PFN in `PRIVATE_DATA` and all reachable PTEs were
> installed through an authorized transaction, Linux CPU accesses cannot read
> or write that PFN directly.

The second half of that statement is not currently established.

## 4. Highest-priority newly confirmed issues

### 4.1 High-page copy is an unbounded M-mode copy primitive

**2026-07-16 reconciliation:** partially contained, not fixed. The two public
raw PFN FIDs used by steps 3 and 4 of the concrete chain below are now hard
disabled, so that exact extraction sequence no longer completes through those
interfaces. The M-mode copy primitive itself still accepts unbound
caller-selected source/destination PFNs, and pending-copy consumption remains
unbound. No broader confidentiality or integrity closure is claimed.

`sm_nacc_copy_user_highpage()` reads tags and refcounts for caller-supplied
PFNs. Its normal private-copy branch requires only:

```text
from_tag == PRIVATE_DATA
to_tag == NORMAL
```

It does not require the source to be the leaf at the supplied root and VA, does
not require the root to be attached or current, does not authenticate PID/CID,
does not require `from_refs > 0`, and does not prove that the destination is a
valid tracked data page (`opensbi/lib/sbi/sm/sm.c:1197-1267`). It then executes
an M-mode `sbi_memcpy(PPN2PA(to_pfn), PPN2PA(from_pfn), PGSIZE)`.

Out-of-range PFNs are reported as `NORMAL`, and an out-of-range tag write is a
silent no-op (`opensbi/lib/sbi/sm/bitmap.c:99-120`). Consequently, malicious
Linux can request an M-mode copy to an address outside the tracked data range.
Depending on the selected PFN, this can corrupt Monitor-managed memory rather
than merely fail a user-page copy.

The pre-hardening tree also had a direct confidentiality chain using only the
then-exposed interfaces:

1. Select any victim `PRIVATE_DATA` PFN as `from_pfn` and a tracked normal page
   as `to_pfn`.
2. `COPY_USER_HIGHPAGE` copies the secret and leaves the destination
   `PRIVATE_COPY_PENDING/0`.
3. Raw `ACQUIRE_PRIVATE_PFN(to_pfn)` changes it to `PRIVATE_DATA/1`.
4. Raw `RETIRE_PRIVATE_PFN(to_pfn)` changes it to `NORMAL/0`.
5. Linux reads the now-normal destination.

This issue should be treated as immediate containment work even if the larger
transaction redesign is staged.

### 4.2 Secure PTP reclaim has no ownership or liveness proof

**2026-07-16 reconciliation:** the specific honest
`linux/mm/memory.c::free_pte_range()` ordering defect described below is fixed.
That path now captures the token, clears the parent, executes `smp_wmb()` for a
secure child, completes local `ptdesc` and mapping-slot teardown, and only then
enqueues. The heading remains true for Monitor ownership/liveness, duplicate,
replay, foreign/live-page rejection, generation, and translation-quiescence
properties. Other PTP free paths were outside the patch.

`sm_alloc_ptp()` pops a page from a freelist and writes its physical address to
a caller-supplied pointer (`opensbi/lib/sbi/sm/sm.c:513-525`). The allocator
records no root, level, parent, allocation generation, or linked state
(`opensbi/lib/sbi/sm/kalloc.c:68-84`).

`sm_reclaim_ptp()` trusts a caller-supplied PFN array and count and passes every
entry directly to `sec_mem_free()` (`opensbi/lib/sbi/sm/sm.c:230-246`). The
free path checks only alignment and pool bounds, zeroes the page, and inserts it
into the intrusive freelist (`opensbi/lib/sbi/sm/kalloc.c:44-61`). It cannot
detect:

- a reachable PTP being freed;
- a stale PFN being replayed after reallocation;
- a duplicate free inserting the same page more than once;
- one Secure PTP being linked into multiple roots;
- a free-list page being accepted as an empty page table;
- a supplied slot belonging to a different root or level.

The pre-hardening tree also had an honest-kernel ordering defect.
`free_pte_range()` queued the PTE-page PFN before clearing its parent PMD
(`linux/mm/memory.c:193-211`). `add_to_reclaim_list()` synchronously flushes
when the queue reaches its capacity (`linux/arch/riscv/mm/nacc.c:1330-1346`).
The queue-saturating entry can therefore be reclaimed and zeroed while its
parent still points to it. This is not only an adversarial scenario.

### 4.3 `PRIVATE_COPY_PENDING` is unbound and has no cancellation transaction

**2026-07-16 reconciliation:** open and unchanged.

The high-page copy path creates `NORMAL/0 -> PRIVATE_COPY_PENDING/0` before
copying (`opensbi/lib/sbi/sm/sm.c:1250-1257`). PTE preparation consumes any
pending PFN by acquiring it (`opensbi/lib/sbi/sm/vm.c:377-399`); the pending
state contains no source root, destination root, VA, expected old PTE, PID/CID,
operation token, or generation.

Linux may perform the copy and then lose the COW race. It discards the new
folio without issuing a trusted pending cancellation
(`linux/mm/memory.c:3694-3803`). `nacc_bitmap_retire_private_data()` panics on
zero refs, so it is not a cancellation API
(`opensbi/lib/sbi/sm/bitmap.c:431-450`). The recycled page remains M-only and
can poison later allocator use.

Pending must become a one-use, bound transaction state with an explicit
zero-and-cancel path.

## 5. Detailed verification of the five seed gaps

### 5.1 Existing-private alias authorization is absent

**2026-07-16 reconciliation:** open and unchanged. Disabling the raw PFN FIDs
does not authenticate aliases requested through the generic PTE-update path.

For an attached root, an ordinary requested leaf is treated as private even if
Linux omits `PTE_NACC` (`opensbi/lib/sbi/sm/vm.c:373-383`). If its PFN differs
from the old slot, `nacc_bitmap_acquire_private_data()` is called regardless of
whether the new PFN was `NORMAL`, already `PRIVATE_DATA`, or another tag
(`opensbi/lib/sbi/sm/vm.c:393-399`).

The bitmap acquire API accepts only a PFN. It increments the counter and forces
the tag to `PRIVATE_DATA` without root, VA, CID, source mapping, operation type,
or grant validation (`opensbi/lib/sbi/sm/bitmap.c:362-409`).

This generic behavior is needed by the current fork path: the parent is
write-protected and the same private PFN is installed into the child at
`linux/mm/memory.c:1031-1045`. The Monitor sees the same shape if malicious
Linux installs process A's private PFN into an unrelated root. A typed fork or
sharing grant is therefore required; another tag check cannot distinguish the
two cases.

### 5.2 PTE slot, root, VA, and level are not bound

**2026-07-16 reconciliation:** open and unchanged.

`sm_nacc_set_ptes()` and `sm_nacc_wrprotect_ptes()` require the supplied span to
fall in the broad Secure PTP physical range, then dereference and write that
pointer (`opensbi/lib/sbi/sm/sm.c:722-795`). `sm_nacc_update_pte()` accepts a
slot in the same range or a `ROOT_L0` slot
(`opensbi/lib/sbi/sm/sm.c:816-897`). None derives the target slot from the
claimed root and VA.

`nacc_semantic_prepare_pte_update()` receives root, VA, old PTE, and requested
PTE, but not `ptep_pa`, so it cannot perform the missing binding
(`opensbi/lib/sbi/sm/semantic.c:902-973`). Its root context checks only a
`ROOT_L0` tag and nonzero recorded CID, not `ATTACHED` or current-root state
(`opensbi/lib/sbi/sm/semantic.c:111-134`). For ordinary transitions it returns
success when root context is absent (`opensbi/lib/sbi/sm/semantic.c:911-918`).
Accessed-bit clearing bypasses semantic and private-lifecycle validation
entirely (`opensbi/lib/sbi/sm/sm.c:881-893`).

The current Linux ABI is insufficient for a strict fix. For example,
`pmd_populate()` sends `start_va = 0`
(`linux/arch/riscv/include/asm/pgalloc.h:37-47`). The hardening route must either
change callers to supply the real VA and level or let Monitor-owned PTP
parent/owner metadata derive them. Merely comparing the existing arguments
would reject honest paths or validate the wrong slot.

### 5.3 Raw private PFN lifecycle remains Linux-controlled

**2026-07-16 reconciliation:** resolved for the exact public capability
described below. The retained acquire/retire FID numbers now return
`SBI_ENOTSUPP` directly from the dispatcher without invoking these handlers.
The wrappers and internal handlers remain in-tree, but no current in-tree
caller relies on the raw wrappers. Normal reference accounting continues as an
internal effect of Monitor PTE preparation; the broader transaction and
last-reference problems are not resolved by this interface removal.

The pre-hardening NACC handler exposed raw acquire and retire FIDs
(`opensbi/lib/sbi/sbi_ecall_nacc.c:116-126`). Their handlers take only a PFN
and call bitmap lifecycle functions (`opensbi/lib/sbi/sm/sm.c:930-951`).

Those calls could:

- increment the refcount of an arbitrary tracked PFN;
- force `ROOT_L0 -> PRIVATE_DATA` while retaining the stale root record;
- repeatedly retire all references of a live private PFN;
- force the final `PRIVATE_DATA -> NORMAL` before its PTE is removed;
- panic the Monitor on malformed retire sequences.

They must not remain independent S-mode capabilities. Tag and reference changes
must be internal effects of a verified mapping transaction.

### 5.4 Root lifecycle permits identity loss and cross-type downgrade

**2026-07-16 reconciliation:** partially resolved. `nacc_bitmap_tag_root_l0()`
now accepts only a clean, unreferenced `NORMAL` page with no root record, or an
exact existing `ROOT_L0`/same-CID tuple as a no-write idempotent call. This
closes attachment-flag loss, CID replacement, and private-to-root conversion
through the root-tag API. It does not redesign root retirement or quiescence,
and the generic PTE lifecycle still requires a broader guard against treating a
root PFN as private data. The idempotent branch preserves rather than diagnoses
any pre-existing inconsistent refcount.

The pre-hardening `nacc_bitmap_tag_root_l0()` rewrote `record->cid` and set
`record->flags = 0` every time (`opensbi/lib/sbi/sm/bitmap.c:265-298`). Thus a
repeat tag silently cleared `ATTACHED` and could change CID. This was not only
an external misuse: `sm_confirm_root_l0()` deliberately re-tagged an existing root
before attach work (`opensbi/lib/sbi/sm/sm.c:181-224`).

The pre-hardening root-tag operation did not require an old `NORMAL/0` state.
If Linux called `TAG_ROOT` on a live private-data PFN, the tag became `ROOT_L0`
while private refs remained. QEMU then permitted Linux S-mode reads of that page
because the root policy is weaker than the private-data policy. This was an
immediate confidentiality downgrade.

In the opposite direction, raw acquire could change a root page to
`PRIVATE_DATA`; raw retire could then publish it as `NORMAL`, while the root
record remained. The bounded patch blocks this exact raw-FID sequence, but does
not yet make every internal acquire transition type-safe.

`sm_nacc_retire_root()` removes semantic state and the root record without
proving detach, empty user mappings, no active Agent context, all-hart TLB
quiescence, or PTP-tree reclamation
(`opensbi/lib/sbi/sm/sm.c:907-914`,
`opensbi/lib/sbi/sm/bitmap.c:300-325`). A root-tag transition flushes aliases of
the root PFN itself, but it does not invalidate every cached leaf translation
that was produced by walking that root.

### 5.5 Last-ref publication is ordered before trusted revocation

**2026-07-16 reconciliation:** open and unchanged.

PTE preparation acquires the new PFN and retires the old PFN before the caller
stores the prepared PTE (`opensbi/lib/sbi/sm/vm.c:393-406`). The actual stores
occur later in `sm_nacc_set_ptes()`, `sm_nacc_wrprotect_ptes()`, and
`sm_nacc_update_pte()` (`opensbi/lib/sbi/sm/sm.c:754`, `791`, `864-877`).

If the old PFN had one reference, `nacc_bitmap_retire_private_data()` publishes
it as `NORMAL` immediately (`opensbi/lib/sbi/sm/bitmap.c:412-469`). At that
moment the old PTE can still be present. QEMU's physical invalidation causes
future refills to observe the new permissive tag, so it cannot repair the
ordering.

Additional transaction failures include:

- no M-mode zero before `NORMAL` publication;
- no proof that every trusted mapping or stale translation is gone;
- multi-PTE SET commits incrementally without prevalidation or rollback;
- XCHG mutates refs based on one old value, then only logs if the atomic
  exchange returns a different old value;
- protection and move paths can transiently retire and reacquire a mapping
  that logically never lost its reference.

The required publication invariant is:

```text
tag(pfn) == NORMAL
    implies private_refcount(pfn) == 0
        and no trusted PTE maps the old private contents
        and no stale CPU translation can reach the old private contents
        and every byte has been zeroed by trusted code
```

Failure must leave the page protected or pending, even if that leaks memory.

## 6. Required state-machine constraints

These remain target constraints, not a description of the implemented first
iteration. Only public raw-FID removal, fresh root-tag/idempotence guards, and
one honest PTP teardown ordering edge have been implemented. The full data,
root, and PTP state machines below remain open.

### 6.1 Data PFN transitions

The following are conceptual legal transitions. They should be implemented by
typed internal functions, not a public generic setter.

| Old state | Typed cause | New state |
|---|---|---|
| `NORMAL/0`, no root record | verified fresh private map | protected first reference |
| `PRIVATE_DATA/n` | authorized alias grant | `PRIVATE_DATA/n+1` |
| `PRIVATE_DATA/n>1` | verified removal | `PRIVATE_DATA/n-1` |
| `PRIVATE_DATA/1` | verified removal | deny-access retiring state, still not `NORMAL` |
| retiring | all-hart revocation plus M-mode zero | `NORMAL/0` |
| `NORMAL/0` | verified copy reservation | bound `PRIVATE_COPY_PENDING/0` |
| bound pending | matching one-use destination commit | `PRIVATE_DATA/1` |
| bound pending | abort | M-mode zero, then `NORMAL/0` |

All direct cross-type transitions involving `ROOT_L0`, a nonzero refcount on
`NORMAL`, or an unbound pending page must be rejected. The existing 2-bit tag
does not contain a distinct retiring value; a safe implementation may keep the
hardware tag deny-capable while richer Monitor metadata records the software
state.

### 6.2 Root lifecycle

A conservative full design can give each root a generation and an explicit
lifecycle:

```text
UNTRACKED
  -> TAGGED_FRESH
  -> ATTACHING
  -> ATTACHED_ACTIVE
  -> DETACHING
  -> QUIESCED
  -> RETIRED/UNTRACKED
```

Required properties:

- fresh tag requires page alignment, `NORMAL/0`, no data or root record, and a
  valid initial root shape;
- re-tag of the same root/CID/generation is idempotent and preserves state;
- CID replacement and re-tag from another PFN type are denied;
- attach validates the complete reachable PTP tree and either commits all
  metadata or leaves a recoverable fail-closed state;
- detach blocks new updates, proves no active trusted root use, revokes stale
  translations on all harts, and clears the user half before publication;
- retire is legal only from `QUIESCED` and never directly from active state.

The full persistent state machine is not the only way to satisfy these
properties. For the current no-shared-memory scope, root generation can be
deferred if every root operation is synchronous under a Monitor lock, validates
the current root record and expected page-table state, exposes no replayable
root capability, and does not reuse the root PFN until teardown and translation
revocation are complete. In that smaller design, the existing tagged/attached
record plus strict operation guards may be sufficient. Generation becomes
important again if operations are split across ecalls, stale handles remain
valid, or root reuse can overlap delayed work.

### 6.3 Secure PTP lifecycle

Range membership is not liveness. A conservative full design can use
Monitor-owned metadata such as:

```text
FREE
  -> ALLOCATED_UNLINKED(generation, level)
  -> LINKED(root, root_generation, parent, index, level)
  -> UNLINKED_PENDING
  -> RECLAIMABLE
  -> FREE
```

Every PTE operation must walk from a live root to the requested level and
derive the slot. A caller-supplied `ptep_pa`, if retained for diagnostics or an
optimistic check, must exactly equal the derived slot. A batch must stay within
one live PTP and match consecutive VA indices. Linking a child already owned by
another parent must fail unless a future design explicitly supports shared
page-table pages.

Reclaim must use root/generation/link metadata and a completed translation
grace point. A raw PFN list is replayable and cannot be an authority.

A smaller current-scope design can avoid the full owner/parent/generation table
if it establishes the same invariant by construction:

- only the Monitor allocates and links a fresh Secure PTP;
- a PTP link is derived from an exact root/VA/level parent slot;
- unlinked Secure PTP slots cannot be mutated through the generic PTE API;
- the Monitor records only minimal `allocated` and `linked` state, or combines
  allocation and link into one synchronous operation;
- unlink, translation revocation, emptiness validation, and free are one
  synchronous operation;
- raw PFN-list reclaim is removed;
- alternatively, Stage A may quarantine unlinked PTPs instead of reusing them,
  accepting bounded memory loss as a fail-closed temporary policy.

The reserved Secure PTP pool is currently 256 MiB, or 65,536 base pages
(`opensbi/include/sbi/sbi_domain.h:181-183`). Quarantine is therefore useful as
a bounded hardening fallback, but it is not a complete long-running resource
management design.

## 7. Compatibility-derived operation classes

The Linux paths cannot all be treated as arbitrary old/new PTE assignments.
Their logical reference effects differ.

| Linux workflow | Logical effect | Required Monitor class |
|---|---|---|
| Initial anonymous fault | empty slot to first mapping of a fresh page | typed fresh-map; destination slot and PFN state verified; trusted zero if anonymous zero-fill is in scope |
| Access/dirty/write permission update | same root, VA, slot, and PFN; flags only | bounded generic flag update; no refcount change |
| `mprotect` / `PROT_NONE` | same mapping identity, although Linux uses clear/restore helpers | typed protection transaction; no transient last-ref retirement |
| Fork parent write-protect | flags only on existing source | bounded generic flag update |
| Fork child insertion | authorized additional alias of source PFN | typed fork grant; source and destination roots/VA/slots bound; exactly one added ref |
| Fork of pinned anonymous page | trusted copy to fresh destination | typed copy-derived fresh map |
| COW | source mapping replaced by one-use trusted copy | typed copy-and-replace; source leaf and destination reservation bound |
| PTE `mremap` | mapping moves to another VA with zero net refs | typed move; source present, destination empty, same root/PFN |
| Unmap / exit | one verified mapping removed | generic verified deletion; last ref enters trusted reclaim transaction |
| Non-leaf populate/unlink | Secure PTP ownership graph changes | typed PTP link/unlink; level and generation checked |
| Huge leaf | span-level version of the operations above | reject until full-span tagging, reference accounting, and transaction semantics exist |

Fork deserves special attention. The child PTEs are copied before the child's
first-user-return attach path. A fork grant therefore must exist before the
child root is `ATTACHED_ACTIVE`; simply requiring attached destination roots
would break honest fork.

The current configuration disables transparent huge pages
(`config/linux_config:806`), and attach rejects existing protected huge leaves
(`opensbi/lib/sbi/sm/vm.c:436-440`). Generic PMD update paths still collapse to
the same level-unaware PTE interface. Until span-aware lifecycle exists, every
private huge-leaf request should fail closed rather than tag only the base PFN.

KSM, khugepaged, and other kernel-worker operations may not execute under the
target process's current SATP. A design that relies only on
`root == current SATP` will either be bypassable or break these workers. The
first closed implementation should explicitly disable unsupported protected-mm
workers, or introduce a Monitor-issued worker capability; it should not trust a
Linux assertion that a worker acts for a root.

## 8. Transaction ordering required for closure

### 8.1 Fresh map or replacement

1. Lock the live root/slot and relevant PFN metadata in a fixed order.
2. Derive the slot from root, generation, VA, and level.
3. Verify the expected old PTE and operation-specific grant.
4. Reserve the destination while it is deny-access (`PRIVATE_DATA` or bound
   pending); never expose copied private bytes in `NORMAL`.
5. Commit the PTE while the old PFN is still protected.
6. Revoke the old VA translation if the mapping identity changed.
7. Only then decrement the old trusted reference.
8. If it was the last reference, keep a deny-access tag, complete all-hart
   revocation, zero in M-mode, and finally publish `NORMAL`.
9. On failure, roll back or retain a protected recoverable state.

### 8.2 Move and protection change

Move and protection changes must not be decomposed into an independently
authorized delete followed by an independently authorized map. They are one
transaction and must preserve the logical reference count throughout.

### 8.3 Root teardown

1. Enter `DETACHING` and reject new root transactions.
2. Ensure no trusted Agent context is executing with the root.
3. Remove or verify removal of every user mapping through trusted slots.
4. Perform an all-hart/all-ASID translation revocation appropriate to leaf
   translations, not only a physical flush of the root page.
5. Unlink and reclaim only PTP pages whose ownership metadata is quiescent.
6. Clear the root user half and retire semantic records.
7. Publish the root PFN as `NORMAL` only from `QUIESCED`.

## 9. Proposed staged route for discussion

This is not yet a task-packet route. It is a dependency ordering for human
discussion.

### Refinement after the lifecycle-complexity discussion

The required result is self-validating operations, not a particular metadata
shape. Full root/PTP generations are avoidable in the current scope when
multi-step protocols are collapsed into synchronous Monitor transactions:

- copy and destination-PTE replacement occur in one ecall, eliminating an
  unbound pending object;
- PTE removal, last-ref decrement, trusted zero, and `NORMAL` publication occur
  in one ecall while the hardware tag remains deny-capable until the end;
- PTP unlink, translation revocation, and reclaim occur in one ecall, or the
  PTP is quarantined;
- every mutation re-derives the actual slot from root/VA/level and checks the
  expected old value;
- no raw PFN or stale handle is accepted as authority.

This stronger Stage A needs relationship checks and some Linux/OpenSBI call-site
changes, but it does not require a general object-lifecycle framework. Full
generation metadata should be reconsidered only if later work introduces
asynchronous operations, reusable cross-ecall tokens, shared memory, or
cross-container objects.

### Stage A: immediate containment and state sanity

- bound and authenticate the high-page copy source and destination; reject all
  out-of-range PFNs before any tag write or memcpy;
- remove or hard-deny the raw private acquire/retire FIDs;
- replace generic tag mutation with legal transition guards;
- make same-root/same-CID tagging idempotent and preserve `ATTACHED`;
- reject CID replacement and every private/root cross-type transition;
- add a bound pending cancel path that zeroes before normal publication;
- fix the honest PTP queue ordering so enqueue cannot synchronously reclaim a
  still-linked table.

This stage blocks the clearest primitives, but must not be described as full
malicious-Linux closure.

**2026-07-16 progress reconciliation:**

| Stage A item | Status after the bounded patch |
| --- | --- |
| Authenticate and bound high-page copy | Open. The exact raw-FID extraction tail is blocked, but the copy operands and transaction are unchanged. |
| Remove or hard-deny raw private acquire/retire FIDs | Complete at the public dispatcher boundary. |
| Legal tag-transition guards | Partial. Fresh root tagging and exact root idempotence are guarded; generic data/root lifecycle transitions are not comprehensively typed. |
| Preserve same-root/same-CID attachment state and reject CID replacement | Complete for `nacc_bitmap_tag_root_l0()`. |
| Reject every private/root cross-type transition | Partial. The root-tag API and raw-FID path are closed; broader PTE-derived acquisition still needs explicit old-type enforcement. |
| Bound pending-copy cancellation and zeroing | Open. |
| Honest PTP queue ordering | Complete only for `free_pte_range()`; other paths and Monitor-side liveness remain open. |

Stages B through E remain unimplemented. In particular, the successful
canonical workload run is not the adversarial evidence described by Stage E.

### Stage B: Monitor-owned identity substrate

- add root generation/lifecycle metadata;
- add per-Secure-PTP allocation, owner, parent, level, link, and generation
  metadata;
- return allocated PTP identifiers as SBI results instead of writing through
  unvalidated S-mode pointers;
- replace raw PTP reclaim with typed unlink and generation-checked reclaim;
- implement a Monitor walk that derives exact slots from root/VA/level.

### Stage C: typed leaf transactions

- restrict generic updates to same-PFN flag changes and verified deletion;
- add typed fresh-map, fork-alias, copy-and-replace, move, and protection
  transactions;
- bind pending copy state to its one legal destination and expected source;
- serialize Monitor updates and require expected-old-PTE matching;
- prevalidate batches so a later element cannot leave an untracked partial
  lifecycle mutation.

### Stage D: trusted teardown and publication

- implement last-ref deny/revoke/zero/publish ordering;
- implement root detach/quiesce/retire ordering;
- define and execute all-hart translation revocation for shared private PFNs
  and retired roots;
- provide fail-closed rollback or leak states for interrupted transactions.

### Stage E: adversarial and compatibility evidence

- negative tests for every raw/cross-type/replay/mismatched-root operation;
- race tests for XCHG, COW loss, pending cancellation, batch updates, and PTP
  queue saturation;
- functional coverage for anonymous faults, permission changes, PROT_NONE,
  fork, pinned-fork copy, COW, mremap, unmap, exit, and PTP exhaustion/reuse;
- explicit tests that private huge leaves and unsupported workers fail closed;
- CPU-path stale-translation tests across multiple harts and ASIDs.

## 10. Decisions required before writing the execution packet

### 10.1 Default protection principal: resolved

Root/process isolation is the confirmed default. Same-CID membership does not
authorize an ordinary private alias. Fork inheritance is the only allowed
current exception. Explicit shared-memory and cross-container authorization
are out of scope for this round.

The remaining design question is narrower: how the Monitor recognizes a real
fork-derived alias without trusting a Linux-supplied operation name or
parent/child PID pair as sufficient authorization.

### 10.2 Source of fork and worker authority

The current PID/CID and parent/child relationship are supplied by Linux. If
Linux is malicious, a typed ecall named `fork` is not authorization by itself.
The design must choose whether a trusted Agent/parent context issues a one-use
grant, whether CID membership is intentionally sufficient, or whether fork is
temporarily outside the malicious-Linux claim.

### 10.3 First packet scope

**2026-07-16 decision record:** the executed packet selected an even smaller,
four-item containment slice: Agent entry/FID guards, raw-FID disablement, legal
root tagging, and the identified honest PTP ordering fix. It intentionally did
not implement the stronger Stage A relationship checks or synchronous
copy/PTE/reclaim transactions recommended below. The prose that follows is
retained as the broader design recommendation, not as a claim about the patch.

The first Coder packet can be one of three scopes:

- an emergency containment slice limited to Stage A, with an explicit statement
  that it does not close the control plane; or
- a stronger Stage A that adds exact relationship checks and synchronous
  copy/PTE/reclaim transactions, while deliberately avoiding a full generation
  framework; or
- a larger foundation slice covering Stages A and B, so subsequent typed leaf
  operations have trustworthy root/PTP identity.

Combining every stage in one unreviewed patch would have a large blast radius
across Linux, OpenSBI, QEMU, and the memory-management hot paths. A staged
packet sequence is safer, but Stage A should not be delayed because the current
copy and cross-type transitions are independently exploitable.

The current recommendation is the stronger Stage A middle option. Pure tag-type
checks do not reject a wrong private source, a foreign Secure PTP slot, or a
live Secure PTP reclaim because all of those operands have the expected type.
The stronger option adds the missing relationship and ordering checks without
committing the project to full root/PTP generations.

### 10.4 Unsupported feature policy

Until typed support exists, the packet should say whether protected THP,
hugetlb leaves, KSM, khugepaged, and non-current-root worker operations are
disabled fail-closed or remain outside the claim. Silent fallback to the
current generic update path is not acceptable.

### 10.5 Initial-content guarantee

For anonymous pages, a malicious Linux threat model normally requires trusted
zero-fill before first private publication. File-backed and exec-import pages
have different integrity semantics: Linux may provide public bytes, but that
does not authenticate them. The task should distinguish confidentiality of
later private writes from integrity/measurement of initial contents instead of
using one generic `NORMAL -> PRIVATE_DATA` rule for both.

### 10.6 Next manual discussion checkpoint (2026-07-16)

The first activity after the completed four-item packet should not be a broad
Stage A implementation. The recommended next step is a human-held design
discussion for the exact base-page leaf relationship: deriving or validating
the precise PTE slot from trusted root, VA, and level, then separating fresh
mapping, same-PFN permission change, removal, and existing-private alias cases.

This recommendation is a direction, not a frozen implementation decision.
Protected-fork compatibility, current versus non-current root operations, the
scope of parent-level PTP updates, and whether minimal PTP ownership metadata is
a prerequisite must be resolved first. The detailed checkpoint and hard
non-goals are recorded in Section 10 of
`record/20260715_nacc_bitmap_control_plane_small_step_hardening.md`.

No new machine owner is selected here. High-page copy, pending cancellation,
last-reference publication, broader PTP/root retirement, and fork/sharing
authority remain separate later slices.

## 11. Candidate acceptance properties for later packet design

These are security properties, not yet the active task Definition Of Done.

1. No Linux-facing call can directly select a PFN and change its tag or private
   refcount without a verified mapping/lifecycle transaction.
2. Every Secure PTP mutation is derived from a live root, generation, VA, and
   level; a mismatched, free, stale, or foreign slot is rejected without state
   change.
3. No legal operation can transform private data into `ROOT_L0` or `NORMAL`, or
   transform a root into private/normal, outside the corresponding lifecycle.
4. High-page copy cannot read an unrelated private source or write outside a
   validated destination data page.
5. Fork, COW, move, protection, and unmap each produce exactly their intended
   reference-count delta.
6. `NORMAL` publication occurs only after trusted unmap, all required
   translation revocation, and M-mode zeroing.
7. PTP reclaim rejects live, linked, duplicate, stale-generation, and foreign
   PFNs, including queue-saturation timing.
8. Root re-tag is idempotent; active-root retire is rejected; successful retire
   proves quiescence and invalidates derived leaf translations.
9. Unsupported huge leaves and worker contexts fail closed and are covered by
   tests.
10. Honest anonymous, permission, PROT_NONE, fork, COW, mremap, unmap, exit, and
    PTP reuse workflows retain explicit regression coverage.

### 2026-07-16 acceptance-property progress

| Property | Current status |
| --- | --- |
| 1. No direct Linux-selected PFN tag/ref mutation | Partial: the two raw PFN FIDs are disabled, but generic PTE and high-copy paths still accept caller-selected PFNs without the complete verified transaction. |
| 2. Exact live-root/slot derivation | Open. |
| 3. Typed data/root transitions | Partial: root-tag creation and exact idempotence are guarded; last-ref, generic acquire, and root retirement remain open. |
| 4. Bounded high-page copy | Open. |
| 5. Exact lifecycle deltas | Open. |
| 6. Revoke/zero before `NORMAL` | Open. |
| 7. Secure-PTP reclaim validity | Partial: one honest ordering edge is fixed; live/stale/duplicate/foreign rejection and saturation-specific runtime proof remain open. |
| 8. Root idempotence and safe retire | Partial: re-tag idempotence is implemented; active-root rejection and quiescent retirement are open. |
| 9. Unsupported huge/worker contexts | Open. |
| 10. Honest workflow regressions | Partial: the canonical eight-workload T2 batch passed, but it is not the complete workflow matrix listed here and does not test PTP reuse. |

## 12. Evidence boundary

This audit used static source inspection only. It did not run a compiler, VM,
QEMU, test suite, exploit, or concurrency probe. Line references describe the
current worktree as inspected on 2026-07-14 and may move after edits.

The audit was intentionally bounded to bitmap/PTE/root/PTP/copy control-plane
paths named by the seed record. Other Linux-facing SBI handlers also accept raw
pointers or Linux-declared identity. A later claim of complete malicious-kernel
resistance requires a separate enumeration and audit of the full NACC SBI
surface.

The 2026-07-16 reconciliation adds two later evidence classes:

- reviewer source inspection of the committed, four-item patch; and
- successful QEMU, OpenSBI, and Linux builds plus all eight canonical T2
  workloads, each with its expected output and guest exit code zero.

That runtime evidence proves build and canonical honest-path compatibility. It
does not directly exercise the new negative guards or the exact teardown
ordering, and it does not change any open finding above into a malicious-kernel
lifecycle proof.

## 13. Follow-up: Agent-first syscall path and fork authorization

This follow-up corrects the earlier discussion after tracing the protected
syscall path, Linux fork ordering, and Monitor entry points together. It remains
a planning result; no code or task packet was changed as part of the audit.

### 13.1 The protected syscall really does land in Agent first

For a protected task in `NACC_STATE_AGENT`, QEMU redirects a U-mode trap to
`CSR_TWIN_ENTRY` (`qemu/target/riscv/cpu_helper.c:2172-2184`). Agent
`__trap_entry` saves the complete user register/trap frame in Agent-owned memory
before copying it to the Linux kernel stack and executing `acall`
(`agent/src/entry.S:203-359`). Linux handles the delegated syscall and returns
with `aret`; Agent then resumes at `__agent_linux_return` and returns to protected
U-mode (`agent/src/entry.S:389-475`).

The earlier suggestion that a libc wrapper or a new syscall interception point
would be required was therefore wrong. The trusted first-landing point already
exists. What is missing is syscall policy in Agent: the current entry code never
branches on saved `scause` or `a7`; every exception is delegated generically to
Linux. The existing C `usertrap()` is an unused fatal loop
(`agent/src/trap.c:142-147`).

This makes an Agent pre-delegation hook the natural source of fork intent. A
post-delegation hook can cancel an unused intent or close the authorization
window before returning to protected U-mode. Both hooks must run on an
Agent-owned runtime stack, not on the Linux-controlled kernel stack.

### 13.2 The current first-landing boundary is not yet hostile-Linux proof

**2026-07-16 reconciliation:** the two bounded prerequisites were hardened, but
the broader heading remains intentionally qualified.

1. S-mode writes to `CSR_TWIN_ENTRY` and `CSR_TRAMPOLINE` now require exact
   Agent state; M-mode writes are preserved. Protected U/S redirect rejects a
   zero twin entry before changing privilege flow. A nonzero value is not yet
   proven aligned, executable, or within an Agent-owned entry window, and the
   T2 run did not directly force the zero-entry branch.
2. `SBI_EXT_AGENT_MMAP` and `SBI_EXT_AGENT_READY` now require Agent state and
   reject other origins before their handlers. The first iteration explicitly
   trusts Agent-supplied mapping arguments, so fixed-range, permission, and W^X
   validation described by the broader audit remains open rather than silently
   assumed.

The numbered findings below are retained as the pre-patch basis for those
changes.

Two prerequisite defects were identified before an Agent-issued fork grant
could be treated as an authority:

1. `CSR_TWIN_ENTRY` and `CSR_TRAMPOLINE` writes are denied only while the current
   state is `NACC_STATE_LINUX` (`qemu/target/riscv/csr.c:4339-4373`). Linux in
   `NACC_STATE_INACTIVE` can still rewrite them. The U-mode trap redirect also
   does not reject a missing or out-of-Agent `twin_entry`. Agent/M-mode must be
   the only writers, and every protected redirect must validate the trusted
   entry before changing privilege state.
2. The NACC SBI dispatcher has no per-FID caller-origin policy
   (`opensbi/lib/sbi/sbi_ecall_nacc.c:26-185`). In particular,
   `SBI_EXT_AGENT_MMAP` can be invoked from Linux state and directly writes the
   current page tables through `mem_mmap()` (`opensbi/lib/sbi/sm/sm.c:528-539`,
   `opensbi/lib/sbi/sm/vm.c:746-755`). Agent-only FIDs must require authenticated
   Agent state, and `AGENT_MMAP` must be limited to the fixed Agent mapping it is
   intended to construct.

Consequently, the original audit verified that "the syscall is intended to land
in Agent first" on the honest path but did not treat it as an unforgeable
security boundary against malicious Linux. The bounded fixes above strengthen
that boundary without completing the wider argument-validation and fork-grant
design.

### 13.3 Fork authorization must be root-based, not PID-based

The actual new-mm ordering is:

```text
Agent sees clone intent
  -> copy_mm / dup_mm
  -> child PGD allocation and generic CID root tag
  -> dup_mmap / copy_page_range / private-PFN aliases
  -> copy_thread marks NACC_FORKED
  -> PID allocation
  -> child PID registration
  -> wake child
  -> first-user-return attach
```

`copy_mm()` runs before `copy_thread()` and PID allocation
(`linux/kernel/fork.c:2384-2405`). `dup_mm()` creates the child root and then
copies VMAs/PTEs (`linux/kernel/fork.c:1670-1687`). The first private alias is
installed by `copy_present_ptes()` through the generic secure `SET_PTES` path
(`linux/mm/memory.c:1025-1045`). `NACC_FORKED`, child PID registration, and child
attach all occur later.

Therefore neither `NACC_FORKED` nor `(parent_pid, child_pid)` can authorize PTE
copying. The authorization identity available in time is:

```text
Agent-authenticated parent_root -> freshly created child_root
```

The child PID may be bound to that already-authorized root after `copy_process()`
returns and before wake-up, but it is bookkeeping/dispatch identity rather than
the source of fork authority.

### 13.4 Revised minimal fork route

A bounded implementation can avoid a general shared-object or generation
framework, but it cannot avoid the following relationship checks:

1. Agent recognizes a supported new-mm clone from its protected pre-delegation
   frame and asks the Monitor to record one pending intent for the current
   attached parent root. The Monitor derives root and CID from trusted current
   state; Linux does not supply them as authority.
2. The child PGD is bound to that intent after `mm_init()` creates it and before
   `dup_mmap()` copies any leaf. The destination root must be fresh, empty, and
   incompatible with any existing root/data record.
3. Existing-private child insertion uses a typed fork transaction that derives
   both source and destination slots from the bound roots and VA, verifies the
   same PFN and non-escalating flags, updates exactly one reference, commits the
   child PTE, and returns an error that propagates back through `dup_mm()`.
4. The generic PTE API rejects every new reference to an already-private PFN;
   same-slot/same-PFN flag updates remain legal and do not change references.
5. The pre-wake registration binds the eventual child PID to the authorized
   child root. First-child attach validates that binding and consumes the
   temporary fork relation instead of re-tagging/reassigning the root.
6. Fork failure, child-root teardown, or parent return without a bound child
   cancels the temporary intent. Root PFN reuse is forbidden while such a record
   exists, so a fork generation is not required in this bounded design.

Exact root/VA/slot validation requires at least minimal Monitor-owned Secure PTP
allocation/link ownership. Otherwise Linux can link a foreign PTP into the
child and make a correctly walked child slot mutate another root. This is the
specific part of the earlier Stage B identity substrate that is a prerequisite
for a real fork guarantee; a full reusable generation framework is not.

### 13.5 Clone-family scope is not yet resolved

Native RISC-V exposes `clone` (220) and `clone3` (435), not separate native
`fork`/`vfork` syscall entries. Legacy `clone` places flags in a register, so
Agent can classify `CLONE_VM` before delegation. `clone3` places flags behind a
user pointer and needs a fault-safe trusted read or an explicit unsupported
policy.

Current Linux hooks mark every user child of an initialized NaCC task as
`NACC_FORKED`, including `CLONE_VM`, `CLONE_THREAD`, and `CLONE_VFORK`
(`linux/arch/riscv/kernel/process.c:240-248`). Those cases share the original mm
and create no child root, but still take the PID registration and first-return
attach paths. This is a current semantic defect, not an implementation of
thread/vfork support. The execution packet must explicitly choose whether to
reject these forms in the first closed implementation or design a separate
same-root thread policy.
