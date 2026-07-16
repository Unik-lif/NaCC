# NaCC Bitmap Control-Plane Hardening: Small-Step Plan and First-Iteration Reconciliation

Date: 2026-07-15

Status: first bounded iteration implemented, source-reviewed, committed, and closed at T2; focused runtime-negative coverage remains open

Last reconciled: 2026-07-16

Continuation Mode: manual

Implemented commits:

- QEMU `346924247094f0dc2b15afd64144b8a02f41959f`
  (`riscv: nacc: harden Agent entry controls`)
- OpenSBI `817a09136012294e5f8194d8b863e722fbcf3b39`
  (`nacc: harden control-plane transitions`)
- Linux `aa0801fdfe9214e71aa052bf4687fe0356b8fa1a`
  (`mm: nacc: order PTP teardown before reclaim`)

The Agent subrepository required no source change in this iteration.

### Reconciliation snapshot

| Item | Current status | Evidence boundary |
| --- | --- | --- |
| Agent-owned entry CSRs | Resolved for the scoped source property | S-mode writes require exact Agent state; M-mode access is preserved; a zero protected entry is fail-stop. The rejection branches were not exercised directly at runtime. |
| `AGENT_MMAP` / `AGENT_READY` origin | Resolved for these two FIDs | Wrong-origin calls return `SBI_EDENIED`; this is not a dispatcher-wide FID classification audit and trusted Agent arguments remain unchecked by design. |
| Raw private-PFN FIDs | Resolved at the public dispatcher boundary | Both retained FIDs return `SBI_ENOTSUPP`. Monitor-internal PTE-mediated acquire/retire bookkeeping remains active. |
| Root-tag transition | Resolved for root creation and exact idempotence | Root retirement, generations, quarantine, and safe reuse remain deferred. |
| Honest child-PTP teardown | Resolved only in `free_pte_range()` | Parent unlink, ordering, and local teardown now precede enqueue. Other teardown paths and malicious-Linux-safe reuse remain unresolved. |
| Canonical compatibility | Resolved at T2 | QEMU, OpenSBI, and Linux built; all eight canonical workloads reported `status=ok` and guest exit code zero. |
| Focused runtime-negative tests | Not resolved | Wrong-origin/state, disabled-FID, illegal root-transition, zero-entry, and forced synchronous-reclaim cases were not directly exercised. |
| Leaf authorization, alias policy, copy authorization, lifecycle containment, fork/sharing | Deferred | No first-iteration security claim applies to these areas. |

## 1. Scope Decision

The hardening work should not be issued as one large implementation task. The
current concerns span syscall mediation, SBI authorization, page-table update
authorization, copy-on-write state, and page/root reclamation. Combining all of
them would make both implementation review and security claims difficult.

The agreed first iteration contains only four bounded items:

1. Protect the Agent-owned entry controls and Agent-only FIDs while preserving
   the existing checked `acall`/`aret` state transitions.
2. Disable the raw private-PFN acquire/retire FIDs.
3. Enforce legal root-tag transitions.
4. Correct the honest PTP unlink-and-local-teardown-before-reclaim ordering.

High-page copy, exact leaf authorization, lifecycle containment, and fork remain
separate follow-up discussions.

The bounded execution packet was implemented, reviewed, validated, and closed
on 2026-07-15. QEMU, OpenSBI, and Linux built successfully, and the canonical
eight-workload batch completed with eight `status=ok` results and zero guest
exits. This closes only the four scoped source changes and the canonical
compatibility gate.

## 2. Explicit Non-Goals for the First Iteration

The first iteration does not attempt to support or fully specify:

- protected-process fork, vfork, clone, or clone3;
- CLONE_VM or shared address spaces;
- shared memory, shared grants, or cross-container sharing;
- parent/child root metadata;
- root, PTP, or data-page generations;
- safe page reuse after a complete revocation and TLB-shootdown protocol;
- huge-page, migration, mremap, or worker-thread authorization;
- validation of trusted Agent-supplied `AGENT_MMAP` address and permission
  arguments;
- high-page copy preconditions or pending-copy lifecycle changes;
- a complete proof against a malicious Linux kernel.

These non-goals remain unimplemented after the first iteration. In particular,
private-page alias rejection has not yet been introduced. The successful
`fork_private_done` workload is honest-path compatibility evidence, not proof of
a secure fork or sharing model. When alias rejection is introduced, unsupported
protected fork must fail explicitly rather than silently construct an
incomplete child address space until an authorized parent/child design exists.

## 3. Static Facts and Current Resolution

The following observations were checked against the current source tree:

- A protected user trap is redirected to the Agent first. The Agent saves the
  frame and delegates the syscall to Linux, then resumes after `aret`.
  Relevant paths include `qemu/target/riscv/cpu_helper.c` and
  `agent/src/entry.S`.
- The Agent currently does not decode ordinary syscall semantics before that
  delegation.
- `nacc_state` is trusted machine state. M-mode context management may install a
  complete value, while `acall` and `aret` perform checked, narrow transitions
  between Agent and Linux and manage the pending-return bit. Those transitions
  are intended behavior and are not treated as a disclosure.
- **Resolved for this iteration:** S-mode writes to `CSR_TWIN_ENTRY` and
  `CSR_TRAMPOLINE` now require exact Agent state, while M-mode writes remain
  available. Protected redirect also fails stop if `CSR_TWIN_ENTRY` is zero.
  The Agent already installs the entry before `AGENT_READY`; per-hart
  initialization and entry-address validity beyond nonzero remain separate
  audit questions.
- **Partially resolved:** the NaCC SBI dispatcher still has no general per-FID
  origin taxonomy, but `AGENT_MMAP` and `AGENT_READY` now require Agent state.
  This iteration intentionally does not validate trusted Agent-supplied mapping
  arguments.
- **Resolved at the dispatcher boundary:** the retained raw private-PFN
  acquire/retire FIDs return `SBI_ENOTSUPP` without calling their mutation
  handlers. Static search found no current in-tree callers. Internal reference
  changes derived by the Monitor from PTE-update paths were not removed; the
  exact-slot authorization gap in those paths remains deferred.
- **Resolved for root tagging:** a new root requires no existing root record,
  tag `NORMAL`, and private refcount zero. Exact same-root/same-CID tagging is a
  no-write idempotent success; conflicting transitions fail. Root retirement
  and safe reuse remain unchanged.
- **Deferred:** leaf-update entry points check that a supplied PTE address lies in the secure
  PTP region, but do not prove that the supplied address is the exact leaf slot
  derived from the supplied root and virtual address.
- **Deferred:** the generic secure-PTE update path can acquire an already-private data PFN,
  which makes private aliases possible without a declared sharing relation.
- **Deferred:** the high-page copy FID accepts caller-supplied PFNs and creates a pending-copy
  state. The current state is not bound to a one-use `(root, virtual address)`
  authorization and has no explicit cancellation operation.
- **Deferred:** last-reference removal can publish a page as normal before a complete
  revocation, zeroing, and reuse protocol exists.
- **Resolved only for `linux/mm/memory.c::free_pte_range()`:** the secure child
  PTP token is captured before unlink, but parent unlink and ordering plus local
  `ptdesc`/mapping-slot cleanup now precede enqueue. Other PTP teardown paths and
  a Monitor-owned reuse protocol remain outside this iteration.

These facts do not imply that every item should be fixed in the same patch.

## 4. Implemented First Iteration

This was the agreed first coder packet. It remained limited to four local
changes whose expected behavior was already clear.

### 4.1 Preserve trusted state transitions and protect Agent-owned controls

- Preserve the current `nacc_state` layout and the checked transitions performed
  by M-mode context management, `acall`, and `aret`.
- Do not add a general S-mode bitmask update interface for `nacc_state`.
- Permit S-mode writes to `CSR_TWIN_ENTRY` and `CSR_TRAMPOLINE` only while the
  trusted state identifies the Agent as the current S-mode principal.
- Preserve M-mode save, load, and initialization of those CSRs.
- Reject protected entry when no trusted Agent entry has been installed.
- Require Agent state for the two explicitly Agent-owned FIDs,
  `SBI_EXT_AGENT_MMAP` and `SBI_EXT_AGENT_READY`.
- Treat the Agent as trusted in this iteration: do not add address, range,
  permission, or W^X validation to Agent-supplied `AGENT_MMAP` arguments.
- Do not turn this item into a classification audit of every NaCC FID.

Security effect: Linux cannot install its own first-hop handler or invoke the two
Agent-owned operations, while the intended Agent-to-Linux and Linux-to-Agent
`acall`/`aret` path remains unchanged.

Implementation status: **resolved for the scoped source property** in
`qemu/target/riscv/csr.c`, `qemu/target/riscv/cpu_helper.c`, and
`opensbi/lib/sbi/sbi_ecall_nacc.c`. `acall`/`aret` and M-mode CSR context
management were left unchanged. Direct runtime-negative coverage was not added.

### 4.2 Disable the raw private-PFN acquire/retire interface

- Make `SBI_EXT_LINUX_ACQUIRE_PRIVATE_PFN` and
  `SBI_EXT_LINUX_RETIRE_PRIVATE_PFN` fail closed at the monitor boundary.
- Keep the failure explicit and deterministic.
- Do not treat absence of honest in-tree callers as proof that the interface is
  safe; it is the reason disabling it has low expected compatibility risk.

Security effect: Linux cannot directly mutate private-data ownership using a raw
PFN capability that is not tied to a validated page-table operation.

Implementation status: **resolved at the public dispatcher boundary**. Both
retained FID numbers now return `SBI_ENOTSUPP`; their old mutation handlers are
not dispatched. This intentionally preserves internal PTE-mediated reference
bookkeeping and does not establish complete lifecycle safety.

### 4.3 Enforce legal root-tag transitions

- Allow a new root tag only from an unreferenced `NORMAL` page with no conflicting
  metadata.
- Treat tagging the same root with the same CID as idempotent.
- Preserve existing attachment state during an idempotent call.
- Reject CID replacement, root/private cross-type conversion, and any other
  undeclared transition.

Security effect: the root-tag operation cannot be used as an untyped metadata
overwrite primitive.

Implementation status: **resolved for root creation and exact idempotence** in
`opensbi/lib/sbi/sm/bitmap.c`. The idempotent branch performs no record or flag
mutation. Root retirement, liveness, quarantine, generations, and reuse were not
changed.

### 4.4 Correct the honest PTP teardown ordering

- Capture the child PTP token while the parent entry is still readable.
- Clear and order the parent page-table entry.
- Complete Linux-side `ptdesc` and secure-PTP mapping-slot cleanup.
- Only then place the child PTP page on a reclaim queue that may synchronously
  call OpenSBI and return the page to `sec_mem_free()`.

Security effect: this removes a concrete honest-path ordering defect.

Limitation: this is not a malicious-Linux-safe PTP reuse protocol. Monitor-owned
PTP ownership and reuse checks remain required later.

Implementation status: **resolved only for the identified
`free_pte_range()` path** in `linux/mm/memory.c`. The ordering is confirmed by
source review; the T2 workloads did not deliberately force the queue-full,
synchronous-reclaim edge at the exact ordering boundary.

### 4.5 Outcome Against the Original Definition of Done

The original definition of done required:

- `acall` and `aret` retain their existing checked state-transition semantics;
- Linux and inactive S-mode cannot rewrite the Agent-owned entry controls;
- `SBI_EXT_AGENT_MMAP` and `SBI_EXT_AGENT_READY` require Agent state without
  imposing new validation on trusted Agent arguments;
- the two raw PFN FIDs fail closed;
- root tagging follows the transition rules above;
- the honest PTP path unlinks and completes local teardown before enqueueing;
- focused negative tests cover wrong origin, wrong state, raw PFN FIDs,
  cross-type root tagging, and root/CID replacement;
- documentation claims only immediate guard-rail coverage, not complete memory
  lifecycle security.

Reconciled outcome:

- Reviewer inspection confirmed all scoped source properties, and the three
  required builds plus the canonical eight-workload T2 batch passed.
- The focused runtime-negative-test bullet was **not satisfied**. The batch did
  not directly execute the wrong-origin, wrong-state, raw-FID, illegal-root,
  zero-entry, or forced synchronous-reclaim rejection cases.
- The authoritative execution packet closed using source review for the new
  rejection/ordering properties and T2 for canonical compatibility. This record
  does not retroactively describe direct negative runtime coverage as complete.
- Therefore the implementation is closed at its bounded gate, while focused
  runtime-negative proof remains a separately routable evidence task rather
  than an unreported implementation claim.

## 5. Deferred Leaf Authorization Baseline

Status: deferred; unchanged by the first iteration.

This should be a separate packet after the first iteration is reviewed.

- Add a non-allocating validated page-table walk from the trusted root.
- At every non-leaf level, require the next page to be a valid secure PTP page.
- For resident leaf insertion, removal, and flag updates, require the caller's
  `ptep_pa` to equal the exact leaf slot derived from `(root, virtual address)`.
- Reject unsupported huge leaves instead of partially interpreting them.
- Permit same-slot, same-PFN flag updates without changing reference counts.
- Reject a new generic mapping to a PFN already tagged `PRIVATE_DATA`.
- Add an explicit honest-path unsupported error for protected fork or any other
  operation that would require such an alias.

This step intentionally chooses non-sharing as the default. It avoids inventing
fork authorization before a parent/child model has been agreed.

## 6. Deferred High-Page Copy Split

Status: deferred; unchanged by the first iteration.

The former item 5 is not part of the first iteration. It should be split before
implementation:

- Phase 5A validates the current root, virtual address, exact source PFN, fresh
  destination PFN, tracked ranges, and legal source/destination tags before any
  copy or metadata mutation.
- Phase 5B binds the pending result to a monitor-owned one-use authorization and
  adds a safe cancellation path.

Phase 5A narrows the copy primitive but does not close pending-state consumption.
The two phases therefore require separate claims and tests even if they are later
issued close together.

## 7. Deferred Fail-Closed Lifecycle Containment

Status: deferred; unchanged by the first iteration.

This should also be a separate packet. It is more stateful than the agreed first
iteration and the leaf-authorization baseline, but can still avoid generations
and full reuse support.

- Bind pending high-page copies to a monitor-owned, one-use authorization record,
  including at least destination PFN, root, virtual address, and expected source.
- Consume that state only for the exact authorized leaf update.
- Add cancellation that zeroes the destination in M-mode before returning it to
  any reusable state.
- When a private page reaches its last reference, keep it deny-tagged or
  quarantined rather than publishing it as normal immediately.
- Quarantine unlinked PTP and retired root pages until a later task implements
  trusted liveness, invalidation, zeroing, and reuse.

The accepted cost is bounded functionality and possible memory exhaustion under
repeated teardown. That is a denial-of-service limitation, but it avoids claiming
confidential reuse that the system cannot yet establish.

## 8. Work Deferred Until After Containment

Status: deferred; unchanged by the first iteration.

Fork support should be designed only after the non-sharing baseline is enforced.
That later discussion must decide:

- how the Agent identifies fork/clone intent before Linux changes page tables;
- how a new child root is authorized and linked to a parent root;
- whether eager copy, COW, or another mechanism is supported;
- which clone flags are rejected;
- how root relationships are retired without stale authority;
- whether future shared-memory grants reuse or remain separate from fork
  authorization.

Fork management can involve the Agent because it is already the first syscall
hop, but the Monitor must still enforce the resulting authority. Agent policy
alone cannot protect against a malicious Linux kernel invoking monitor APIs
directly or fabricating page-table update arguments.

## 9. First-Iteration Result and Remaining Decisions

The Section 4 implementation is complete, its three subrepository commits are
recorded above, and the execution packet is closed. The canonical T2
compatibility gate passed. Primary preserved evidence is:

`/home/link/NaCC/logs/test_runner/TASK_20260714_164716_harden/validation_evidence_20260715_131523.log`

Direct runtime-negative proof may be routed as a separate, bounded validation
task if it is needed. It must not be inferred from the canonical workload run.

The next hardening implementation should not combine exact leaf authorization,
high-page copy, lifecycle containment, and fork. The unresolved choices remain:

1. enforce exact leaf-slot authorization and a fail-closed non-sharing baseline;
2. validate high-page copy inputs, then separately bind and cancel pending copy;
3. quarantine retired data/root/PTP pages until trusted revocation, zeroing, and
   safe reuse are defined; and
4. design fork/sharing authority only after the non-sharing and containment
   decisions converge.

This record does not select or dispatch a next machine owner. The first bounded
patch closes four local control-plane and ordering gaps, but it does not
establish complete malicious-Linux-safe memory lifecycle handling. Runtime
evidence proves build and canonical compatibility, while the new negative
guards and exact teardown ordering remain source-reviewed properties.

## 10. Proposed Next Small-Step Discussion

Status: human-held planning checkpoint. This section does not authorize a new
task packet, Coder handoff, or implementation.

### 10.1 Recommended theme

The next discussion should focus on the **exact leaf-authorization baseline**:
how the Monitor can prove that a caller-supplied PTE slot is the one reached by
the claimed trusted root, virtual address, and page-table level.

This is the recommended next dependency because disabling the raw PFN FIDs
removed one direct mutation interface, but the generic PTE-update path still
has broad authority. A trustworthy root/VA-to-slot relation is also needed
before high-page copy can be bound to its real source mapping or an existing
private PFN alias can be distinguished from an unrelated mapping request.

The desired tone is deliberately conservative:

- discuss and record the contract before changing code;
- start with base-page resident leaf operations, not every page-table level and
  lifecycle at once;
- require rejection to be deterministic and free of bitmap, refcount, PTE, and
  semantic-state side effects;
- preserve the existing trusted-Agent and checked `acall`/`aret` model; and
- make only the relationship claim actually established by the resulting
  checks.

### 10.2 First discussion deliverable

The next planning turn should produce a compact design decision, not a patch.
It should:

1. enumerate the leaf insertion, removal, replacement, and permission-update
   entry points and state which arguments currently identify root, VA, level,
   expected old PTE, and physical PTE slot;
2. define a non-allocating Monitor walk, or identify the minimum missing trusted
   metadata if the current tree cannot safely derive the exact slot;
3. classify fresh `NORMAL` mapping, same-slot/same-PFN permission change,
   removal, and already-`PRIVATE_DATA` alias as separate operation shapes;
4. state which base-page operations can be supported immediately and which
   must fail closed; and
5. record the honest compatibility impact, especially the currently passing
   protected-fork path, before selecting an implementation boundary.

### 10.3 Open semantic questions for human discussion

These choices must remain explicit rather than being frozen by an implementer:

1. May the first non-sharing baseline make protected fork fail explicitly until
   a trusted fork grant exists, or must honest fork compatibility be preserved
   by the very next implementation?
2. Should the first exact-slot packet cover only base-page leaf APIs, leaving
   parent PTP population/removal and accessed-bit shortcuts for separate
   slices?
3. Must a mutable root be the currently attached root, or are authenticated
   non-current-root worker operations required now?
4. Can a read-only walk over the existing Secure-PTP tree establish sufficient
   reachability for this slice, or is minimal Monitor-owned PTP owner/level
   metadata a prerequisite?

### 10.4 Hard boundary for the next discussion

Do not combine this decision with high-page copy implementation, pending-copy
cancellation, last-reference publication, root/PTP retirement, generations,
fork grants, shared memory, or a complete malicious-Linux-safe lifecycle. High
page copy remains security-relevant, but its root/VA/source binding should be
planned after this relationship contract is understood.

The stop condition is a human-reviewed contract with the questions above either
resolved or explicitly conditional. Only after that checkpoint should a new,
small execution packet be created and its exact machine owner approved.

## 11. Human Discussion Reconciliation: Exact Leaf Authorization

Date: 2026-07-16

Status: discussion recorded; no implementation, task-packet update, or machine
handoff is authorized by this section

Continuation Mode: manual

This section records the human discussion that followed Section 10. It narrows
several earlier questions, but it does not yet constitute an implementation
route. Where this section distinguishes a decided boundary from an unresolved
mechanism, an implementer must preserve that distinction.

### 11.1 Exact leaf-slot relation is required, with bounded cost

For a base-page resident leaf operation, the Monitor must not treat
caller-supplied `ptep_pa` as an independent write capability. The intended
authority is the registered root plus virtual address; `ptep_pa` is at most a
location hint whose claimed relation must be checked.

The accepted structural rule is:

```text
validated_leaf_slot(registered_root, virtual_address) == ptep_pa
```

The walk should be non-allocating and bounded to the Sv39 levels needed to
derive the L0 slot. Unsupported huge leaves must not be partially interpreted
as base-page leaves.

The performance decision is:

- perform the check only on mediated page-table mutations, not on ordinary
  memory accesses;
- do not introduce a persistent cross-call page-table-walk cache;
- minimize repeated work within one call or batch where this does not create
  cached authority; and
- keep rejection before bitmap, refcount, PTE, or semantic-state mutation.

The BlackBox and RContainer comparison did not provide evidence that this
binding is unnecessary. Their papers expose high-level `set_pt` or
`rc_set_pte` operations but do not publish the exact prototype or enough source
to establish whether an arbitrary caller-selected PTE pointer is accepted.
Both designs place mapping validation and the actual protected page-table
update in a trusted CSM or mini-OS and maintain additional mapping/ownership
state. Therefore their interface names are not evidence that NaCC may safely
accept independent root, VA, and PTE-slot claims without binding them.

Primary references discussed:

- BlackBox: <https://www.usenix.org/system/files/osdi22-vant-hof.pdf>
- RContainer: <https://www.ndss-symposium.org/wp-content/uploads/2025-328-paper.pdf>

### 11.2 The existing SBI operation is level-polymorphic

The current `SET_PTES` shape does not state whether the target is an L0 leaf,
a parent entry that links another PTP, or a supported huge leaf. This is a real
contract ambiguity, not a reason to replace Linux's generic MM APIs.

In particular, the current NaCC `pmd_populate()` path uses the same SBI
operation to link a child PTE page and supplies `start_va = 0`. A blanket rule
that interprets every `SET_PTES` request as an L0 leaf update would therefore
reject honest parent-PTP construction or validate the wrong semantic object.

The accepted direction is a controlled split:

- preserve Linux's standard `set_pte_at()` / `set_ptes()`-style interfaces;
- narrow the NaCC base-page leaf operation to an explicit L0-leaf contract;
- route parent-PTP linking/unlinking through a distinct operation contract;
- classify huge PMD/PUD leaves separately and either validate them under a
  later contract or fail them explicitly; and
- treat any caller-supplied level or operation kind as declared intent, not as
  trusted proof. The Monitor must still verify the selected structural rule.

The exact ABI choice remains open. A new FID, an operation-kind argument, or
another bounded architecture-level dispatch may be considered later. The
expected Linux change is concentrated in the RISC-V/NaCC wrappers rather than
a rewrite of generic Linux MM call sites.

### 11.3 Registered-root validity is required; `satp` is not authority

The root used for the exact walk must already have a valid Monitor-owned
`ROOT_L0` record and must be in the legal lifecycle state for the requested
operation. A caller-supplied physical page that has not been registered as a
root is not acceptable.

`SATP_PA(csr_read(CSR_SATP))` must not be treated as the security authority for
this decision. S-mode Linux can select `satp`, so equality with the current
`satp` value is only a consistency observation and does not prove permission.

The first exact-slot slice will not require a proof that the root is the one
exact process root currently selected by Linux. Under the present model the
physical caller of these SBI operations is the same globally untrusted Linux,
and a current-root check does not prevent that Linux from requesting a harmful
operation once the selected root is current. The first slice therefore makes
an object-validity claim, not a complete actor-to-root authorization claim:

> the named root is Monitor-registered, and the named slot is exactly the L0
> slot reached from that root and VA.

Whether a particular operation additionally requires the root's `ATTACHED`
state must be decided when the supported operation shapes are finalized;
pre-attach construction must not be accidentally described as a resident-leaf
operation.

Trusted CID matching remains a possible intermediate guard because the NaCC
trusted state and root record both carry a CID. Exact process-to-root authority,
non-current-root workers, and child-root authority are deferred. If those
claims are later required, the Agent may identify policy intent, but the
Monitor must own and enforce the resulting authorization record; Linux cannot
be allowed to self-authorize by choosing a root or `satp` value.

### 11.4 Fresh-page rule and default non-sharing

The intended default remains no sharing. Fork is treated as an exceptional,
later feature rather than as a compatibility requirement that weakens the
first baseline.

For an empty-slot insertion of a newly allocated data page, the accepted rule
is:

1. the destination PFN must currently be `NORMAL` and have no private
   reference;
2. after all non-mutating request and exact-slot checks pass, the existing
   bitmap lock must cover one checked transition from `NORMAL` with refcount
   zero to `PRIVATE_DATA` with the intended first reference;
3. after that tag transition has revoked untrusted Linux access, M-mode clears
   the page to zero; and
4. only then may the Monitor publish the protected leaf.

A Linux assertion that a page is empty is not sufficient under the malicious
Linux threat model. The simplest safe interpretation is trusted clearing;
whether that clearing is performed directly by the Monitor or established by
another trusted allocation path remains an explicit implementation choice.
Checking or clearing while the PFN remains freely writable as `NORMAL` is not
sufficient, because Linux could race the check or rewrite the page before PTE
publication. No additional pending tag or long-lived page-state transaction is
required for this fresh-insertion shape: `PRIVATE_DATA` itself can protect the
zeroing interval. The current QEMU bitmap write path publishes the new tag and
synchronously flushes cached physical aliases for each changed PFN, so this
ordering can revoke pre-existing Linux translations before M-mode clears the
page.

This simplification does not mean that the tag transition may be implemented
as an unlocked check followed by a later write. The existing bitmap lock is
still needed to make `NORMAL/refcount-zero` validation and the first private
claim one indivisible metadata transition; otherwise two concurrent requests
could both claim the same fresh PFN. That claim is the only atomic boundary
selected here. The discussion does not require the entire claim, trusted
zeroing, and PTE publication sequence to be one long atomic transaction or to
hold the bitmap lock throughout. Once the claim has installed `PRIVATE_DATA`,
untrusted Linux access is denied; once M-mode zeroing completes, the page no
longer contains prior contents, so PTE publication may be a later step.

All non-mutating checks that can reject the request should still run before the
claim. If publication then definitely does not occur, the trusted-zeroed page
has no confidential contents and may either remain private for retry or be
returned to `NORMAL`. If a leaf was published, or publication outcome is
ambiguous, the PFN must not be returned to `NORMAL` until that mapping has been
securely detached under the separately defined removal lifecycle.

Requiring a fresh mapping PFN to be `NORMAL` is itself the first-slice
enforcement of default non-sharing: an existing `PRIVATE_DATA` PFN is not a
fresh page and must not be accepted through this path. No separate sharing
graph, cross-root sharing relationship, or general alias mechanism is required
in this slice. This must not be misread as permission to accept an already
private PFN without checking its tag.

The fresh-insertion reasoning does not automatically authorize every other PTE
shape:

- a same-slot/same-PFN permission update operates on an existing private page
  and needs its own rule without a refcount change;
- replacement and removal interact with last-reference quarantine, trusted
  zeroing, and reuse, and cannot be justified by saying that the incoming page
  is fresh; and
- arbitrary permission changes may be an integrity-policy question even when
  they do not create sharing.

Those operation shapes remain to be classified before an execution packet is
written.

### 11.5 Deferred fork and precise security claim

Protected fork, clone, and deliberate sharing are deferred. Until the future
authority exists, an operation that would require mapping an existing private
PFN into another root must fail explicitly rather than silently create an
undeclared alias.

The intended future split is:

- the trusted Agent recognizes fork/clone or another declared sharing intent
  and requests a bounded authorization; and
- the Monitor records, binds, consumes, and cancels that authorization so that
  a malicious Linux SBI caller cannot fabricate it.

The current discussion authorizes only the following narrow future claim:

> For a supported base-page operation, the Monitor acts on a valid registered
> root and the exact L0 slot derived from the declared VA. A fresh insertion
> accepts only a trusted-zeroed `NORMAL` PFN. Existing private PFNs are not
> implicitly shareable.

It does not yet claim complete mapping integrity, safe last-reference reuse,
fork compatibility, parent-PTP authorization, huge-page support, or complete
malicious-Linux-safe lifecycle handling.

### 11.6 Intermediate-PTP reachability and reclaim boundary

The discussion does not make a complete per-PTP owner, level, and liveness
table a prerequisite for the first exact-leaf slice. It now does, however,
bring malicious early PTP reclaim into the follow-up design scope rather than
relying only on an honest Linux unlink-before-reclaim convention.

Let parent PTP X contain the non-leaf entry that points to child PTP Y. The
important distinction is between protecting the contents of a live PTP and
protecting its lifetime identity. While Y remains live, an old translation or
page-walk-cache reference still names the same page-table object. Once Y is
returned to the freelist and reused by another root, that same physical address
may name a different security object. Making Y unwritable by Linux does not
invalidate the old hardware reference or bind Y to one root. If Y were cleared
and quarantined forever, the stale-reference case would reduce to availability;
the confidentiality/integrity risk begins when Y becomes reusable.

The agreed high-level reclaim order is:

1. The Monitor observes the parent unlink itself. It reads the old exact slot
   in X, verifies that it is the expected non-leaf entry pointing to Y, and
   clears that slot. Merely observing that an arbitrary slot is already zero
   does not prove that caller-supplied Y was formerly attached there.
2. Y may enter a pending reclaim batch, but it is not yet placed on the
   reusable secure-PTP freelist.
3. When the batch is drained, the Monitor performs one synchronous TLB
   invalidation for the entire batch and waits for completion on every hart
   that could retain a relevant translation or page-walk-cache entry. A first
   conservative implementation may cover all harts. A local-only
   `sfence.vma` is not sufficient.
4. Only after that batch-level invalidation completes may the Monitor clear Y
   and pass it to `sec_mem_free()` for reuse.

This is one Monitor-enforced invalidation per reclaim batch, not one
invalidation per PTP page. The existing Linux `tlb_finish_mmu()` invalidation
may therefore remain useful for normal Linux semantics, but the first secure
design does not treat Linux call ordering as proof that the invalidation
happened: a malicious Linux kernel can call the public reclaim FID early, and a
local S-mode `sfence.vma` is not observable by the Monitor. Reusing an existing
invalidation as a trusted commit can be considered later as an optimization;
the bounded conservative route accepts one Monitor-controlled invalidation at
batch drain.

The batch invalidation does not replace unlink authorization. If X still points
to Y, invalidation only causes a later page walk to rediscover the same edge.
Conversely, unlink authorization alone does not make immediate reuse safe
because hardware may retain the old translation until invalidation. Both
conditions are required before freelist publication.

No separate `DETACHED` bitmap state is selected by this discussion. The exact
trusted representation that binds each queued Y to a Monitor-observed unlink
remains open; the current caller-owned raw PFN array is not, by itself, such
evidence. That mechanism must also prevent duplicate reclaim and unsafe relink
before reuse, without silently expanding this decision into a complete PTP
ownership graph.

### 11.7 First-stage same-PFN permission expansion and `mprotect`

This decision assumes that the previously selected fresh-insertion rule is in
force: an empty-slot insertion accepts only `NORMAL/refcount-zero`, and an
already `PRIVATE_DATA` PFN cannot enter another protected mapping through the
ordinary insertion path. Cross-root sharing and fork grants remain separate,
later features and are not reopened by this permission discussion.

The PFN bitmap and the PTE permission contract have deliberately different
roles. The current two-bit PFN tag represents `NORMAL`, `ROOT_L0`,
`PRIVATE_DATA`, or `PRIVATE_COPY_PENDING`; private refcounts and root
`CID/ATTACHED` records are stored separately. It does not encode VA or
R/W/X/U/G permissions. For a same-slot/same-PFN operation, the bitmap tag and
private refcount must remain unchanged. The first-stage permission policy only
prevents an untrusted Linux kernel from adding access that the protected caller
did not request.

The first-stage policy is:

- a registered root, exact base-page L0 slot, resident ordinary private leaf,
  and unchanged PFN are mandatory;
- PPN, V, U, G, the Monitor-owned NACC marker, special/devmap state, memory
  type, NAPOT, and reserved bits cannot be changed by this operation; ordinary
  private user leaves keep `U` unchanged and `G` clear;
- narrow A/D maintenance and removal of existing R/W/X permissions need no
  trusted permission grant; malicious use is treated as housekeeping damage or
  denial of service for this bounded claim; and
- any R/W/X bit that changes from zero to one requires a matching trusted
  permission-expansion grant.

For a protected U-mode `mprotect(start, len, prot)` trap, the Agent observes the
original syscall number and arguments before delegating to Linux. It creates a
short-lived Monitor grant before `acall`, binding at least the trusted CID,
registered root, page-aligned VA range, normalized final R/W/X ceiling, and a
grant generation. The Agent then delegates the syscall normally so Linux can
retain responsibility for VMA validation, splitting/merging, locking, and
nonresident-page bookkeeping.

There is no Agent callback for each PTE. While Linux handles the syscall, each
secure PTE change goes directly to the Monitor. For an expansion, the Monitor
requires the exact slot and same live PFN, checks that the VA is covered by the
active grant, and requires the final new R/W/X set to be a subset of the
grant's target permissions. Checking only the newly added bits is insufficient:
for example, an old `RW` mapping and a requested `RX` result must not permit
Linux to retain W and publish `RWX`. A W addition also remains subject to the
default non-sharing invariant.

The actual same-PFN change must be one Monitor transaction. The current generic
clear-then-reinstall shape must not transiently retire the private reference or
change `PRIVATE_DATA` to `NORMAL`; the Monitor reads the live old leaf,
preserves concurrent hardware A/D state as required, validates the grant, and
publishes only the allowed flag change without bitmap or refcount mutation.
Unsupported generic clear/reinstall paths fail closed rather than being treated
as a safe same-PFN update.

The selected first-stage Linux integration keeps Linux responsible for the
`mprotect` VMA operation but does not use Linux's default clear/reinstall PTE
transaction for a protected ordinary private leaf. The NaCC/RISC-V
modify-protection start path takes a snapshot without clearing the secure slot;
the matching commit path makes one Monitor call that validates and atomically
publishes the same-PFN flag change. Non-NaCC mappings continue to use the normal
Linux transaction. This override is limited to resident base-page ordinary
private leaves with unchanged PPN/V/U/G/NACC and does not silently absorb
`PROT_NONE`, removal, replacement, huge-leaf, special-mapping, or parent-PTP
semantics.

When Linux returns through `aret`, the Agent ends or cancels the grant regardless
of the reported syscall result. A Linux kernel that never returns cannot use
the grant outside its bound root, range, operation shape, or final permission
ceiling; it can only retain a bounded authorized window while preventing the
protected caller from continuing, which is an availability failure. No
mid-syscall transition back to the Agent is required.

This first stage covers only resident base-page same-PFN expansions committed
during that `mprotect` delegation. It does not authorize a later write fault to
restore W after the syscall grant has closed, a permission change for a
nonresident page, NUMA `PROT_NONE` restoration, UFFD write-protect resolution,
kernel-origin fault/GUP/KSM expansion, huge leaves, or fork/COW sharing.
Supporting delayed expansion requires a later persistent trusted permission
ceiling or another explicitly authorized fault protocol.

The bounded consequence of rejecting such a delayed W restoration is limited
under the bitmap protection assumed here: the PFN remains `PRIVATE_DATA`, Linux
does not gain direct access, and the leaf remains read-only, so the protected
task may fault, fail, or be terminated. That is a compatibility/availability
limitation, not publication of private contents. This statement does not excuse
the clear/reinstall `PRIVATE_DATA -> NORMAL -> PRIVATE_DATA` window; eliminating
that window is a confidentiality prerequisite even when permission reductions
otherwise remain outside the first-stage policy.

For an expansion, a stale translation contains no more permission than the new
leaf, so failing to invalidate it can at worst retain a restrictive translation
and cause an extra fault. The first-stage expansion claim therefore does not add
a Monitor-owned TLB flush. Permission revocation and its trusted invalidation
semantics remain outside this narrow expansion-only claim.

This decision uses the existing design assumption that the Agent-observed
protected trap-entry snapshot is the trusted intent source. It does not expand
the present claim into complete protected return-frame or control-flow
integrity.

### 11.8 Remaining planning questions

Before a task packet or Coder handoff, the remaining discussion must still
settle:

1. the exact trusted zeroing mechanism and its ordering relative to tag,
   refcount, and PTE publication, including the bounded pre-publication
   rollback rule;
2. which removal and replacement operations belong in the first executable
   slice, and the exact narrow A/D and permission-reduction operations retained
   beside the expansion contract above;
3. the concrete leaf-versus-parent SBI split and honest compatibility impact;
4. whether the selected resident-leaf operations require `ATTACHED`, and
   whether a trusted CID equality check is required now;
5. batch preflight and serialization requirements needed for side-effect-free,
   race-safe rejection;
6. the concrete trusted binding between a Monitor-observed parent unlink and a
   queued PTP PFN, including duplicate-reclaim/relink prevention and the exact
   hart coverage of the one batch-level Monitor flush;
7. the exact Agent begin/end grant ABI, permission normalization, concurrency
   boundary, and deterministic failure behavior for delayed/nonresident
   expansion; and
8. which unsupported fork, huge-page, worker, and lifecycle paths must fail
   explicitly.

No machine next owner is selected. Human approval is still required before
turning these decisions into a task packet or implementation handoff.

### 11.9 First execution slice selected after human review

The human selected small-step implementation and authorized preparation of the
first execution packet. The packet is
`docs/workflow/tasks/active/TASK_20260716_003236_harden_step2.md`. This selection
was followed by explicit manual approval to hand the bounded packet to the
Coder; `Continuation Mode: manual` and all listed stop conditions remain in
force.

The first execution slice is narrower than the complete set of Section 11
decisions. It covers only direct caller-mediated L0 writes whose old or
requested value is a resident 4 KiB leaf:

- require a valid Monitor-registered root and a non-allocating Sv39 walk whose
  derived L0 slot equals the supplied `ptep_pa`;
- keep structural preflight pure and side-effect free, and keep the validated
  root/path/slot relation valid through the corresponding write;
- separate the existing parent-PTP population request shape so
  `pmd_populate(..., start_va = 0, ...)` is not misinterpreted as a base-page
  leaf operation; and
- make only the direct-L0-write claim. A structurally accepted parent relink
  can still redirect reachability to another Secure PTP because parent owner,
  level, and reachability authorization remain deferred.

This slice requires only a valid registered root record. It does not use
`satp` as authority and does not add an `ATTACHED` or actor-to-root gate, so
registered pre-attach construction remains compatible. The existing Secure-PTP
range/tag predicate is sufficient for the bounded walk; no new per-PTP owner,
level, generation, or liveness table is introduced.

The fresh-page rule, private-PFN alias rejection, atomic same-PFN `mprotect`,
Agent permission grants, data-page removal/replacement, PTP reclaim hardening,
fork authorization, and huge-page support are not part of this first packet.
In particular, canonical workload 3 exercises the current protected-fork
compatibility path. Requiring workload 1-8 to remain green means this packet
must temporarily preserve the current private-PFN alias/refcount behavior; its
success is compatibility evidence and not a fork-security claim.

The acceptance gate combines focused negative evidence for an unregistered
root and a registered-root/VA request paired with the wrong Secure-PTP slot,
affected-component builds, Reviewer verification of the narrowed security
claim, and the canonical workload 1-8 batch with eight `status=ok` results and
guest exit code zero.
