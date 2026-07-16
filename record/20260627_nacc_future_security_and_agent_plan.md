# 2026-06-27 NaCC Future Security And Agent Implementation Plan

## Purpose

This note defines the next implementation direction after the current single
container private-memory baseline.

Current NaCC is reasonably close to a single confidential container domain:
Linux keeps normal memory-management policy, secure page-table writes go through
OpenSBI, and private anonymous pages are tracked by monitor bitmap/refcount
state. This is a useful core, and it is close in spirit to the page-table
handoff/verification parts of BlackBox and RContainer.

However, it is not yet a full confidential-container isolation model. The
missing work is mainly around domain ownership, IPC/shared memory, cross-domain
sharing, and Agent concurrency/throughput.

This document is a forward implementation plan, not a claim about completed
support.

## Current Baseline

Implemented or partially implemented today:

- Secure page-table pages are monitor-owned; Linux updates them through SBI
  helpers instead of direct stores.
- Private anonymous leaf pages can be marked with `_PAGE_NACC`; OpenSBI converts
  that request into monitor-owned PFN bitmap state.
- The monitor has PFN tags for `NORMAL`, `ROOT_L0`, `PRIVATE_DATA`, and
  `PRIVATE_COPY_PENDING`.
- `ROOT_L0` records carry a `cid`, so the monitor can associate a root page
  table with a container id.
- `PRIVATE_DATA` has PFN-wide refcounting, which is enough for the current
  single-domain private anonymous page lifecycle.
- fork/COW/exit paths have enough NaCC-aware handling for the current container
  baseline.

Important current boundaries:

- Private leaf installation excludes `VM_SHARED`, `VM_MAYSHARE`, and
  file-backed VMAs. POSIX shm, SysV shm, memfd, tmpfs shared mappings, and
  general `MAP_SHARED` are therefore not protected as NaCC private shared
  objects.
- `PRIVATE_DATA` is not currently owner-tagged by `cid` or root id. The root
  page table has a container record, but the data PFN itself does not encode an
  owner domain.
- SBI PTE update validation checks secure page-table range and PTE shape, but it
  is not yet a complete authorization framework that proves the current PID/CID
  is allowed to update that PTE page or map that PFN.
- The Agent should be treated as a single-active runtime shim. It is not
  structurally safe for concurrent Agent entry on multiple harts because mutable
  runtime state and allocator state are global inside the shared Agent image.

## Target Security Model

The next phase should make the security model explicit:

1. A container is a protection domain.
2. A process belongs to exactly one active container domain while it is protected.
3. Secure page-table pages have an owner domain and, ideally, an owner root/mm.
4. Private data pages have an owner domain or a shared-object owner record.
5. PTE updates are authorized by monitor state, not by Linux VMA flags alone.
6. Sharing is denied by default unless a monitor-visible grant exists.
7. Intra-container isolation is not implied by container isolation. It must be a
   separate mode if we want it.

This is the main distinction from the current prototype: today `cid` is mostly
attached to roots and PID records; the future design should attach ownership to
the objects being mapped and modified.

## Gap Analysis Against BlackBox And RContainer

BlackBox and RContainer both treat the container as a monitor-visible protected
domain. They let the commodity OS perform much of the normal fork/exec and
memory-management work, but the trusted component verifies or takes ownership of
the resulting protected state.

NaCC already follows that direction for secure page-table updates and private
anonymous memory, but it still needs three larger pieces to be comparable as a
complete confidential container design:

- Container-domain authorization: every protected page-table page and private
  data page should be tied to a domain, and monitor entry points should validate
  the caller's domain before updating state.
- IPC/shared-memory semantics: container workloads use pipes, sockets, futexes,
  `shm_open`, SysV shm, memfd, and `MAP_SHARED`. Running such workloads is not
  the same as protecting their shared data.
- Concurrency model: modern containers have many threads/processes. The Agent
  path must either be explicitly serialized or redesigned around per-hart or
  per-task mutable state.

## Workstream A: Domain Ownership And Authorization

Goal: make it impossible for one container or stale process record to map,
modify, or retire another domain's protected pages.

Implementation steps:

1. Add monitor-side owner metadata for secure PTP pages.
   - Track `owner_cid`, `owner_root_pfn` or `owner_mm_id`, page-table level, and
     lifecycle state.
   - Populate this metadata when OpenSBI allocates a secure PTP page for Linux.
   - Retire it only through monitor-validated reclaim.

2. Add owner metadata for private data PFNs.
   - Minimal version: `owner_cid`, refcount, and state.
   - Better version: `owner_cid`, optional `shared_object_id`, per-root mapping
     count, permissions, and generation.
   - Keep the small PFN tag as a fast hardware/QEMU-facing class, but move rich
     ownership into protected metadata.

3. Strengthen all PTE update SBI calls.
   - Resolve caller PID to CID in monitor state.
   - Validate that the target PTE page is owned by that CID/root.
   - Validate that the mapped PFN is either normal and being acquired by this
     CID, already owned by this CID, or covered by an explicit share grant.
   - Reject cross-CID PTE updates by default.

4. Harden PID/CID lifecycle.
   - Prevent arbitrary user-chosen CID reuse unless a runtime authority token or
     monitor-created container handle exists.
   - Handle fork child registration, exec, unregister, and abnormal exit with
     generation checks.
   - Treat stale PID records as security-relevant, not only cleanup bugs.

Definition of done:

- A negative test where container A tries to map or retire a PFN owned by
  container B is denied by OpenSBI.
- A stale PID/CID record cannot authorize a PTE update after process exit and
  PID reuse.
- Final cleanup leaves no live PTP owner records, private PFN owner records, or
  root records for a completed container.

## Workstream B: Intra-Container Isolation

Goal: decide whether NaCC wants sub-container isolation. This should not be
claimed accidentally.

Two policy options:

1. Single trust domain per container.
   - All processes in the same container are mutually trusted.
   - The monitor prevents cross-container access, but not same-container process
     access.
   - This is the simplest model and matches many confidential container systems.

2. Compartments inside one container.
   - Add a subdomain id, process group id, or mm capability under the CID.
   - Private pages are owned by `(cid, subdomain)` instead of just `cid`.
   - Explicit same-container sharing grants are required.

Recommendation:

- Do not implement intra-container isolation implicitly.
- First document the current model as "single trust domain per container".
- Add subdomain support only if the paper or target workloads need it.

Definition of done if implemented:

- Two processes in the same container can be placed into different NaCC
  subdomains.
- Default cross-subdomain memory mapping is denied.
- A same-container grant can selectively allow read-only or read-write sharing.

## Workstream C: Shared Memory And IPC

Goal: turn IPC from "workloads can execute" into an explicit security design.

IPC categories:

- Byte-stream IPC: pipe, Unix domain socket, TCP loopback, socketpair.
- Kernel synchronization IPC: futex, robust futex, rseq interactions.
- Shared-memory IPC: POSIX shm, SysV shm, memfd, tmpfs, file-backed
  `MAP_SHARED`.
- Runtime/control IPC: runc init pipe, log pipe, pidfd/console socket,
  containerd/shim communication.

Security choices:

1. Byte-stream IPC can be treated as declassification/reclassification.
   - If Linux is outside the TCB, kernel pipe/socket buffers are not private.
   - The design must say whether data written to a pipe/socket is intentionally
     released to the OS path or copied through a trusted mediation path.

2. Shared-memory IPC needs a first-class object model.
   - Introduce a `shared_object_id` managed by the monitor.
   - A shared object has owner CID, allowed CID/subdomain set, permissions,
     refcount, and generation.
   - Mapping a shared object installs secure PTEs only if the caller has a grant.
   - Unmap/exit decrements monitor mapping counts.
   - Revoke requires PTE invalidation and TLB shootdown semantics; avoid
     promising revoke until this is designed.

3. Same-container shared memory can be a first milestone.
   - It is simpler than cross-container sharing.
   - It closes the most obvious gap for multi-process container workloads.

Suggested sequence:

1. Keep current private anonymous behavior unchanged.
2. Add explicit detection and accounting for shared-memory VMAs without marking
   them private yet.
3. Implement same-CID shared anonymous/shmem object support.
4. Add negative tests proving cross-CID shared mapping is denied.
5. Add explicit cross-CID grant/revoke only after same-CID shared objects are
   correct.

Definition of done:

- `shm_open + mmap(MAP_SHARED) + fork` is represented as a monitor-owned shared
  object, not an ordinary unprotected mapping.
- SysV shm and memfd paths either use the same object model or are explicitly
  rejected from protected mode.
- Cross-container shared memory is denied without a grant.
- A granted read-only mapping cannot be upgraded to writable by Linux alone.

## Workstream D: Container Isolation

Goal: make "container isolation" a complete claim instead of an emergent
property of private anonymous pages.

Required protected resources:

- Root page table and all secure PTP pages.
- Private anonymous PFNs.
- Monitor-owned shared-memory objects.
- Agent mapping and trampoline state.
- PID/CID/thread context records.
- Runtime authority to create, attach, fork, exec, and unregister protected
  tasks.

Implementation steps:

1. Define a container creation authority.
   - Prefer a monitor-created container handle or runtime token over trusting a
     raw user-provided CID.

2. Bind roots and PTP pages to the container handle.
   - `ROOT_L0` should not only record `cid`; PTE update paths should use that
     record for authorization.

3. Bind private PFNs and shared objects to the same domain model.

4. Make teardown auditable.
   - Container unregister should fail or warn if protected objects remain live.
   - Add a final monitor dump/check that distinguishes expected live global
     state from leaks.

Definition of done:

- Two NaCC containers can run concurrently with distinct CIDs.
- Each can fork/exec/exit without modifying the other's roots, PTP pages, or
  private PFNs.
- Cross-container attack tests fail closed.

## Workstream E: Kernel Data Paths Touching Private Memory

Goal: avoid an endless syscall-by-syscall repair strategy.

Known categories to audit:

- `copy_to_user`, `copy_from_user`, string usercopy.
- scalar `get_user` and `put_user`.
- futex atomics and robust-futex exit walk.
- rseq ABI maintenance.
- signal frame setup and restore.
- ptrace, `/proc/$pid/mem`, process_vm_readv/writev.
- coredump.
- GUP/pinning, DMA, and device passthrough.
- file-backed mmap and page cache.

Policy:

- Prefer centralized range/type mediation over one-off syscall patches.
- A Linux VMA flag can be a routing hint, but monitor ownership metadata must be
  the authority.
- If a path cannot be made safe, deny it or explicitly document it as outside
  protected mode.

Definition of done:

- A checklist exists for every kernel user-memory access family.
- Each family is classified as mediated, denied, declassified, or out of scope.
- Regression workloads cover at least shell pipeline, shm repro, LTP shm/mmap,
  futex microtests, signal frame, and coredump/ptrace negative tests.

## Workstream F: Agent Throughput And Multicore Safety

Goal: make Agent behavior correct and scalable enough for multi-process
containers, without requiring preemptive Agent execution.

Current issue:

- The Agent image is shared.
- Mutable Agent runtime values are global.
- The Agent stack, trap-save page, and allocator are effectively singleton.
- The allocator is explicitly lock-free.
- Existing notes correctly classify the current Agent as single-active, not
  multicore-safe.

Phase F0: make the current boundary explicit.

- Add a monitor-side serialization or detection boundary around Agent entry,
  reexec entry, first fork-child attach, and trap handoff.
- If serialization is used, make it visible in profiling so throughput loss is
  measurable.
- Save/restore or refresh hart-local CSR state used by the Agent, especially
  `CSR_TWIN_ENTRY`.

Phase F1: reduce unnecessary Agent work.

- Separate full Agent initialization from lightweight attach with reliable log
  markers and counters.
- Cache per-container or per-mm setup that does not need to run on every task.
- Batch repeated `agent_mmap` or secure mapping operations.
- Keep monitor-side metadata updates in OpenSBI when Agent execution is not
  needed.

Phase F2: introduce per-context Agent runtime state.

- Move `_satp`, `_user_pt_regs`, `_kernel_tp`, `_current_gp`, trap-save pointer,
  and handoff state into a context structure.
- Decide the context key: hart, task, PID, mm, CID, or `(hart, task)`.
- Add per-hart or per-task Agent stacks.
- Add per-hart or per-task trap-save pages.

Phase F3: make Agent allocation safe.

- Replace the singleton lock-free freelist with:
  - per-context arenas, or
  - a locked allocator, or
  - monitor-owned allocation with explicit mappings.
- Keep allocator correctness first; optimize after concurrency tests pass.

Phase F4: throughput validation.

- Measure entry/attach/reexec/trap counts and latency.
- Use small deterministic tests before Hackbench:
  - repeated container loop,
  - fork/exec loop,
  - pthread loop,
  - mmap/munmap loop,
  - shm repro loop.
- Then use Hackbench as a high-fanout diagnostic, not as the first correctness
  test.

Definition of done:

- Concurrent NaCC processes cannot corrupt Agent global state.
- The monitor can report whether Agent entry was serialized, parallel, or
  rejected.
- Multicore runs do not depend on accidental single-hart scheduling.
- Throughput bottlenecks are attributed to specific phases: container creation,
  Agent full init, lightweight attach, PTE update, usercopy mediation, or
  teardown.

## Suggested Milestones

### Milestone 1: State The Supported Model

- Document current support as single container trust domain, private anonymous
  memory protection, no secure IPC/shared-memory guarantee.
- Add explicit runtime warnings or debug counters when shared mappings appear in
  protected containers.

### Milestone 2: Owner Metadata MVP

- Add owner metadata for secure PTP pages and private data PFNs.
- Validate CID/root ownership in all PTE update paths.
- Add cross-container negative tests.

### Milestone 3: Same-CID Shared Memory MVP

- Introduce monitor-owned shared object records.
- Support POSIX shm or memfd first; do not try all shared memory APIs at once.
- Define read/write permissions and cleanup.

### Milestone 4: Container Isolation Hardening

- Replace raw CID trust with container handles/tokens.
- Harden fork/exec/unregister generation checks.
- Add stale PID and PID reuse negative tests.

### Milestone 5: Agent Correctness Boundary

- Add Agent entry serialization or per-context runtime state.
- Save/restore hart-local trap CSRs.
- Prove multicore safety before chasing throughput.

### Milestone 6: Agent Throughput

- Batch avoidable mappings/ecalls.
- Split full init from lightweight attach.
- Add per-context stacks/trap pages if serialization is too costly.
- Validate with lifecycle loops, then Hackbench.

## Workloads To Keep As Gates

Correctness gates:

- `busybox true`
- shell `fork + exec`
- shell pipeline
- `nacc_shm_repro`
- repeated fork/exec loop
- repeated mmap/munmap loop
- pthread loop
- LTP selected `mmap*`, `shmat*`, `shmctl*`, `shmdt*`, `shmget*`

Security negative gates:

- Cross-container PTE update denial.
- Cross-container private PFN mapping denial.
- Stale PID/CID denial after exit and PID reuse.
- Shared-memory mapping denied without grant.
- Read-only grant cannot become writable by Linux PTE update alone.

Performance/scale gates:

- lmbench syscall and pipe subset.
- repeated container startup.
- small Hackbench `-T -g 1..N` ramp.
- target Hackbench only after small ramps are stable.

## Non-Goals For The Next Phase

- Do not claim intra-container isolation unless subdomains are implemented.
- Do not claim secure cross-container sharing before grant/revoke exists.
- Do not treat pipe/socket execution as proof of secure IPC.
- Do not optimize Hackbench before Agent concurrency and attribution are clear.
- Do not patch every syscall independently; prefer monitor-owned metadata and
  central mediation points.
- Do not implement revocation for shared memory without a PTE invalidation and
  TLB shootdown story.

## Bottom Line

The current implementation is a solid single-container private-memory baseline.
The next security step is not another private-page special case; it is domain
ownership. Once PTP pages, private PFNs, and shared objects all carry
monitor-visible ownership, NaCC can make stronger claims about container
isolation and then add IPC and sharing intentionally.

The Agent should be treated as a separate but blocking scalability track. It is
acceptable to avoid preemptive Agent execution, but the implementation still
needs either explicit serialization or per-context mutable state before
multi-process and multi-container workloads can be considered robust.
