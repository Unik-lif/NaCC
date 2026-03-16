# Presentation: NaCC System Development Progress (Feb 17 - Mar 15, 2026)
**Subtitle**: Breakthrough — Securing the Core Container Lifecycle (execve & fork)
**Presenter**: [Your Name]
**Date**: March 16, 2026

---

## Slide 1: Introduction & Background
**Core Content**:
- **Recent Focus**: Elevating the functional ceiling of the NaCC system by addressing critical bugs in page management during multi-process and multi-stage lifecycle transitions.
- **Pain Points**: While basic containers (`docker run hello-world`) run successfully, deeper scenarios involving `fork` + `exec` and `re-exec` frequently triggered kernel crashes (e.g., `kmem_cache_free` Oops, `anoand.d` exceptions). These were caused by abnormal reads/writes or incorrect freeing of Page Table Pages (PTPs).
- **Architectural Principle**: "Lazy Coding Principle." Minimize modifications to the standard Linux kernel page table reclaim paths. Instead, delegate NaCC PTP interventions and data migrations to the higher-privilege M-mode (OpenSBI).

---

## Slide 2: Progressive Testing Strategy
**Core Content**: Establishing an 8-level testing plan based on increasing application complexity to pinpoint edge cases.
- **Level 0-1**: Basic lifecycle (e.g., `docker run hello-world`). [✔️ Completed]
- **Level 2**: Basic filesystem and I/O mem-mapping; validating basic Page Fault handling.
- **Level 3**: Multi-process scenarios, specifically `fork` + `exec` integration. [📌 Current Focus]
- **Level 4-8**: [Future Roadmap] High-volume page allocation, network namespaces, interactive long-running containers (e.g., Ubuntu base images), and concurrent container stress testing.

---

## Slide 3: Overcoming the First Hurdle — execve and PTP Reclaim Conflict (Phase 0)
**Core Content**: Analyzing and resolving system crashes when a process invokes `execve`.
- **The Issue**: When testing `sh -c "cat"`, Busybox attempts a `re-exec` optimization. During the new `execve`, Linux's `exit_mmap` clears the old address space. However, these PTPs were already moved to the secure memory managed by the NaCC Agent. The standard kernel clearing mechanism attempts to free these secure pages to the slab allocator, causing a fatal Oops.
- **The Solution**: Early in `begin_new_exec`, if the process is marked with `NACC_INITED`, we force the `NACC_RECLAIM` flag. This safely reuses the existing, dedicated NaCC secure page reclaim logic.
- **Result**: `execve` reclaim crashes are completely eliminated; processes can now complete their normal exit workflows.

---

## Slide 4: Facing the Hard Barrier — Native Fork Copy Failures
**Core Content**: How NaCC was intercepted by privilege boundaries during a real `sys_clone` (fork).
- **The Conflict**: During a Linux `fork`, the execution reaches `dup_mmap` -> `copy_page_range`. The kernel attempts to conventionally traverse and read the parent's PMD/PTE for duplication...
- **Privilege Block**: However, the parent's PTPs have already been moved to the M-Mode managed secure memory. A forced read from S-Mode immediately triggers a hardware-level `anoand.d` exception (crash).
- **A Failed Shortcut**: We previously attempted a hack by providing an "empty mm" to Linux during `dup_mmap` (assuming fork is always followed by exec). This was evaluated as a **CRITICAL risk** (if the child process executes even briefly before exec, e.g., due to a signal, a missing mm leads to total data corruption).

---

## Slide 5: The Breakthrough — OpenSBI Delegation (Phase 1)
**Core Content**: Embracing the separated privilege architecture: let the Right entity do the Right job.
- **The New Workflow**:
  1. **Linux Bypasses**: When `dup_mmap` encounters an `NACC_INITED` parent, it **skips** the default Linux per-VMA copy.
  2. **Switch to M-mode**: It initiates a proprietary ecall: `SBI_EXT_NACC_FORK(parent_pgd, child_pgd)`.
  3. **SBI Takes Control**: OpenSBI, operating in M-mode, safely traverses the parent's secure PTPs. It allocates a completely new set of secure PTPs for the child and precisely copies the entries.
  4. **Building COW (Copy-On-Write)**: Still in M-mode, OpenSBI conservatively applies write protection (wrprotect) to all writable user-leaf PTEs, laying the foundation for COW.
- **Key Advantages**: Zero complex kernel hack code, strong performance (optimized via a single batch ecall), and a closed-loop security semantic.

---

## Slide 6: State Machine Refactoring and the re-exec Dilemma
**Core Content**: Fixing trap corruption caused by mingling recovery mechanisms.
- **The Trap**: We initially tried to share the same recovery logic (`nacc_invoke_child`) for both a same-PID `re-exec` (e.g., sh->cat) and a genuinely forked `child`.
- **The Fallout**: In a re-exec, the PID remains the same, but the user-space image and mm have entirely changed. Reusing the old trap recovery led to corrupted critical context (like the `tp` register), causing the kernel to mistake user TLS for thread_info, resulting in a cascading Oops.
- **Restoring Order**: Strict conceptual separation was enforced.
  - A same-PID **`NACC_REEXEC`** must establish a completely new trap mechanism and refresh the host/agent trap context.
  - Only a genuinely branching **`NACC_FORKED`** (child process) can use `invoke_child`.
  - **The Strict Red Line**: Once an mm holds a secure PTP, it must pass through `RECLAIM` before destruction; and a process is only considered `INITED` when `CSR_NACC_STATE` is definitively set to `LINUX`.

---

## Slide 7: Phase Summary & Next Steps: Metadata Lifecycle!
**Core Content**:
- **Phase Milestone**: The system has successfully tackled the two most challenging architectural hurdles within the kernel—`execve` and `fork`—without compromising overall integrity. This clears the theoretical and structural path for running large-scale components like multi-process databases and web servers.
- **The Final Hurdle (Current Focus)**:
  - While OpenSBI now allocates new PTP trees for child processes and returns a physical list (`ptp_list`), back on the Linux side, this list is still detached from kernel semantics.
  - **Next Step**: Once Linux receives the `ptp_list`, it must formally integrate these pages by executing the standard `pagetable_pmd_ctor` functions and attaching the necessary ptlocks. This will complete the true lifecycle metadata mapping.
- **Looking Ahead**: Progressively targeting Level 5 - Level 8 tests, making isolated microservices running within the NaCC framework a reality!

---
**Appendix / Q&A Prep Material**:
- *Why not just intercept Page Faults and let them copy autonomously?* (A: Because the parent process's memory is inherently invisible during the fork phase.)
- *What is the granularity of the COW strategy?* (A: Initially, we apply a conservative wrprotect to all writable leaf nodes to simplify checks and prioritize security.)
