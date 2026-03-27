# NaCC Knowledge Base

Purpose:

- preserve facts that have already been validated repeatedly
- reduce repeated mistakes across long debugging cycles

Update rule:

- keep only stable conclusions here
- keep speculative ideas in `record/*.md`

## 1. State Layers Must Be Distinguished

NaCC does not have a single state machine. It has multiple layers.

### 1.1 Linux semantic state

Primary software-side task state currently includes:

- `NACC_PREPARE = 0b001`
- `NACC_INITED = 0b010`
- `NACC_RECLAIM = 0b100`
- `NACC_FORKED = 0b1000`
- `NACC_REEXEC = 0b10000`

Typical historical flow:

```text
NORMAL -> PREPARE -> INITED
INITED --(same PID exec)--> REEXEC -> INITED
INITED --(fork child)--> child:FORKED --(child exec)--> INITED
INITED --(exit/exec teardown)--> RECLAIM
```

This layer expresses Linux-side task semantics, not trusted trap continuation.

### 1.2 Hart-local runtime state

`CSR_NACC_STATE` currently carries values such as:

- `INACTIVE`
- `AGENT`
- `LINUX`
- `MONITOR`

Important constraint:

- `aret` is meaningful only when `nacc_state == LINUX`
- otherwise QEMU prints:
  - `Not in nacc process linux state. Simply omit it.`

### 1.3 Newer design conclusion: runtime context must be layered further

The newer accepted direction is:

- `CSR_NACC_STATE` should not be treated as a full process-state register
- it should be treated as a hart-local runtime mode register
- multi-process support likely requires:
  - per-hart loaded runtime state
  - per-thread secure runtime context
  - per-mm secure address-space state
  - Linux semantic state

This matters because trusted first landing, delegation to Linux, and return-to-agent behavior cannot be modeled safely with only a mode bit plus `cid`.

## 2. Stable Invariants

1. If an `mm` owns secure NaCC page-table pages, teardown must respect the correct reclaim semantics before destruction.
2. `INITED` should only be set after the relevant re-attach / runtime handoff has succeeded.
3. `nacc_flag` is a bitmask and should not be treated as a simple enum with `==` checks on mixed states.

### 2.1 Do not keep mixing task semantic state and `mm` reclaim state

One stable lesson from fork debugging:

- `thread.nacc_flag` is better suited to task execution phase
- `mm` reclaim / teardown policy should not continue to depend solely on `thread.nacc_flag`

Why:

- `exit_mmap()`, `unmap_page_range()`, and `free_pgtables()` are `mm` / `VMA` lifetime logic
- if reclaim policy depends only on the current task flag, one missed state transition can mis-handle the entire address space

Preferred layering:

- task-side execution state
- mm-side secure address-space / reclaim state

## 3. Meaning Of Frequent Warnings

### 3.1 `BUG: Bad rss-counter state`

Trigger point:

- `check_mm()` near the end of `__mmdrop()`

Meaning:

- `rss_stat` does not match real mappings

High-probability NaCC interpretation:

- Linux accounting for child mappings was skipped or not restored correctly
- but mappings still existed and later teardown tried to subtract accounting that was never added

### 3.2 `BUG: Bad page state in process ... pfn:xxxxx`

Trigger point:

- `free_pages_prepare()` detects inconsistent `struct page` metadata before returning pages to the buddy allocator

Meaning:

- page metadata such as mapcount, refcount, mapping, or flags is inconsistent

Common NaCC interpretations:

1. a PFN inside the NaCC PTP range was released through an ordinary path
2. a normal data page lost Linux metadata consistency after a special fork / teardown path

## 4. Useful Command-To-Scenario Mapping

These commands are still useful as scenario anchors.

### 4.1 Direct execution, shortest path

```bash
docker run --security-opt seccomp=unconfined --rm busybox echo test
```

Use for:

- shortest registration / initialization / exit path

Suggested log tag:

- `smoke_echo`

### 4.2 Minimal same-pid reexec

```bash
docker run --security-opt seccomp=unconfined --rm busybox sh -c "cat /tmp/test.txt"
```

Use for:

- single external command under `sh -c`
- BusyBox often takes a same-pid reexec path here

Suggested log tag:

- `reexec_cat_only`

### 4.3 Reexec with builtin plus external command

```bash
docker run --security-opt seccomp=unconfined --rm busybox sh -c "echo hello > /tmp/test.txt && cat /tmp/test.txt"
```

Use for:

- observing the transition between builtin execution and an external command in one shell script

Suggested log tag:

- `reexec_builtin_plus_cat`

### 4.4 Builtin-only control group

```bash
docker run --security-opt seccomp=unconfined --rm busybox sh -c 'echo hello; echo b; echo c'
```

Use for:

- low-variance shell-only control
- usually no fork and no reexec

Suggested log tag:

- `builtin_only`

### 4.5 Fork+exec key scenario

```bash
docker run --security-opt seccomp=unconfined --rm busybox sh -c "cat /etc/hostname; echo done"
```

Use for:

- a parent shell that must continue after running an external command
- one of the most important current fork+exec probes

Suggested log tag:

- `fork_exec_cat_then_echo`

## 5. Code Entrypoint Shortlist

### Linux

- `linux/fs/exec.c`
  - exec flag transitions
  - `bprm_execve` tail
- `linux/kernel/fork.c`
  - `dup_mmap`
- `linux/arch/riscv/kernel/process.c`
  - `copy_thread`
- `linux/mm/memory.c`
  - `unmap_page_range`
  - `zap_pte_range`
  - `free_pte_range`
- `linux/kernel/exit.c`
  - exit / reclaim entry
- `linux/arch/riscv/kernel/traps.c`
  - user ecall, page fault, irq, and aret-related trap flow

### OpenSBI / QEMU

- `opensbi/lib/sbi/sm/sm.c`
  - attach / exec / switch-side runtime updates
- `opensbi/lib/sbi/sm/vm.c`
  - secure page-table behavior in earlier fork paths
- `qemu/target/riscv/op_helper.c`
  - `helper_aret`
  - `helper_acall`

## 6. Agent Initialization Versus Trap Proxying

One common confusion:

- "agent booted once" is not the same as
- "every later protected user trap still first lands in agent"

### 6.1 Full initialization chain

Entry chain:

- OpenSBI `agent_prepare(...)`
- agent `_entry`
- agent `main()`
- `vm_init()`

What the full initialization chain does:

1. OpenSBI passes Linux-side anchors such as:
   - `_user_pt_regs`
   - `_do_irq`
   - `_excp_vect_table`
   - `_current_gp`
   - plus page-table switch data
2. agent `_entry` stores those values and enters `main()`
3. `main()` runs `mem_init()` and `vm_init()`
4. `vm_init()` prepares the agent page-table view and temporary mappings
5. `trap_init()` installs later trap-proxy entry points
6. `__agent_exit(_user_pt_regs)` performs the first return to user space

Conclusion:

- `agent_prepare -> _entry -> main -> vm_init` is the heavy full initialization path
- it should not be re-run by default for every same-pid reexec-like event

### 6.2 Trap proxy chain

The long-term security-critical part is the trap proxy chain:

- `trap_init()` in `agent/src/trap.c`
- `__trap_entry` in `agent/src/entry.S`
- `__ret_from_exception` / `__agent_exit` in `agent/src/entry.S`

Semantic summary:

1. `trap_init()` allocates `_user_context` and writes `CSR_TWIN_ENTRY = __trap_entry`
2. later user traps first enter `__trap_entry`
3. `__trap_entry`:
   - swaps `tp` with `CSR_SSCRATCH`
   - relies on Linux kernel `tp` already being stored in `sscratch`
   - saves user registers into the agent-private `_user_context`
   - copies them into Linux-visible `pt_regs`
   - dispatches back into Linux through `_do_irq` or `_excp_vect_table`
4. Linux returns through `__ret_from_exception`, which restores the user-facing state
5. the first return from agent to user space goes through `__agent_exit(_user_pt_regs)`

Conclusion:

- the real secure copy of user context is agent-private `_user_context`
- Linux-visible `pt_regs` is a copied view
- the `sscratch/tp` contract is critical

### 6.3 Direct implication for same-pid reexec and multi-process runtime work

Stable judgment:

1. many same-pid reexec failures look more like broken trap-entry / trap-exit continuation than missing full agent initialization
2. reexec still likely needs lightweight refresh of:
   - agent-region mapping in the new `mm`
   - current `_user_pt_regs`
   - correct `sscratch/tp` semantics for the next user return
3. `_do_irq`, `_excp_vect_table`, and `_current_gp` are more like static Linux-side trap-shim anchors than the primary source of semantic change

Current design tendency:

- `NACC_REEXEC` should not simply reuse `nacc_invoke_child()`
- it should not collapse into "run full agent init again"
- a lighter refresh path is preferable

## 7. Runtime-Context Direction

New accepted invariants:

1. `AGENT` is a transient hart execution mode, not a persistent process lifecycle state
2. scheduling a protected thread in must restore a full trusted runtime context
3. first landing of protected user traps must be enforced by hardware / monitor, not chosen by Linux

Practical implication:

- future work should likely introduce an OpenSBI-owned per-thread secure runtime context
- likely fields include:
  - `cid`
  - thread identity
  - `saved_nacc_sstatus`
  - `saved_resume_pc`
  - `user_pt_regs` anchor
  - trap-save anchor
  - delegation / return flags

## 8. Debugging Discipline

- Prefer state-transition-level logs over per-PTE log floods when possible.
- For each experiment, record:
  - the exact command
  - the scenario tag
  - the target assertion
