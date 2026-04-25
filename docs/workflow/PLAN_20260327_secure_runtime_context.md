# Secure Runtime Context Plan

## Problem

NaCC's multi-process challenge is no longer just a fork/exec semantic problem. It increasingly looks like an **incomplete trusted runtime-context model**.

Current intent:

- Linux still performs normal scheduling and most ordinary execution
- protected user traps should be forced to land in agent first, not in untrusted Linux
- agent may delegate selected work to Linux
- after Linux finishes, control should return to agent first, and agent should decide the final resume path

A single-process prototype can survive for a while with a few hart-local runtime fields. Once multiple protected processes or threads are involved, a `CSR_NACC_STATE`-style register that mainly carries `mode + cid` is no longer sufficient.

Stronger current judgment:

- `CSR_NACC_STATE` should not be treated as a process-state register
- the missing object is a **per-thread Secure Runtime Context**
- hard-to-explain non-converging cases such as `ld-linux` / `cat /etc/hostname; echo done` may come from runtime context and continuation not being saved / loaded correctly across multi-process execution

## Accepted Invariants

These three invariants are now accepted:

1. `AGENT` is a transient hart execution mode, not a persistent process lifecycle state.
2. Scheduling in a protected thread must restore a full trusted runtime context, not just a `cid` or a mode bit.
3. First landing of protected user traps must be enforced by hardware / monitor, not chosen by Linux.

## Layering

Future design should be understood in four layers instead of packing everything into one CSR meaning.

### 1. Per-Hart Loaded Runtime State

This layer answers:

- is a NaCC context currently loaded on this hart?
- which secure thread is this hart currently serving?
- is the hart currently executing `INACTIVE / LINUX / AGENT / MONITOR`?

This layer should stay small:

- `current_ctx` pointer or id
- `current_mode`
- fixed `TWIN_ENTRY`
- a small amount of per-hart cache

This layer should not carry lifecycle semantics such as:

- `FORKED`
- `EXEC`
- `RECLAIM`

### 2. Per-Thread Secure Runtime Context

This is the core object of the plan and should likely be owned by OpenSBI / monitor.

Suggested logical object:

`struct nacc_thread_ctx`

Minimum suggested fields:

- `valid`
- `tid` / `pid`
- `cid`
- `mm_identity` or an equivalent owner identifier
- `saved_nacc_sstatus`
- `saved_resume_pc`
- `user_pt_regs` anchor
- `agent_trap_ctx` or trap-save anchor
- `flags`
  - `delegated_to_linux`
  - `return_to_agent`
  - `in_agent`
  - `active`

Most important meaning:

- `saved_resume_pc` is continuation state and should not rely only on a hart-local `trampoline`
- `saved_nacc_sstatus` is thread-local runtime metadata
- "Linux must return to agent first" should also be represented by this context's flags / continuation rules

### 3. Per-MM Secure Address-Space Context

This layer manages the address space, not continuation.

It should keep things such as:

- `mm->context.nacc_state`
- secure pgd / secure page-table ownership
- reclaim / active / teardown status
- `VM_NACC`, agent aperture, and later bitmap-related address-space resources

### 4. Linux Semantic State

Linux-side semantic states remain software-side:

- `NACC_INITED`
- `NACC_FORKED`
- `NACC_EXEC`

These describe the Linux-side phase of a task and should no longer directly decide trap first landing.

## Key Design Decisions

### `CSR_NACC_STATE`

Its meaning should be narrowed:

- it is a **hart-local loaded mode register**
- it may keep:
  - current mode
  - current active `cid`
- it should not carry full process lifecycle semantics

### `TWIN_ENTRY`

Preferred direction:

- make it a **per-hart constant first-landing entry**
- all protected user traps first jump to the same agent trap stub
- do not make `TWIN_ENTRY` a frequently changing per-thread jump target

Why:

- first landing must be trusted
- first landing must not be stealable by Linux

### `trampoline` / `resume_pc`

Preferred direction:

- promote it from a CPU-local temporary value to a **per-thread continuation**
- it should not exist only inside the QEMU CPU env
- it needs clear thread ownership
- the hart should keep only the currently loaded copy

### `nacc_sstatus`

Preferred direction:

- move it into the **per-thread Secure Runtime Context**
- do not keep it as a loose CPU-global runtime field
- when multiple protected threads interleave, it must be saved and restored with the thread

## Scheduling Model

Current accepted scheduling principle:

- Linux keeps the normal scheduler
- no custom scheduler is introduced

But that does not mean Linux owns trusted continuation control.

Division of responsibilities:

- Linux decides **which task runs**
- OpenSBI decides **which trusted runtime context is loaded on this hart**

Therefore, a context-switch handoff should eventually support:

1. save the previous `nacc_thread_ctx` if the current hart is serving a protected thread
2. resolve `next task -> nacc_thread_ctx`
3. load the next `nacc_thread_ctx`
4. restore:
   - `CSR_NACC_STATE`
   - `saved_nacc_sstatus`
   - `saved_resume_pc`
   - fixed `TWIN_ENTRY`
5. if the next task is not protected, move the hart to `INACTIVE`

## Trap / Delegate / Return Model

The target chain is:

`user trap -> agent first landing -> agent decides -> optional Linux delegation -> return to agent -> agent decides final resume`

Implications:

- Linux should not be the first landing of a protected user trap
- Linux should not return freely to user mode after delegated handling
- the return target after Linux handling must remain under trusted continuation control

## Phased Plan

### Stage 0: Freeze the model

Freeze these conclusions in docs first:

- `AGENT` is only a transient hart mode
- `CSR_NACC_STATE` is not a process lifecycle state
- `nacc_thread_ctx` is the intended new runtime object

### Stage 1: Inventory runtime state

Inventory runtime state currently spread across layers:

- QEMU CPU env:
  - `nacc_state`
  - `nacc_sstatus`
  - `trampoline`
- OpenSBI:
  - `pid -> cid`
  - current hart switch logic
- agent:
  - `TWIN_ENTRY`
  - trap-save anchor
  - `user_pt_regs` anchor

Goal:

- identify which fields must become per-thread owned state
- identify which fields are only per-hart loaded cache

The current stage-1 role split and variable formalization are captured in:

- `docs/workflow/PLAN_20260328_stage1_runtime_roles.md`

The first coding round intentionally uses a reduced v0 model:

- per-`pid` `thread_ctx`
- no `mm_handle`
- no generation / epoch field yet

### Stage 2: Introduce `nacc_thread_ctx`

Create a minimum trusted object on the OpenSBI side:

- allocation / lookup / validation
- mapping from `task(pid/tid)` to `nacc_thread_ctx`
- `save_ctx()` / `load_ctx()` API

This stage does not require all trap details to be finished at once. First establish ownership and API shape.

### Stage 3: Integrate context switching

Upgrade the current switch logic from "only rewrite `CSR_NACC_STATE`" to:

- save previous context
- load next context
- refresh per-hart loaded runtime state

Prefer reusing the existing Linux -> OpenSBI thread-switch notification point.

### Stage 4: Harden the trap round-trip

Validate:

- protected user trap first landing always enters agent
- Linux delegation always returns to agent first
- agent then decides whether and how to resume user mode

### Stage 5: Re-validate the current blockers

After runtime-context convergence, revisit:

- `sh -c "cat /etc/hostname; echo done"`
- `echo alpha | wc -c; echo done`
- `ld-linux` / loader progress

The goal is not to claim these issues must disappear automatically. The goal is to verify whether the current hard-to-explain execution-progress failures are fundamentally runtime-context failures.

## Recommended Immediate Questions

Before implementing:

1. Which current fields are **thread-owned continuation** and which are merely hart-owned cache?
2. If a protected thread is scheduled out while in the middle of `AGENT`, is that allowed? If yes, how is the continuation saved?
3. Who currently decides the Linux-delegation "return to agent" target, and is Linux still able to influence that control flow?
4. Can `TWIN_ENTRY` be fixed while all dynamic continuation information moves into `nacc_thread_ctx`?

## Non-Goals

- do not replace the Linux scheduler model in this phase
- do not pull `bitmap` protection earlier
- do not rewrite fork / exec / `mmap` end-to-end all at once
- do not combine this with a cleanup of all historical ABI names

## Definition Of Done

This plan is considered implemented only when:

1. NaCC has an explicit per-thread Secure Runtime Context
2. `CSR_NACC_STATE` is clearly limited to hart-local runtime mode instead of process lifecycle semantics
3. scheduling can save / load trusted continuation instead of merely changing a `cid` / mode bit
4. protected user trap first landing is still forced into agent
5. Linux delegation returns to agent first, and agent decides final user resume
