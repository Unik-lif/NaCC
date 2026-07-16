# 2026-06-02 Multicore Agent Context Model Note

## Purpose

This note records the planning conclusion from the `multicore_agent` discussion.
The question was whether the current NaCC Agent design remains appropriate after
switching the platform to multicore, and whether it should be structurally
changed now for future multi-container concurrency.

No code changes or validation runs were made for this note.

## Current Judgment

The current tree can run on a multicore machine, but the Agent itself should not
be treated as multicore-ready.

The important distinction is:

- Multicore host execution is possible.
- Monitor-side shared metadata is partly multicore-aware.
- Concurrent Agent entry is not currently safe by construction.

So the current state is not simply "single-core Agent throughput, but safe."
It is closer to "safe only while the Agent path is effectively single-active."
If two NaCC tasks or containers enter Agent attach/reexec/trap paths on
different harts at the same time, there are real shared-state hazards.

## Evidence

The Agent is loaded as one physical image at `SBI_DOMAIN_AGENT_REGION_BASE`.
OpenSBI copies the footer-selected binary to that single destination in
`opensbi/lib/sbi/sbi_agent.c`.

The Agent linker script places `.data`, `.bss`, the boot stack, and runtime
storage inside that fixed image. OpenSBI then maps the same physical Agent range
into each NaCC process address space.

The Agent entry path writes process/hart-sensitive values into global storage:

- `_offset`
- `_satp`
- `_user_pt_regs`
- `_kernel_tp`
- `_current_gp`

The lightweight reexec path also overwrites these globals. The trap path uses a
single `_user_context` pointer to a fixed `__agent_user_context_page`, and the
direct Agent return path uses the fixed `boot_stack_top` for debug/transition
work.

The Agent allocator is also global and explicitly lock-free:

- `agent/src/mem.c` says the Agent does not need a spin lock.
- `kmem.freelist` is a singleton.

These are all reasonable for a single-active Agent shim, but they are not a
valid concurrent runtime model.

Monitor-side state is in better shape. The CID table, thread context table,
secure allocator, bitmap, root records, and private refcounts use locks or
atomic operations. The Linux scheduler also calls the NACC verify ecall on
context switch to save/load per-PID monitor context. That lowers risk in the
SBI service path, but it does not make the Agent image runtime state
concurrent-safe.

One specific multicore gap is `CSR_TWIN_ENTRY`. The Agent programs it in
`trap_init()` and refreshes it during lightweight reexec, but OpenSBI
`thread_ctx` currently persists `CSR_NACC_SSTATUS` and `CSR_TRAMPOLINE`, not
`CSR_TWIN_ENTRY`. If `TWIN_ENTRY` is hart-local, task migration to a hart that
has not run the Agent setup path can leave the trap contract incomplete.

## Performance Interpretation

If a protected workload spends most of its time in user-space computation, it
may still benefit from Linux scheduling across multiple harts. But NaCC control
paths involving Agent attach, reexec, first fork-child attach, or Agent trap
handoff are effectively singleton today.

If a lock were added around Agent entry without changing the Agent structure,
those paths would become intentionally serialized. That would give correctness
for the current model but not multi-container Agent throughput.

Without such serialization, concurrent Agent entry is not just slow; it can
overwrite shared Agent globals, stack, trap-save page, or allocator state.

## Recommendation

Do not do a full Agent rewrite immediately.

The current phase should instead make the boundary explicit:

- Define the current supported model as multicore host supported, concurrent
  Agent entry unsupported.
- Add or plan a conservative serialization/detection boundary around Agent
  entry, reexec, first fork-child attach, and trap handoff if multicore testing
  will continue.
- Audit hart-local CSRs used by the Agent, especially `CSR_TWIN_ENTRY`, and
  either save/restore them in thread context or refresh them on every hart
  entry path.

When the project intentionally supports multiple containers or multiple NaCC
threads entering Agent paths concurrently, then the Agent should be redesigned
as:

- shared text/image;
- per-hart or per-task mutable runtime context;
- per-hart or per-task trap-save page;
- per-hart or per-task Agent stack;
- explicit ownership for `_satp`, `_user_pt_regs`, `_kernel_tp`,
  `_current_gp`, and related handoff values;
- allocator state moved out of the singleton Agent image, locked, or made
  context-local.

That future work is architectural. It should be a separate task with a clear
definition of whether the context key is hart, task, PID, mm, container, or a
combination of them.

## Bottom Line

For now, treat the current Agent as a single-active runtime shim. It is
acceptable to defer the large redesign, but only if the project explicitly
records the concurrency boundary and avoids interpreting "runs on multicore" as
"Agent is multicore-safe."
