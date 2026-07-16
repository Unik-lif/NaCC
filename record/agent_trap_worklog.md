# Agent Trap Worklog

Date: 2026-07-06

This note tracks the current Agent trap refactor outside the Harness V2 task
packet flow. It records the local design direction and code changes made in the
long-running Codex session.

Use this worklog as the current local direction. `record/agent_trap.md` contains
older design analysis and is partly stale, especially where it treats Agent
S-mode traps as a possible normal Linux delegation path.

## Current Understanding

The normal protected-user trap path should be:

```text
protected U-mode
  -> Agent trap entry
  -> Agent saves user pt_regs-style context
  -> Agent builds a Linux pt_regs frame
  -> acall to Linux handler
  -> Linux handler eventually aret
  -> Agent restores from the Linux pt_regs result
  -> sret to protected U-mode
```

The Agent first landing must remain compatible with Linux
`arch/riscv/kernel/entry.S`. Protected U-mode execution must keep
`CSR_SSCRATCH = kernel tp`, and the Agent trap entry must use the Linux-style
`csrrw tp, CSR_SSCRATCH, tp` swap. Agent-private pointers must not be stored in
`CSR_SSCRATCH` across a return to protected U-mode; doing so breaks the Linux
`thread_info` stack/tp contract and can corrupt the system immediately.

Agent S-mode traps should not be treated as the normal delegation path. With
SIE kept off inside Agent, ordinary S-mode interrupts should not enter Agent
while Agent is running. S-mode exceptions can still happen and should be treated
as Agent fault diagnostics. The current code should panic and stop after
printing cause/address/status and trapped `sp/tp`, not delegate the trap to
Linux.

The hard concurrency issue is the Linux delegation window. After `acall`, Linux
may re-enable interrupts or schedule while handling syscalls, page faults, or
IRQs. Therefore Agent per-hart frame/stack storage should be a short staging
area, not long-lived ownership state across the whole Linux handler.

## Code Changes So Far

- Removed the `CSR_NACC_SSTATUS` design and related QEMU/Linux/OpenSBI plumbing.
  Linux now relies on the delegated `pt_regs->status` instead of a separate
  NaCC status CSR.
- Added a delegated-return pending bit in `CSR_NACC_STATE.reserved`.
  QEMU `acall` sets it when Agent enters a Linux delegated handler; QEMU `aret`
  requires and clears it before switching `LINUX -> AGENT`. OpenSBI
  `thread_ctx` now saves/restores that reserved substate while Linux may
  schedule away from the delegated handler.
- Reworked Agent trap naming away from `ALR_*` and old landing-record wording
  toward `TRAP_*` and `__agent_trap_entry_context`.
- Changed the U-mode trap path so Agent first saves into its own user context,
  copies that into the Linux handler frame, then restores directly from the
  Linux frame result before final `sret`.
- Narrowed the Agent S-mode branch to a fail-fast diagnostic path. It now uses
  a fixed Agent panic stack, prints the saved `scause`/cause code,
  `stval`/badaddr, `sepc`, `sstatus`, trapped `sp/tp`, `CSR_TRAMPOLINE`, and
  `CSR_NACC_STATE`, then stops in a `wfi` loop.
- First interrupt-discipline fix:
  - OpenSBI no longer stores an SIE restore token in `CSR_SSCRATCH` before
    entering Agent.
  - Agent `trap_init()` and `__reexec_entry` no longer restore `SIE`.
  - Linux disables local interrupts immediately before executing NaCC `aret`.
- Return-to-user contract tightened:
  - Both `__ret_from_exception` and `__agent_exit` clear `SIE` and `SPP` from
    the return `sstatus` before writing `CSR_SSTATUS`.
  - They preserve `SPIE`; the final `sret` restores interrupt state from that
    bit after leaving Agent S-mode.
  - Both paths re-seed `CSR_SSCRATCH` with the Linux kernel `tp` before
    returning to protected U-mode, matching Linux entry.S. `CSR_TWIN_ENTRY`
    remains a stable trap-entry pointer that is set during init/reexec, not on
    every return.
- Linux delegated trap return centralized:
  - Linux full init now passes `nacc_delegate_entry` to Agent instead of
    `do_irq`.
  - Agent delegates all user traps through that wrapper with `a0=regs`,
    `a1=kind`, and `a2=handler`. IRQ is an explicit kind because Linux's
    `do_irq()` is not part of `excp_vect_table`.
  - The old Agent `__offset32/__offset48/__offset80` return labels were removed;
    Linux `aret` now returns to a single `__agent_linux_return` continuation.
  - Ordinary Linux trap handlers no longer execute NaCC `aret` themselves.
- U-mode return ownership narrowed:
  - Agent `_user_context` is now only the pre-delegation staging copy used to
    build the Linux `pt_regs` frame.
  - After Linux `aret`, Agent restores directly from the Linux `pt_regs` frame
    instead of copying it back into `_user_context`.
- `CSR_SSCRATCH` ABI repaired:
  - The Agent first landing is back to Linux-style
    `csrrw tp, CSR_SSCRATCH, tp`.
  - Agent S-mode code keeps `CSR_SSCRATCH = 0`; `__ret_from_exception` and
    `__agent_exit` write `CSR_SSCRATCH = kernel tp` only immediately before
    returning to protected U-mode.
  - Agent S-mode diagnostics now use the `sscratch == 0` first landing and an
    Agent-owned panic stack instead of depending on `CSR_SSCRATCH` holding an
    Agent-private context pointer.

## Immediate Next Steps

1. Validate the final `sret` status contract by build/run.
   The code now clears `SIE/SPP`, preserves `SPIE`, and routes delegated Linux
   handlers through `nacc_delegate_entry`, but this still needs to be confirmed
   against the actual boot/reexec/runtime traces.

2. Move from global Agent trap storage toward per-hart staging.
   The intended structure is per-hart `entry_context` and pt_regs-style staging
   frames for the protected-user trap path. This does not replace Linux/OpenSBI
   task context for state that must survive scheduling, and it is not an
   Agent S-mode recovery stack.

3. Add owner/depth checks later.
   Per-hart storage should eventually have an owner/depth guard so a new
   protected owner cannot silently overwrite an active Agent trap window.

## Open Risks

- The current Agent trap context, user frame, and S-mode panic stack are still
  effectively global. This is not yet safe for concurrent harts or task
  migration.
- Linux handler paths can still open interrupts and schedule after `acall`.
  OpenSBI thread context now saves/restores `CSR_TRAMPOLINE` and
  `CSR_NACC_STATE.reserved` for the delegated-return pending bit; Agent now
  re-seeds `CSR_SSCRATCH` with Linux kernel `tp` before `sret`, but the staging
  frame itself is still global until per-hart storage is implemented.
- No compile or VM run was done for this refactor step. The human will run those
  checks separately.
