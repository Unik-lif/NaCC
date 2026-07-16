# Agent-first trap handling

## Status note, 2026-07-06

This document is partly stale. It should be read as historical design analysis,
not as the current authority for the Agent trap refactor.

Current working assumption:

- Protected U-mode traps first land in Agent.
- Agent saves a short-lived pt_regs-style staging frame, delegates to Linux with
  `acall`, restores from the Linux `pt_regs` result after `aret`, then returns
  with `sret`.
- Agent trap entry and return must stay aligned with Linux
  `arch/riscv/kernel/entry.S`. In particular, protected U-mode execution must
  keep `CSR_SSCRATCH = kernel tp`, and the first landing must use the same
  `csrrw tp, CSR_SSCRATCH, tp` contract as Linux. If this ABI drifts, Agent may
  save stack/tp state into the wrong Linux task frame and the system can fail
  catastrophically.
- Agent S-mode traps are not a normal Linux-delegation path. With SIE kept off
  while Agent runs, ordinary S-mode interrupts should not enter Agent. If an
  Agent S-mode trap still happens, treat it as an Agent fault diagnostic path
  and fail-fast: print the trap cause, fault address, `sepc`, `sstatus`, and
  trapped `sp/tp`, then stop in a `wfi` loop. Do not delegate it to Linux
  and do not try to resume Agent S-mode.
- Per-hart Agent staging remains a future concurrency cleanup for normal
  protected-user trap entry. It is not a current S-mode recovery design. State
  that must survive Linux scheduling belongs in Linux task state or OpenSBI
  thread-context state, not in a globally live Agent frame.

For the current step-by-step direction, prefer `record/agent_trap_worklog.md`.

## Purpose

This note records the core design for fixing the current Agent/Linux trap state
confusion. It intentionally stays short. The important point is the hardware
state contract, not a Linux policy branch.

## Terminology

- `CSR_NACC_STATE`: the authoritative NaCC hardware state.
  - Contains the protected context identity, including CID, and the current
    domain mode such as `AGENT` or `LINUX`.
  - Final design: S-mode Linux must not directly read or write it.
  - Current diagnostic exception: QEMU temporarily allows S-mode reads for
    state-transition logging. This is debug debt and must be removed.
  - Normal S-mode code changes only the mode part indirectly through the
    hardware primitives `acall` and `aret`.

- `CSR_NACC_SSTATUS`: rejected prototype helper for `aret`.
  - It carried a Linux-provided copy of `regs->status` so QEMU could inspect
    `SPP` during `aret`.
  - This is the wrong authority boundary. Linux is the delegated handler
    provider, not the return-authority provider.
  - Remove this custom NaCC CSR path now. This is not a compatibility migration
    and not a staged fallback path. The register is wrong and must be deleted.
  - Do not preserve QEMU storage, Linux writes, OpenSBI thread-context snapshots,
    traces, or any Agent-facing dependency for compatibility with the old path.
  - If deleting it leaves the current runtime unable to return to Agent, that is
    acceptable. The failure mode should be fail-closed/no-op, not a fallback to
    Linux-provided status.
  - Do not confuse this with the normal RISC-V `CSR_SSTATUS` or saved `sstatus`
    fields in Agent-owned trap frames. Those remain ordinary context data.

- `CSR_TRAMPOLINE`: the Agent/Linux continuation slot.
  - Before `acall`, Agent sets it to the Linux handler entry.
  - After `acall`, hardware stores the Agent continuation there.
  - It must not be used to store the interrupted Agent PC. The interrupted PC
    belongs in the Agent trap frame.

- `CSR_SSCRATCH`: must keep Linux entry.S semantics at the Agent/Linux boundary.
  - Protected U-mode running state: `tp = user tp`, `CSR_SSCRATCH = kernel tp`.
  - First landing must mirror Linux: `csrrw tp, CSR_SSCRATCH, tp`.
  - After that swap, U-mode traps have `tp = kernel tp` and
    `CSR_SSCRATCH = user tp`; Agent may then use Linux `thread_info` offsets
    such as `kernel_sp` and `user_sp`.
  - While running delegated Linux S-mode handlers, `CSR_SSCRATCH` must be `0`,
    matching Linux kernel-mode trap expectations.
  - Before final `sret` to protected U-mode, Agent must write
    `CSR_SSCRATCH = kernel tp`, not an Agent-private context pointer.
  - Do not repurpose `CSR_SSCRATCH` as an Agent context register. Agent-private
    trap state must live in explicit Agent memory reached after the Linux entry
    ABI has been honored.

## Core Invariant

When `CSR_NACC_STATE.mode == AGENT`, protected U-mode traps must first land in
Agent.

If an Agent S-mode trap occurs, it should also land in Agent, but only for
fault diagnostics. The current policy is fail-fast panic, not delegation,
recovery, or Agent S-mode resume.

Linux may handle a trap only after Agent explicitly delegates by `acall`:

```text
Agent -> acall -> Linux
CSR_NACC_STATE.mode: AGENT -> LINUX
CSR_NACC_STATE.pending_return: 0 -> 1
```

Linux may return only by executing `aret`; hardware decides whether that `aret`
is allowed to switch back:

```text
Linux -> aret -> Agent
CSR_NACC_STATE.mode: LINUX -> AGENT
CSR_NACC_STATE.pending_return: 1 -> 0
pc = CSR_TRAMPOLINE
```

Linux should not be the authority for deciding whether a protected return goes
to Agent. The authority is `CSR_NACC_STATE`: the current mode, CID, and any
return/delegation state that is explicitly part of the NaCC state contract.
`CSR_NACC_SSTATUS` is not part of the target return contract, and there should
not be a separately framed "return token" authority beside `CSR_NACC_STATE`.
The delegated-return marker is now a pending bit in `CSR_NACC_STATE.reserved`.
QEMU sets it only in `acall` when Agent enters Linux delegation, and consumes it
only in `aret` when Linux returns to Agent. OpenSBI must preserve that reserved
substate in the per-pid thread context while Linux may schedule away from the
delegated handler.

## Current Code Shape

The original bug was that QEMU redirected only protected U-mode traps to
`CSR_TWIN_ENTRY`:

```text
if source_priv == U && CSR_NACC_STATE.mode == AGENT:
    pc = CSR_TWIN_ENTRY
```

In that old shape, Agent S-mode traps were not redirected. They took the normal
Linux `stvec` path while `CSR_NACC_STATE.mode` was still `AGENT`.

That is the state-domain leak:

```text
Agent S-mode interrupted
-> trap enters Linux stvec
-> Linux do_irq / scheduler runs while CSR_NACC_STATE.mode == AGENT
-> OpenSBI observes/saves/clears same-CID AGENT state
```

The Linux `do_irq()` `user_mode(regs)` guard fixed the old repeated
`helper_aret outcome=non-linux-noop` loop. By itself, that guard did not fix the
first-landing issue because it only changed Linux behavior after Linux had
already become the handler.

Current working-tree patches have partially moved past that old shape:

- QEMU now redirects both protected U-mode and Agent S-mode traps to
  `CSR_TWIN_ENTRY` when `CSR_NACC_STATE.mode == AGENT`.
- Agent has a unified first landing path for protected U-mode traps.
- The Agent S-mode branch is intentionally fail-fast: from the `sscratch == 0`
  landing it reads `scause`, `sepc`, `stval`, `sstatus`, trapped `sp/tp`,
  `CSR_TRAMPOLINE`, and `CSR_NACC_STATE`, switches to an Agent-owned panic
  stack, logs them, and stops. It is not a delegated Linux handler path and it
  does not restore the interrupted Agent S-mode context.

Do not extend the S-mode branch into a Linux delegation path without a fresh
design decision. For now, an Agent S-mode exception means the Agent violated its
own assumption that it does not fault internally.

## OpenSBI -> Agent Handoff

The current code has two different OpenSBI-to-Agent entry paths. They must not
be merged conceptually.

### Common Precondition

Linux enters these paths through the NaCC SBI extension from S-mode. The SBI
handler captures Linux `regs->tp` as `kernel_tp` and forwards it as an opaque
Agent handoff value.

`agent_prepare()` and `agent_prepare_reexec()` write `CSR_MEPC` and execute
`mret` directly. They do not explicitly set `mstatus.MPP`. Therefore the entry
contract assumes the current OpenSBI trap context is returning to S-mode. Do not
reuse these helpers from an arbitrary M-mode context without making the target
privilege explicit.

Before both entries, OpenSBI must:

- validate/prepare the current protected page-table root;
- ensure and load the pid's thread context;
- write `CSR_NACC_STATE` through `nacc_thread_ctx_load(pid, NACC_STATE_AGENT)`;
- restore that pid's saved `CSR_TRAMPOLINE` snapshot;
- map the fixed Agent image into the process root at `agent_virt_start`;
- mask S-mode interrupt delivery for the small entry window.

The interrupt mask is implemented by saving the prior `mstatus.SIE` bit as a
token in `CSR_SSCRATCH`, then clearing `mstatus.SIE` before `mret`. At this moment
`CSR_SSCRATCH` is not an Agent landing-record pointer.

### Full Init Entry

The full path is used before the Agent has completed first initialization for
the current boot/run:

```text
Linux __nacc_invoke_full()
-> SBI_EXT_NACC_INVOKE
-> sm_nacc_invoke_full()
-> agent_prepare(SBI_DOMAIN_AGENT_REGION_BASE, offset, saved_linux_satp, ...)
-> mret to Agent _entry with satp = 0
```

Linux passes:

- `agent_virt_start`: the process virtual slot where the Agent image is mapped;
- `pid`;
- `user_pt_regs`;
- Linux handler state: `do_irq`, `excp_vect_table`, and `current_gp`.

OpenSBI adds `kernel_tp` from the SBI trap registers. `sm_nacc_invoke_full()`
then validates the current Linux `satp`, confirms the protected root, prepares
secure user page tables, opens/maps the Agent image, sets the full-init guard
state, and calls `agent_prepare()`.

`agent_prepare()`:

- writes `CSR_MEPC = SBI_DOMAIN_AGENT_REGION_BASE`;
- writes the SIE restore token into `CSR_SSCRATCH`;
- clears `CSR_SATP`, so the initial Agent entry runs through the fixed physical
  mapping;
- passes the handoff registers:
  - `a0 = offset`;
  - `a1 = saved_ra`;
  - `a2 = saved_linux_satp`;
  - `a3 = user_pt_regs`;
  - `a4 = do_irq`;
  - `a5 = excp_vect_table`;
  - `a6 = current_gp`;
  - `a7 = kernel_tp`;
- executes `mret`.

Agent `_entry` stores those values in Agent globals, seeds `tp = kernel_tp`,
uses the boot stack, and calls `main()`. `main()` eventually calls `vm_init()`.
`vm_init()` builds a temporary Agent page table, maps the Agent image and
trampoline, switches to that temporary `satp`, jumps through the trampoline,
and then switches to the saved Linux `satp`.

Only after Agent is running under the Linux page table does `trap_init()` install
the real Agent first-landing contract:

- consume the `CSR_SSCRATCH` SIE restore token;
- initialize `_user_context` and the landing record;
- write `CSR_TWIN_ENTRY = __trap_entry`;
- replace `CSR_SSCRATCH` with the Agent landing-record pointer;
- restore the intended SIE state.

Then Agent calls `SBI_EXT_AGENT_READY`. OpenSBI accepts that call only while
`g_nacc_agent_full_init_in_progress` is true, `CSR_NACC_STATE.mode == AGENT`,
and the CID matches the full-init guard. After that, Agent returns directly to
the protected user frame through `__agent_exit(_user_pt_regs)`.

### Lightweight Reexec / Attach Entry

The lightweight path is used after Agent full init has completed, for same-PID
reexec, ready-agent invoke reuse, and first-user-return attach for a forked
protected child:

```text
Linux nacc_exec() / fork-child attach / ready-agent invoke
-> sm_nacc_exec() or sm_nacc_attach_forked_child()
-> agent_prepare_reexec(agent_virt_start + AGENT_REEXEC_ENTRY_OFFSET, ...)
-> mret to Agent __reexec_entry with current Linux satp still active
```

OpenSBI still validates the current root, prepares secure page tables, maps the
Agent image into `agent_virt_start`, ensures/loads the thread context in
`NACC_STATE_AGENT`, and masks the SIE entry window. The important difference is
that `agent_prepare_reexec()` does not clear `CSR_SATP`; it enters through the
process virtual Agent mapping.

Do not confuse this with `sm_nacc_invoke_child()`. That path prepares/maps a
child root and loads the child context in `NACC_STATE_LINUX`; it does not enter
Agent. The fork-child path that enters Agent is
`sm_nacc_attach_forked_child()`, which has `user_pt_regs` and `kernel_tp`.

`agent_prepare_reexec()`:

- writes `CSR_MEPC = agent_virt_start + AGENT_REEXEC_ENTRY_OFFSET`;
- writes the SIE restore token into `CSR_SSCRATCH`;
- preserves the current Linux `CSR_SATP`;
- passes only:
  - `a0 = user_pt_regs`;
  - `a1 = kernel_tp`;
- executes `mret`.

Agent `__reexec_entry` refreshes the minimal runtime contract:

- recomputes `_offset` for the fixed reexec entry;
- saves the current Linux `satp` into `_satp`;
- stores the new `user_pt_regs` and `kernel_tp`;
- consumes the `CSR_SSCRATCH` SIE restore token;
- rebuilds the landing record from existing Agent globals, including
  `_user_context`;
- writes `CSR_TWIN_ENTRY = __trap_entry`;
- replaces `CSR_SSCRATCH` with the Agent landing-record pointer;
- restores the intended SIE state;
- jumps to `__agent_exit(user_pt_regs)`.

This path therefore depends on the full-init path having already initialized
the Agent global trap context. It is not a substitute for first initialization.

### Handoff Pressure Points

- `CSR_SSCRATCH` has two meanings across the entry boundary. In OpenSBI it is a
  one-bit SIE restore token. After Agent installs its trap entry, it is an
  Agent-owned landing-record pointer. Treating it as a long-lived OpenSBI
  context pointer is wrong.
- `NACC_STATE_AGENT` is loaded before `CSR_TWIN_ENTRY` is installed/refreshed.
  The SIE mask is what makes that short window valid.
- Full init enters at a physical address with `satp = 0`; lightweight attach
  enters at a virtual address with the Linux `satp` still active. Mixing these
  two address contracts is fatal.
- `agent_prepare_reexec()` uses the existing `_user_context` and handler globals
  from full init. If those globals are stale, uninitialized, or need per-pid /
  per-hart separation, the lightweight path has no independent repair.
- `CSR_TRAMPOLINE` is restored by `nacc_thread_ctx_load()`, but it is not the
  OpenSBI-to-Agent jump target. It becomes relevant when Agent later delegates
  to Linux by `acall` and hardware records the Agent continuation.

## Agent Entry Interrupt Window

The Agent-first invariant only becomes meaningful after Agent has installed a
valid first-landing target. During full Agent initialization and lightweight
reexec, there is a short window where OpenSBI has already selected/loaded
`CSR_NACC_STATE.mode == AGENT`, but Agent has not yet installed or refreshed
`CSR_TWIN_ENTRY`.

S-mode timer/interrupt delivery must be masked for that entry window. Otherwise
QEMU can correctly apply the Agent S-mode redirect rule before
`CSR_TWIN_ENTRY` is valid, producing a redirect to zero instead of reaching
Agent trap entry.

The rule is narrow:

- OpenSBI/entry code may mask S-mode interrupt delivery for the Agent handoff.
- Agent must restore the intended interrupt-enable state only after
  `CSR_TWIN_ENTRY` points at `__trap_entry`.
- The mask must not become a general "run Agent with interrupts disabled"
  policy after initialization/reexec completes.
- A QEMU guard for `CSR_TWIN_ENTRY == 0` is only a fail-loud invariant check. It
  is not the primary repair for the entry-window race.

## Current Agent S-mode Trap Policy

```text
Agent S-mode interrupted while CSR_NACC_STATE.mode == AGENT
-> QEMU redirects to CSR_TWIN_ENTRY
-> Agent entry observes sscratch==0 / S-mode source
-> Agent switches to the fixed Agent S-mode panic stack
-> Agent prints cause, cause code, stval/badaddr, sepc, sstatus, trapped sp/tp,
   CSR_TRAMPOLINE, and CSR_NACC_STATE
-> Agent stops in a wfi loop
```

The working assumption is that Agent itself does not fault in normal operation.
Therefore synchronous Agent S-mode exceptions are bugs in Agent or in the
Agent/OpenSBI handoff. They should not be hidden by entering Linux while the
hardware state is still `AGENT`, and they should not be converted into a normal
Linux delegation path.

## Agent Stack Rule

Agent currently needs only an Agent-owned panic stack for Agent S-mode traps.
This stack exists so the panic logger can call C after the entry path has
captured the failing state.

Do not treat `_user_context` as an Agent S-mode preemption frame. The primary
S-mode panic path does not use `_user_context`; it only reads the failing CSRs
and trapped `sp/tp`. The defensive already-saved branch may print from the
existing pt_regs-style layout, but it still never resumes. That is different
from supporting nested or recoverable Agent S-mode traps.

Current implementation shape:

- Keep a fixed 4 KiB `__agent_smode_panic_stack`.
- Save enough state to print the trap reason and fault location.
- Do not call Linux, do not execute `acall`, and do not return to the
  interrupted Agent S-mode PC.

## Linux Role

Linux remains the handler provider, not the state authority.

Linux may run `do_irq()` or the relevant exception handler after Agent delegates
by `acall`. Linux may execute `aret`, but `aret` is a hardware primitive:

```text
if CSR_NACC_STATE.mode == LINUX
   and CSR_NACC_STATE.cid != 0
   and CSR_NACC_STATE.pending_return == 1
   and CSR_TRAMPOLINE != 0:
    CSR_NACC_STATE.pending_return = 0
    CSR_NACC_STATE.mode = AGENT
    pc = CSR_TRAMPOLINE
else:
    no-op / fail-closed / ordinary Linux kernel return behavior
```

The current `do_irq()` `user_mode(regs)` guard is a temporary diagnostic repair.
The final semantic split should not live in that Linux branch.

## Current Human Corrections

These corrections supersede the earlier staged migration wording in this note.

- Delete `CSR_NACC_SSTATUS`. Do not preserve it until a later slice, do not keep
  it for compatibility, and do not stage a fallback through it.
- This deletion is intentionally aggressive. Do not optimize for preserving the
  current prototype's ability to limp forward through the old status register.
  Removing the wrong authority boundary is more important than keeping the
  current loop runnable.
- Future `aret` authorization must be based on `CSR_NACC_STATE` and
  Agent-owned context/continuation records. Do not introduce a parallel
  "return token" authority that is conceptually separate from `CSR_NACC_STATE`.
- `aret` authorization now uses `mode`, `cid`, `CSR_TRAMPOLINE`, and a
  delegated-return pending bit in `CSR_NACC_STATE.reserved`. Linux must not be
  able to write this bit.
- The recent Agent unified-landing work must keep the S-mode branch as a
  diagnostic panic path. Do not expand it into a return/delegation path unless
  the S-mode recovery design is explicitly reopened.
- Runtime tests and `test_runner` routing for this cleanup should wait for
  explicit human approval after code inspection.

## Implementation Slices

### Design order

The target design removes `CSR_NACC_SSTATUS` use. Do not add new dependencies on
it.

Current order:

1. Delete the custom `CSR_NACC_SSTATUS` path across QEMU, OpenSBI, Linux,
   Agent references, traces, and thread-context snapshots. If this breaks
   runtime return, leave it fail-closed/no-op and document the remaining
   `CSR_NACC_STATE` return-design gap. Do not add compatibility fallbacks.
2. Reconcile the existing safe-first-landing proof with the deletion above:
   QEMU/Agent may keep redirecting protected U-mode and Agent S-mode traps to
   Agent first, but that proof must not depend on `CSR_NACC_SSTATUS`.
3. Review and simplify the Agent-owned context model so the first-landing path,
   scratch contract, protected U-mode frame, and Agent S-mode diagnostic path
   are understandable before adding more behavior.
4. Keep Agent S-mode traps fail-fast unless the design is reopened explicitly.
   The current assumption is that Agent internal S-mode exceptions are bugs and
   should be diagnosed, not delegated.
5. Change `aret` authorization so the domain switch is decided by
   `CSR_NACC_STATE.mode/cid/pending_return` plus `CSR_TRAMPOLINE`, not
   `CSR_NACC_SSTATUS`, Linux `regs->status`, or a separate token authority.
6. Only after that, remove the temporary Linux read access to `CSR_NACC_STATE`.

### Slice 1: safe first landing proof

The current working tree already contains this as a proof direction:

- QEMU redirects Agent S-mode traps to `CSR_TWIN_ENTRY` when
  `CSR_NACC_STATE.mode == AGENT`.
- Full Agent init and lightweight reexec mask S-mode/timer interrupts until
  `CSR_TWIN_ENTRY` has been installed/refreshed.
- Agent has an early `sscratch == 0` diagnostic branch for Agent S-mode traps.
- That branch logs/panics using an Agent-owned panic stack.
- It must not call `save_regs()`, copy into Linux stack, or jump to
  the Linux delegation continuation.

This proof is intentionally not a complete S-mode return design. Under the
current assumption, Agent S-mode exceptions are Agent bugs and should remain
fail-fast.

Expected proof: Linux scheduler/IRQ code is no longer the first observer of the
Agent S-mode trap while `CSR_NACC_STATE.mode == AGENT`.

### Deferred: real Agent S-mode return

This is no longer the current default target. If a future design decides Agent
must recover from Agent S-mode traps, it needs a fresh explicit design before
coding:

- Add a real per-hart Agent trap stack.
- Save the true interrupted Agent S-mode frame there.
- Decide whether any work is delegated to Linux by `acall`.
- Make `aret` continue using `CSR_NACC_STATE.mode/cid/pending_return`, not
  `CSR_NACC_SSTATUS`, Linux `regs->status`, or Linux policy, to decide
  `LINUX -> AGENT`.
- Agent continuation restores from the per-hart stack and `sret`s to the
  interrupted Agent PC.

### Slice 3: cleanup

- Remove the temporary QEMU S-mode read opening for `CSR_NACC_STATE`.
- Apply the same Agent-first delegation model to all protected trap paths, not
  only timer IRQ.
- Remove temporary state-trace noise after workload 1 passes, then validate
  workloads 1-8.

## Disallowed Shortcuts

- Do not let Agent S-mode traps enter Linux `stvec` while
  `CSR_NACC_STATE.mode == AGENT`.
- Do not delegate Agent S-mode traps to Linux as a normal handler path under
  the current fail-fast design.
- Do not make Linux scheduler accept same-CID `AGENT` observations as normal.
- Do not use `CSR_TRAMPOLINE` to store the interrupted Agent PC.
- Do not reuse `_user_context` for recoverable Agent S-mode preemption.
- Do not leave Agent interrupts globally disabled after the entry-window setup.
- Do not add new `CSR_NACC_SSTATUS` dependencies.
- Do not make `CSR_NACC_SSTATUS` an authority for `aret`.
- Do not keep `CSR_NACC_SSTATUS` as migration debt.
- Do not introduce a return-token authority separate from `CSR_NACC_STATE`.
- Do not leave S-mode Linux read/write access to `CSR_NACC_STATE` in the final
  design.
