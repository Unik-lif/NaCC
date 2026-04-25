# Stage-1 Runtime Role Split

## Goal

Formalize the first coding-round runtime model for "multi NACC processes first".

This is a deliberately reduced v0 model. Its purpose is to support multiple protected processes with minimal new runtime machinery, not to solve every lifecycle-hardening problem in one round.

## Stage-1 Scope

Supported in v0:

- normal Linux scheduler
- multiple protected processes distinguished by `pid`
- protected `fork()`
- protected `exec()`
- protected page-fault / `mmap()` evolution inside one process

Explicitly deferred in v0:

- shared-`mm` protected threads
- `clone(CLONE_VM)` as a protected execution model
- schedule-out while the trusted continuation is logically still in `AGENT`
- `pid` freshness hardening for same-`pid` replacement beyond the current first-pass need
- `mm_handle` / generation-style identity hardening

## Core Terms

| Term | Meaning | Scope | Stage-1 Authority |
| --- | --- | --- | --- |
| `pid` | stage-1 protected task key | per-task | Linux-origin, monitor-validated |
| `cid` | container / protection-domain identity | per-container | monitor |
| `thread_ctx` | minimal trusted continuation object for one protected task | per-task | monitor |
| `current_mode` | currently loaded hart mode: `INACTIVE/LINUX/AGENT/MONITOR` | per-hart | monitor |
| fixed first landing entry | trusted first landing for protected user traps | per-hart | monitor / agent contract |
| `saved_nacc_sstatus` | saved trusted runtime status for one protected task | per-task | monitor |
| `continuation_pc` | saved dynamic return PC for agent/Linux handoff | per-task | monitor |
| `ctx_state_flags` | small monitor-owned logical state word for one protected task | per-task | monitor |
| `thread.nacc_flag` | Linux semantic task phase such as `INITED/FORKED/EXEC` | per-task | Linux |
| `mm->context.nacc_state` | Linux-side `mm` flags such as active/reclaim/build state | per-`mm` | Linux |

## v0 Simplifications

The current coding round intentionally makes these simplifications:

- `pid` is the only stage-1 task identity key.
- There is no `mm_handle` in v0.
- There is no generation / epoch field in v0.
- `user_pt_regs` is treated as a handoff input, not a core persistent `thread_ctx` field.
- agent trap-save layout is treated as derived from the fixed agent runtime layout, not a core persistent `thread_ctx` field.

This means v0 is good enough for "multiple NACC processes first", but not yet a full stale-lifecycle hardening model for same-`pid` replacement.

## Linux Role

Linux remains responsible for ordinary kernel semantics and scheduling.

Linux responsibilities:

- decide which task runs with the normal scheduler
- keep task semantic state in `thread.nacc_flag`
- keep `mm` semantic flags in `mm->context.nacc_state`
- evolve the ordinary `mm` through page faults, `mmap`, `munmap`, COW, and exec setup
- decide when a task should call the existing NaCC-aware invoke / attach / exec / reclaim / switch paths
- provide `pid` when asking the monitor to resolve or load the protected runtime context

Linux is not authoritative for:

- the final binding from loaded hart state to trusted continuation state
- the saved trusted continuation PC
- the saved trusted `nacc_sstatus`
- the final decision whether a protected task may resume

Linux-visible state in v0:

| Variable | Purpose | Scope | Authority |
| --- | --- | --- | --- |
| `current->thread.nacc_flag` | Linux task semantic phase | per-task | Linux |
| `mm->context.nacc_state` | Linux `mm` semantic / teardown flags | per-`mm` | Linux |
| `pid` | stage-1 protected task key | per-task | Linux |
| `cid` mirror | advisory container/domain identity if mirrored in Linux | per-task mirror | Linux copy of monitor-owned value |

## OpenSBI / Monitor Role

OpenSBI owns the trusted runtime binding.

OpenSBI responsibilities:

- own the authoritative `pid -> thread_ctx` mapping
- own the authoritative `pid -> cid` mapping
- decide which trusted continuation is loaded on the hart
- save / load protected per-task runtime state
- keep the trap first-landing / delegate / return policy outside Linux control

Suggested v0 monitor object:

```c
struct nacc_thread_ctx {
    bool valid;
    unsigned long pid;
    unsigned long cid;
    unsigned long saved_nacc_sstatus;
    unsigned long continuation_pc;
    unsigned long ctx_state_flags;
};
```

Suggested minimal `ctx_state_flags` in v0:

- `NACC_CTX_ACTIVE`
- `NACC_CTX_RETURN_TO_AGENT`
- `NACC_CTX_DEAD`

Meaning:

- `ACTIVE`: the protected context is live
- `RETURN_TO_AGENT`: after delegated Linux handling, control must come back to agent first
- `DEAD`: this protected context must not be resumed again

OpenSBI-visible state in v0:

| Variable | Purpose | Scope | Authority |
| --- | --- | --- | --- |
| `thread_ctx(pid)` | trusted continuation lookup | per-task | monitor |
| `cid` | container / protection-domain identity | per-container | monitor |
| `saved_nacc_sstatus` | trusted saved runtime state | per-task | monitor |
| `continuation_pc` | trusted dynamic handoff return PC | per-task | monitor |
| `ctx_state_flags` | trusted logical continuation state | per-task | monitor |
| `current_mode` | currently loaded hart mode | per-hart | monitor |
| fixed first landing entry | trusted first trap landing | per-hart | monitor |

Stage-1 OpenSBI rule:

- OpenSBI may use `pid` as the v0 task key.
- OpenSBI should not assume that one hart-local `nacc_sstatus` / `trampoline` pair is enough for all protected tasks.
- OpenSBI should treat per-task saved continuation state as belonging to `thread_ctx(pid)`.

## Agent Role

The agent remains trusted execution logic, but not the owner of the global runtime registry.

Agent responsibilities:

- serve as the trusted first landing for protected user traps
- save the protected trap frame into the fixed agent-private trap-save layout
- decide whether a trap can be handled locally or must be delegated to Linux
- return according to the trusted continuation contract

In v0, agent state is intentionally kept simple:

- fixed first landing entry stays a per-hart trusted entry
- trap-save layout is derived from the fixed agent runtime layout
- `user_pt_regs` remains a Linux-to-agent handoff input on invoke / reexec paths

Agent should not become the authority for:

- `pid -> thread_ctx`
- `pid -> cid`
- scheduler decisions

## Exact Stage-1 Decision Split

### Linux decides

- which task the normal scheduler runs next
- whether a code path is entering a NACC-aware kernel path
- ordinary `mm` evolution in the current task

### OpenSBI decides

- whether a protected task has a valid `thread_ctx`
- which trusted continuation is loaded on the hart
- whether protected execution may resume

### Agent decides

- how to handle the first landed protected trap
- whether to delegate a given event to Linux
- whether final resume may proceed after delegated handling returns

## Stage-1 Lifecycle Rules

### Schedule-in

Linux passes:

- `pid`

OpenSBI validates:

- `thread_ctx(pid)` exists
- `thread_ctx(pid)` is not marked `DEAD`

If valid, OpenSBI loads:

- `CSR_NACC_STATE`
- `saved_nacc_sstatus`
- `continuation_pc`
- fixed first landing entry

### Schedule-out

v0 rule:

- allowed only when the loaded protected continuation is logically in `LINUX`
- not supported while the trusted continuation is logically still in `AGENT`

### `fork()`

- child gets a new `pid`
- child gets a new `thread_ctx`
- child inherits `cid`
- child gets its own saved continuation state

### `exec()`

- task keeps the same `pid`
- existing `thread_ctx(pid)` is refreshed in place as needed
- same-`pid` freshness hardening beyond `pid` is intentionally deferred in v0

### `exit()` / reclaim

- `thread_ctx(pid)` is invalidated or marked `DEAD`
- later resume of that dead context must be rejected

## Fixed Trap Chain

The committed v0 chain remains:

`protected user trap -> fixed first landing entry -> agent -> optional Linux delegation -> return to agent -> final resume`

Hard rules:

- Linux is not the first landing of a protected user trap
- Linux does not directly resume protected user mode after delegated handling
- the return path after delegated handling remains under trusted continuation control

## What v0 Is Trying To Fix

v0 is trying to fix one concrete problem:

- multiple protected processes should no longer rely only on one shared hart-local pair like current `nacc_sstatus` / `trampoline`

v0 is not yet trying to solve:

- full stale-lifecycle rejection for same-`pid` replacement
- full shared-`mm` thread support
- complete monitor-side cloning of Linux thread context

## Deferred After v0

If v0 proves too weak for same-`pid` exec or stale lifecycle cases, the next hardening round may add one of:

- generation / epoch tracking
- a more explicit address-space lifetime identity
- stronger monitor-side validation around exec replacement
