# Hackbench NaCC Thread-Mode Failure and Metadata Direction

Date: 2026-06-07
Task: TASK_20260606_165146_hackbench

## Diagnostic Verdict

The debug run localized the target-scale NaCC Hackbench failure to fork-child registration and monitor bookkeeping, not Docker startup, basic NaCC attach/exec, tiny Hackbench, or generic cleanup.

Hard diagnostic evidence:
- Native/origin completed `hackbench -T -g 25 -f 40 -s 100 -l 100` with Hackbench `Time: 291.984`, wrapper rc `0`, and 100000 aggregate messages.
- NaCC `/bin/true` completed.
- NaCC tiny Hackbench completed.
- Target NaCC `hackbench -T -g 25 -f 40 -s 100 -l 100` started, then the primary QEMU log reported `CONTAINER_FULL`, Linux early fork-child PID registration failure, an unregistered child before `sm_nacc_attach_forked_child`, and a fatal Linux attach failure.

Primary log:
- `logs/test_runner/TASK_20260606_165146_hackbench/final_manual_stop_qemu_pane_nacc_debug_20260606_231015.log`

## Thread-Mode Clarification

The run was genuinely Hackbench thread mode:
- The command used `-T`.
- Hackbench reported 25 groups, 80 file descriptors per group, and 2000 tasks.
- The observed clone flags were pthread-like and included shared address-space/thread semantics such as `CLONE_VM` and `CLONE_THREAD`.
- Multiple attached children shared the same Linux `mm` pointer in the logs.

Therefore the failure should not be interpreted as 2000 independent process address spaces. It is better understood as many Linux task IDs / TIDs belonging to a smaller set of shared-address-space NaCC domains.

## Current Failure Shape

The immediate capacity failure is not global container count exhaustion. The observed pre-failure stats showed one container with 32 registered processes/tasks. The likely immediate cap is the per-container static process list:
- `MAX_CONTAINER = 32`
- `MAX_PROCESS = 32`
- `SATP_HASH_SIZE = 64`
- `NACC_THREAD_CTX_MAX = MAX_CONTAINER * MAX_PROCESS`

Current semantics appear to register by Linux PID/TID. That is compatible with scheduler bookkeeping, because per-thread runtime state may differ even when the address space is shared. However, using a fixed 32-entry per-container PID list makes thread-mode fan-out fail quickly.

## Registration Question

A child registration flow is needed under the current protocol: `sm_nacc_attach_forked_child` expects the child PID/TID to already be known to the monitor. The problem is not simply that registration is missing. The problem is that registration is constrained by static OpenSBI-side data structures that do not scale to the target workload.

The next design should keep a clear distinction between:
- domain/container membership keyed by CID / address-space identity;
- per-task or per-thread scheduler context keyed by PID/TID;
- root/satp-to-domain lookup.

## Current Memory Placement

Approximate current physical layout:
- `0x80000000 - 0x80200000`: OpenSBI / monitor image region.
- `0x80200000 - 0x180000000`: Linux / normal guest memory.
- `0x180000000 - 0x1a0000000`: Agent region, including the agent heap and a private refcount carveout near the end.
- `0x19fc00000 - 0x1a0000000`: private-data refcount region, M-mode-only metadata carved from the agent region.
- `0x1a0000000 - 0x1b0000000`: pvt/metadata memory region.
- `0x1b0000000 - 0x1c0000000`: secure PTP / sec_mem region.

Current usage direction:
- `sec_mem` is actively used for secure page-table page allocation and reclamation.
- `pvt_mem` is initialized but appears underused for monitor metadata.
- the private refcount carveout stores per-PFN private-data reference counts, not thread/container contexts.
- the Agent region is comparatively large and may later be useful for assistive management, but it should not be the first place to move authoritative monitor metadata.

## Recommended Next Design Direction

Do not solve this by only raising static constants. That would likely move the next failure to another static table and keep OpenSBI memory management brittle.

Recommended first follow-up:
- move OpenSBI NaCC task/domain/root metadata out of fixed static arrays and allocate it from `pvt_mem`;
- preserve the existing SBI ABI initially;
- keep authoritative monitor state in OpenSBI for the first pass;
- avoid moving the design directly to Agent-managed metadata until the monitor-side dynamic model is stable.

Suggested first-pass structure:
- `nacc_domain`: CID, domain/root identity, task count, state flags, and domain-level metadata.
- `nacc_task_ctx`: PID/TID, domain pointer/index, saved NaCC scheduler state, trampoline, flags, and generation/lifetime state.
- `nacc_root_record`: root/satp identity mapped to a domain.

The existing hash/list machinery can be simplified in the first pass. A flat dynamic array with linear scans may be acceptable for cold domain/root paths. For the scheduler hot path, a simple flat open-address PID/TID index is preferable to a linked-list hash framework, but the first design should keep this implementation choice explicit.

## Suggested New Packet Seed

Goal: Refactor OpenSBI NaCC PID/CID/thread-context bookkeeping from fixed static arrays into pvt_mem-backed dynamic metadata, so thread-mode workloads with many Linux TIDs in one address space no longer fail at the per-container static process cap.

Critical intent:
- preserve current security semantics and SBI ABI unless source evidence forces a contract change;
- do not move authoritative metadata management to Agent in the first pass;
- do not treat a constant bump as a complete fix;
- keep scheduler checks per PID/TID while separating domain membership from per-thread runtime context.

Definition of done:
- identify and replace the relevant static management structures in OpenSBI;
- show that the former `MAX_PROCESS` per-container limit is no longer the first-order failure condition;
- run the appropriate build for touched components;
- route Hackbench runtime validation as a separate test-runner step.

Open questions for the new task:
- exact lifetime and cleanup rules for task contexts on exit/fork failure;
- whether root/satp records need generation numbers to avoid stale reuse;
- whether the scheduler path needs a PID/TID index in v1 or can temporarily use linear lookup;
- what metadata, if any, should later be delegated to Agent for batching or assistive management.

## Closeout

This record closes the current Hackbench diagnostic/planner packet. The next implementation should be opened as a separate, narrower metadata-refactor task rather than continuing the bloated diagnostic packet.
