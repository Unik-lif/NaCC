# Implementation Ticket

## Goal

- Implement the first v0 multi-NACC-process runtime-context cut.
- Let multiple protected `pid`s keep distinct OpenSBI-owned continuation state instead of relying only on one hart-local `nacc_sstatus` / `trampoline` pair.
- Keep the first implementation minimal and bounded.

## Scope

- Define a minimal OpenSBI-side `struct nacc_thread_ctx` keyed by `pid`.
- Use only the v0 core fields:
  - `valid`
  - `pid`
  - `cid`
  - `saved_nacc_sstatus`
  - `continuation_pc`
  - `ctx_state_flags`
- Integrate that per-`pid` context into the current runtime path so NACC schedule-in / invoke / child-attach no longer assume a single shared continuation state for all protected processes.
- Keep the fixed first-landing model.
- Reuse the existing Linux scheduler and the existing Linux->OpenSBI task-switch handoff point.

## Non-Goals

- Do not add `mm_handle`.
- Do not add generation / epoch tracking in this first cut.
- Do not design full stale-lifecycle rejection for same-`pid` replacement.
- Do not support protected shared-`mm` threads or `clone(CLONE_VM)`.
- Do not support scheduling a protected task out while the trusted continuation is still logically in `AGENT`.
- Do not redesign the full agent trap-save layout or `user_pt_regs` ownership model.
- Do not pull `bitmap` protection into this implementation step.

## Constraints

- Keep `pid` as the stage-1 task key.
- Keep `cid` as container / protection-domain identity.
- Keep `CSR_NACC_STATE` as a hart-local loaded mode register rather than turning it back into a full process-state machine.
- Treat `user_pt_regs` as a handoff input, not as a core persistent `thread_ctx` field in v0.
- Treat the agent trap-save layout as derived from the fixed agent runtime layout, not as a core persistent `thread_ctx` field in v0.
- Prefer a minimal diff centered in OpenSBI; only touch Linux / agent / QEMU where required to make the v0 path work.
- Do not silently expand this into a full architectural cleanup.

## Files Likely Involved

- `opensbi/lib/sbi/sm/sm.c`
- `opensbi/include/sm/sm.h`
- `opensbi/include/sm/nacc.h`
- a new OpenSBI header or source file for `nacc_thread_ctx`, if that keeps the patch reviewable
- `qemu/target/riscv/op_helper.c` if explicit save/load support is needed for the dynamic continuation path
- `linux/arch/riscv/kernel/process.c` only if the current switch notification path is insufficient

## Definition Of Done

- Multiple protected `pid`s can each own a distinct OpenSBI `thread_ctx`.
- The switch / load path restores per-`pid` `saved_nacc_sstatus` and per-`pid` `continuation_pc` instead of assuming one shared continuation state for all protected processes.
- The NACC / non-NACC switch path still drives `CSR_NACC_STATE` correctly.
- The implementation stays within the v0 scope above.
- At least one minimal compile sanity check is run for each touched major component.
- The change is ready for targeted multi-process smoke testing.

## Validation Plan

- Run minimal compile sanity checks for the touched OpenSBI and other relevant objects.
- Re-run at least one fork+exec smoke:
  - `docker run --security-opt seccomp=unconfined --rm busybox sh -c "cat /etc/hostname; echo done"`
- Re-run at least one short multi-process / pipeline smoke:
  - `docker run --security-opt seccomp=unconfined --rm busybox sh -c "echo alpha | cat; echo done"`
- If temporary logs are added, verify they show per-`pid` context initialization / load / update instead of one shared global runtime continuation.

## Rollback Notes

- If the first cut grows beyond the bounded v0 scope, stop and return control to planner instead of silently adding `mm_handle`, generation tracking, or a larger trap-state redesign.
- If the patch only proves a design point but is too invasive to keep, retain the planning conclusions in docs and trim the code back to the smallest reviewable subset.
