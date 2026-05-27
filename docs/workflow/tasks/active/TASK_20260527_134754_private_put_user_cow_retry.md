# Task Packet

- Task ID: TASK_20260527_134754_private_put_user_cow_retry
- Created: 2026-05-27 13:47:54 +0800
- Priority: P1
- Lane: A
- Packet Type: execution
- Owner Role: reviewer
- Status: needs_review
- Goal: Implement a bounded private scalar put_user COW mediation repair for workload 3: when OpenSBI sees a legitimate PRIVATE_DATA user leaf that is write-protected only because Linux has not broken COW yet, return a retry/COW-needed status to Linux instead of treating missing PTE_W as a hard deny; Linux should trigger normal write-fault/COW and retry the OpenSBI private write.
- Critical Intent: Repair the specific COW/write-protected private scalar `put_user` gap exposed by workload 3. Missing `PTE_W` on an otherwise legitimate `PRIVATE_DATA` user leaf must be treated as "Linux must break COW and retry", not as a hard security deny and not as a normal-path fallback to direct S-mode store.
- Preferred Shape: Add an explicit OpenSBI-to-Linux result for the private `put_user` COW-needed case. OpenSBI should keep all hard validation before the final writability check, return the new retry/COW-needed status when the only blocker is missing `PTE_W`, and perform the private write only after retry sees `PTE_W`. Linux should recognize that status, trigger normal write-fault/COW handling for `user_va` through an existing kernel helper such as `fixup_user_fault(..., FAULT_FLAG_WRITE, ...)` or an equivalent local helper, then retry the OpenSBI private write once in a bounded way.
- Disallowed Shape: Do not simply remove OpenSBI's `PTE_W` check. Do not map missing `PTE_W` to `SBI_ERR_NOT_SUPPORTED` because Linux currently interprets that as fallback to ordinary `__put_user_nocheck()`. Do not let Linux directly store to `PRIVATE_DATA` PFNs. Do not change QEMU private-data enforcement, global SUM policy, workload definitions, fork semantics, rseq semantics, or the later coredump/writeback `__memcpy` path in this packet. Do not introduce an unbounded retry loop.
- Allowed Freedom: Coder may choose the concrete status encoding if it is unambiguous and does not collide with existing fallback semantics. Coder may add small Linux helper plumbing around `nacc_private_data_put_user_write()` / `__nacc_put_user_private_or_nocheck()` if needed to run COW outside the raw OpenSBI write attempt. Coder may inspect page-fault, GUP/fault-in, and secure PTE update code to choose the least invasive COW trigger. Coder may route back if existing Linux helpers cannot safely be called from this uaccess context.
- Scope: Linux/OpenSBI private scalar put_user path only, plus any minimal shared enum/status plumbing needed between them. Do not handle the later coredump/writeback __memcpy SUM-off panic in this packet except as post-repair validation evidence.
- Constraints: Human approved immediate coder execution and requested commit coverage for the resulting code, mainly Linux/OpenSBI. Coder may edit Linux/OpenSBI for the private put_user COW-needed flow and should make scoped commit(s) for the completed repair slice after implementation sanity is done. Do not change QEMU enforcement, workload definitions, or global SUM/private-data policy. Do not stage or commit unrelated dirty files, generated logs/images, or pre-existing worktree changes outside this repair scope.
- Open Semantic Questions: No planning blocker remains. Implementation-level choice remains open: whether to encode COW-needed as a new NaCC-private SBI status, reuse a clearly non-fallback existing SBI error such as `SBI_ERR_DENIED_LOCKED`, or carry it through Linux as a positive/special helper result. Coder must document the chosen encoding and why it cannot accidentally fall back to direct S-mode `put_user`.
- Human Concern: Human identified that missing `PTE_W` in workload 3 is expected COW state, not necessarily an invalid access. The repair should guide Linux into normal COW handling before OpenSBI performs the private write.
- Key Assumptions: Workload 3's subshell intentionally triggers `sys_clone`; the observed `clone_flags=0x1200011` include `CLONE_CHILD_SETTID` and `CLONE_CHILD_CLEARTID`, so Linux is expected to write child-tid/rseq-related user bookkeeping fields after fork. The denied addresses `3fb20c10f0` and `3fb20c1808` match earlier `sys_set_tid_address` / `sys_rseq` regions in the same log. The current OpenSBI deny occurs because the target is a private user leaf but lacks `PTE_W`; in COW semantics that should trigger Linux write-fault/COW before the monitor write, not direct monitor mutation of the shared old PFN.
- Evidence / Inference Boundary: Observed evidence comes from `TASK_20260527_095659_workloads_3_8_next_block_validation` and QEMU log `/home/link/NaCC/logs/TASK_20260527_095659_workloads_3_8_01_20260527_104141_qemu_20260527_105432.log`. Observed: workload 3 runs `docker ... busybox sh -c 'a=seed; (...); echo fork_private_done'`, reaches `sys_clone`, logs `private-put-user-write-denied` with `err=-4`, and later enters coredump/writeback panic. Inference: the denied writes are child-tid/rseq bookkeeping on COW/write-protected private pages. This packet does not prove the later coredump `__memcpy` panic is fixed by this repair; that remains a validation question.
- Reconciliation Required: no
- Post-Run Analysis Required: no
- Human Checkpoint Required: no
- Continuation Mode: manual
- Preflight Resolved: yes
- Commit Policy: commit_each_completed_unit
- Definition Of Done: Done when coder provides a reviewer-ready Linux/OpenSBI patch or a no-patch route-back explaining why the COW-needed status approach is not viable. Reviewer/test_runner should later validate workload 3 first.
- Related State:
  - task-local artifacts only; do not list `CURRENT_STATE.md`, `HYPOTHESES.md`, or `NEXT_STEPS.md` here unless the human explicitly says they are current authority for this packet
- Related Ticket / Plan: follows completed failed validation packet `docs/workflow/tasks/completed/TASK_20260527_095659_workloads_3_8_next_block_validation.md`
- Branch / Worktree: `/home/link/NaCC`
- Validation Tier: T1

## Reference Values

- Priority: `P0` / `P1` / `P2` / `P3`
- Lane: `A` / `B` / `C`
- Packet Type: `execution` / `planning` / `analysis`
- Owner Role: `human` / `planner` / `coder` / `reviewer` / `test_runner` / `log_analyzer`
- Status: `draft` / `in_progress` / `needs_review` / `changes_requested` / `needs_test` / `needs_analysis` / `test_failed` / `blocked` / `done`
- Validation Tier: `T0` / `T1` / `T2` / `T3`
- Reconciliation Required: `yes` / `no`
- Post-Run Analysis Required: `yes` / `no`
- Human Checkpoint Required: `no` / `soft` / `hard`
- Continuation Mode: `manual` / `marathon`
- Preflight Resolved: `yes` / `no`
- Commit Policy: `manual` / `commit_each_completed_unit`

## Required Artifacts

- Patch or commit: expected Linux/OpenSBI patch plus scoped commit(s) for the completed repair slice. Commit only task-relevant Linux/OpenSBI changes and matching packet/report updates; leave unrelated dirty files untouched.
- Minimal compile result: bounded coder sanity only; if the only useful proof is heavy `make linux-update` / `make opensbi`, write `deferred to reviewer/test_runner`.
- Test command or batch plan: after reviewer approval, first run focused workload 3 with `config/debug-batch.sh --session-name TASK_20260527_134754_private_put_user_cow_retry_w3_$(date +%Y%m%d_%H%M%S) --tag-prefix TASK_20260527_134754_private_put_user_cow_retry_w3 --ssh-ready-timeout 240 --ssh-auto-timeout 1200 --wait-after-auto 1320 --cmd "docker run --security-opt seccomp=unconfined --rm busybox sh -c 'a=seed; (a=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef; :); echo fork_private_done'"`. If workload 3 clears, route a separate continuation for workloads 4-8.
- Primary log path: source evidence `/home/link/NaCC/logs/TASK_20260527_095659_workloads_3_8_01_20260527_104141_qemu_20260527_105432.log`
- Log path if validation fails: test_runner must preserve generated QEMU/VM/command logs under this packet tag.

## Latest Summary

- 2026-05-27 13:47 +0800 human-approved planning seed: missing `PTE_W` on an otherwise valid private user leaf should route Linux through normal COW/write-fault handling before OpenSBI writes. New packet created because the prior workload 3 packet was a validation/evidence packet, while this is an implementation repair.
- 2026-05-27 13:47 +0800 planner route: focused coder implementation is ready. The repair target is private scalar `put_user` COW mediation, not the later coredump/writeback `__memcpy` panic.
- 2026-05-27 13:52 +0800 human approval update: human approved handing the new task to coder without another permission checkpoint and requested commit coverage for the resulting Linux/OpenSBI code changes. Commit scope is limited to this repair; unrelated dirty worktree state must remain untouched.
- 2026-05-27 14:04 +0800 coder implementation: added a scoped Linux/OpenSBI private scalar `put_user` COW retry flow. OpenSBI returns `SBI_ERR_DENIED_LOCKED` only after S-mode/SUM/width/private user leaf/cross-page validation passes and the remaining blocker is missing `PTE_W`; Linux faults the target writable via `fault_in_safe_writeable()` with SUM temporarily cleared, restores SUM, and retries the SBI private write once.

## Next Handoff

- Next owner: reviewer
- Trigger: Coder produced scoped Linux/OpenSBI commits for the bounded private scalar `put_user` COW-needed retry flow.
- Exact artifact to read first: this packet, then Linux commit `c5a1150fb6bc` and OpenSBI commit `e28f3ca`. Use `git -C linux show c5a1150fb6bc` and `git -C opensbi show e28f3ca`; do not review unrelated pre-existing dirty copy-from-user hunks as part of this packet.
- Exact task for next owner: Review the two scoped commits for packet fidelity. Confirm OpenSBI still hard-denies invalid S-mode/SUM/width/user-leaf/private-PFN/cross-page cases, returns `SBI_ERR_DENIED_LOCKED` only for the validated missing-`PTE_W` private scalar `put_user` case, and never maps COW-needed to `SBI_ERR_NOT_SUPPORTED`. Confirm Linux treats only `SBI_ERR_DENIED_LOCKED` as COW-needed, uses a bounded single retry after `fault_in_safe_writeable()`, preserves `SBI_ERR_NOT_SUPPORTED` as ordinary non-private fallback, and never falls back directly while OpenSBI is still reporting a private COW-needed leaf.
- Expected deliverable: Reviewer approval or changes requested. If approved, route to test_runner for focused workload 3 validation using the packet command in `Required Artifacts`.
- Stop condition: Stop after review verdict and next-owner routing.
- If blocked: Route back to coder with exact file/line findings if the status encoding, retry bound, COW trigger, or fallback behavior is unsafe or inconsistent with the packet.
- Do not do in this turn: Do not change QEMU enforcement, do not remove OpenSBI `PTE_W` protection, do not use `NOT_SUPPORTED` for COW-needed, do not implement coredump/writeback `__memcpy` handling, do not run broad workloads 4-8, and do not commit unrelated dirty files or generated artifacts.

## Coder Result

- Implementation summary: Implemented the bounded private scalar `put_user` COW mediation repair. OpenSBI now splits private user leaf resolution from writability, checks cross-page before writability in `nacc_private_data_uaccess_private_put_user_write()`, and returns `SBI_EDENIED_LOCKED` / `SBI_ERR_DENIED_LOCKED` for the validated missing-`PTE_W` COW-needed case. Linux defines `SBI_ERR_DENIED_LOCKED`, faults the user address writable through `fault_in_safe_writeable()` with SUM cleared/restored around the sleeping helper, and retries the SBI private write once.
- Commit or patch: Linux commit `c5a1150fb6bc` (`riscv: nacc: retry private put_user after COW`) touches `linux/arch/riscv/mm/nacc.c` and `linux/arch/riscv/include/asm/sbi.h`. OpenSBI commit `e28f3ca` (`nacc: signal private put_user COW retry`) touches `opensbi/lib/sbi/sbi_trap_ldst.c`. Existing unrelated dirty copy-from-user hunks in Linux/OpenSBI were intentionally left uncommitted.
- Route chosen and why: Chose `SBI_ERR_DENIED_LOCKED` (`-14`) as the COW-needed status because it is a valid OpenSBI error code, is distinct from `SBI_ERR_NOT_SUPPORTED`, and Linux only handles it inside `nacc_private_data_put_user_write()`. This prevents accidental direct S-mode fallback while OpenSBI still reports a private COW-needed leaf. `SBI_ERR_NOT_SUPPORTED` remains the only "not private path; ordinary fallback allowed" signal.
- Escalations made: none.
- Remaining risks: Coder did not run `make linux-update`, `make opensbi`, QEMU, or workload validation per packet scope. Cheap sanity only: `git -C linux diff --check -- arch/riscv/mm/nacc.c arch/riscv/include/asm/sbi.h`, `git -C opensbi diff --check -- lib/sbi/sbi_trap_ldst.c`, and staged diff checks passed. Reviewer/test_runner still need compile/runtime proof, starting with workload 3. The later coredump/writeback `__memcpy` panic remains intentionally unhandled by this packet.

## Review Result

- Approval status:
- Spec fidelity:
- Fidelity findings:
- Risk review:
- Risk findings:
- Can proceed to test:
- Key files reviewed:
- Human-facing code explanation:
- Why this route still fits the packet:
- Requirements checked directly from code:
- Human-facing summary:

## Test Result

- Command run:
- Build actions:
- Outcome:
- Artifact / log path:

## Analysis Result

- Observed symptom:
- Verdict: acceptable / suspicious / failed
- Key evidence:
- Likely cause:
- Confidence:
- Human-facing summary:
- Recommended next owner:
- Recommended next step:

## Open Questions

- 
