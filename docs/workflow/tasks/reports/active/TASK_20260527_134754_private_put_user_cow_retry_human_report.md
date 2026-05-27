# Human Progress Report

- Task ID: TASK_20260527_134754_private_put_user_cow_retry
- Task Packet: `docs/workflow/tasks/active/TASK_20260527_134754_private_put_user_cow_retry.md`
- Created: 2026-05-27 13:47:55 +0800
- Purpose: cumulative human-readable updates appended by coder, reviewer, and log_analyzer
- Append Rule: add a new timestamped section for each new turn; do not rewrite older entries
- Reading Hint: newest updates are appended at the end of this file

## 2026-05-27 13:47:43 +0800 - planner

Seeded a focused Linux/OpenSBI repair packet from the workload 3 validation evidence and human clarification.

Route: OpenSBI should keep hard private-write validation, but if the only remaining blocker is missing `PTE_W` on a valid private user leaf, return a distinct COW-needed/retry status. Linux should then trigger normal write-fault/COW handling for the target `user_va` and retry the OpenSBI private scalar `put_user` write.

## 2026-05-27 13:52:42 +0800 - planner

Human approved immediate coder execution and requested commit coverage for the resulting code, mainly Linux/OpenSBI.

Packet updated to `Commit Policy: commit_each_completed_unit`. Coder should commit only task-relevant Linux/OpenSBI repair changes and matching packet/report updates, leaving unrelated existing dirty files and generated artifacts untouched.

## 2026-05-27 14:04:07 +0800 - coder

Implemented the bounded private scalar `put_user` COW retry flow.

Changed files in scoped commits:
- Linux commit `c5a1150fb6bc` (`riscv: nacc: retry private put_user after COW`): `linux/arch/riscv/mm/nacc.c`, `linux/arch/riscv/include/asm/sbi.h`.
- OpenSBI commit `e28f3ca` (`nacc: signal private put_user COW retry`): `opensbi/lib/sbi/sbi_trap_ldst.c`.

Route: OpenSBI keeps hard validation and now returns `SBI_ERR_DENIED_LOCKED` only after it has a valid private user leaf, the scalar write does not cross a page, and missing `PTE_W` is the remaining blocker. Linux treats only that status as COW-needed, clears SUM before `fault_in_safe_writeable()`, restores SUM, and retries the SBI private write once. `SBI_ERR_NOT_SUPPORTED` remains the ordinary non-private fallback signal, so COW-needed cannot accidentally fall back to direct S-mode `put_user`.

Intentionally left unchanged: QEMU enforcement, global SUM/private-data policy, workload definitions, fork/rseq semantics, coredump/writeback `__memcpy`, and unrelated pre-existing dirty copy-from-user hunks in the Linux/OpenSBI working trees.

Cheap sanity run: `git -C linux diff --check -- arch/riscv/mm/nacc.c arch/riscv/include/asm/sbi.h`, `git -C opensbi diff --check -- lib/sbi/sbi_trap_ldst.c`, plus staged diff checks before the scoped commits. No whitespace issues were reported.

Deferred to reviewer/test_runner: `make linux-update`, `make opensbi`, QEMU boot, and focused workload 3 validation. The later coredump/writeback panic remains only a post-repair validation question for this packet.
