# Human Progress Report

- Task ID: TASK_20260514_103148_nacc_fix_refcount_metadata
- Task Packet: `docs/workflow/tasks/active/TASK_20260514_103148_nacc_fix_refcount_metadata.md`
- Created: 2026-05-14 10:31:48 +0800
- Purpose: cumulative human-readable updates appended by coder, reviewer, and log_analyzer
- Append Rule: add a new timestamped section for each new turn; do not rewrite older entries
- Reading Hint: newest updates are appended at the end of this file

## 2026-05-14 11:34:57 +0800 - coder

Implemented the minimal PFN-global private-data refcount prototype.

Changed files:
- `opensbi/lib/sbi/sm/bitmap.c`, `opensbi/include/sm/bitmap.h`: added Agent-resident `u32` PFN refcount lookup, acquire, and release semantics under the bitmap lock. Acquire sets `PRIVATE_DATA`; release decrements trusted metadata and clears `PRIVATE_DATA` only when the trusted count reaches zero.
- `opensbi/include/sbi/sbi_domain.h`, `opensbi/lib/sbi/sbi_domain.c`, `agent/include/params.h`: reserved a fixed 4 MiB refcount arena at the tail of the Agent physical region, added a narrower M-only PMP reservation before the broader Agent region, and excluded the carve-out from the Agent allocator.
- `opensbi/include/sm/sm.h`, `opensbi/lib/sbi/sm/sm.c`, `opensbi/lib/sbi/sbi_ecall_nacc.c`, `linux/arch/riscv/include/asm/sbi.h`, `linux/arch/riscv/include/asm/nacc.h`, `linux/arch/riscv/kernel/sys_riscv.c`: added a new acquire-private-PFN SBI call and kept the existing retire-private-PFN call as the release event.
- `opensbi/lib/sbi/sm/vm.c`: changed private leaf tag sync to acquire trusted PFN refs rather than directly setting the bitmap tag.
- `linux/mm/memory.c`: acquired trusted refs for fork-copy inherited NaCC special leaves, new protected anonymous fault leaves, and protected COW replacement leaves; installed new protected anon/COW leaves as direct `pte_special` 4 KiB leaves; released old special PFNs after COW/zap clears the Linux mapping; forced protected active anonymous allocation paths down to order-0.

Why it was needed:
The previous COW/zap path could clear the PFN-wide `PRIVATE_DATA` tag based on one Linux mapping removal. The new path makes OpenSBI/trusted metadata decide whether a PFN is still live before the bitmap transitions back to `NORMAL`.

Nontrivial assumption recorded:
Fork-copy is now treated as the authoritative acquire event for inherited child mappings. Child attach validates secure non-leaf PTPs but does not re-sync/acquire inherited leaves again, because doing both would double-count the same child mappings.

Intentionally left unchanged:
No cid/pid/root ownership database, batch teardown ABI, large-folio lifecycle model, or broad VM refactor was added. The old retire SBI ID remains as the release event to keep the ABI change minimal.

Cheap sanity checks run:
- `git -C linux diff --check -- mm/memory.c arch/riscv/kernel/sys_riscv.c arch/riscv/include/asm/nacc.h arch/riscv/include/asm/sbi.h`
- `git -C opensbi diff --check -- lib/sbi/sm/bitmap.c include/sm/bitmap.h lib/sbi/sm/sm.c include/sm/sm.h lib/sbi/sbi_ecall_nacc.c lib/sbi/sm/vm.c include/sbi/sbi_domain.h lib/sbi/sbi_domain.c`
- `git -C agent diff --check -- include/params.h`

Deferred:
No `make linux-update`, `make opensbi`, `make agent-update`, QEMU run, or workload 1..8 proof was run by coder. Heavy build/runtime validation is deferred to reviewer/test_runner per packet instructions.

## 2026-05-14 11:39:33 +0800 - reviewer

Verdict: changes requested. I reviewed the packet first, then the concrete Linux/OpenSBI/Agent diff and nearby implementation paths. I did not use repo-level state docs.

What I checked directly:
- OpenSBI refcount metadata in `opensbi/lib/sbi/sm/bitmap.c`, the SBI acquire/release path, initial private-tag sync, and child-attach no-resync behavior.
- Linux fork-copy, anonymous fault, COW replacement, old-special-PFN release, and zap release paths in `linux/mm/memory.c`.
- Existing attach detach behavior in `linux/arch/riscv/mm/nacc.c`, and new/expanded VMA behavior in `linux/mm/mmap.c`.
- Agent carve-out exclusion in `agent/include/params.h` and OpenSBI domain protection setup in `opensbi/lib/sbi/sbi_domain.c`.

Most important finding:
The route is faithful in the core security model, but one spec-fidelity gap remains. `nacc_should_install_private_leaf()` only installs/acquires new direct special private leaves when the VMA already has `VM_MIXEDMAP`. Existing attach marks walked VMAs as `VM_MIXEDMAP`, but I did not find a corresponding path for newly created or expanded anonymous VMAs after NaCC activation. Those post-attach faults can still become ordinary Linux anonymous pages in the protected range, which conflicts with the packet requirement for new protected user-data leaves to enter the detached private-data lifecycle.

Short code explanation:
The patch moves private-data tag retirement authority into OpenSBI by adding a trusted PFN-global refcount array in protected Agent memory. Linux reports acquire/release events around attach/fork/fault/COW/zap, while OpenSBI only clears `PRIVATE_DATA` when the trusted PFN count reaches zero.

What the human should watch next:
The next coder pass should stay minimal and repair the VMA coverage issue, not expand into owner records or large-folio policy. After that, reviewer can re-check fidelity and then hand off workload 1..8 validation.

## 2026-05-14 11:42:48 +0800 - coder

Repaired the reviewer-reported `VM_MIXEDMAP` coverage gap for new active anonymous VMAs.

Changed files:
- `linux/mm/mmap.c`: added a small local predicate for active NaCC, protected-range, private anonymous VMA ranges. `__mmap_region()` now sets `VM_MIXEDMAP` before VMA merge/new-VMA creation for eligible private anonymous `mmap()` ranges, and `do_brk_flags()` does the same before brk merge/new-VMA creation.
- `docs/workflow/tasks/active/TASK_20260514_103148_nacc_fix_refcount_metadata.md`: updated owner/status, `Next Handoff`, and `Coder Result` for reviewer handoff.

Why it was needed:
The existing direct special-leaf install path in `linux/mm/memory.c` intentionally requires `VM_MIXEDMAP`. Attach already marks walked VMAs, but anonymous VMAs created or expanded after NaCC activation could miss that prerequisite and later fault ordinary Linux anonymous pages. The repair preserves the existing memory fault gate and makes the new/expanded anonymous VMA paths enter the expected mixed-map lifecycle.

Intentionally left unchanged:
No owner database, batch ABI, large-folio support, or broader VM refactor was added. The existing `nacc_should_install_private_leaf()` gate remains unchanged, and file-backed/private mapping policy was not broadened beyond the reviewer-requested active private anonymous VMA repair.

Cheap sanity checks run:
- `git -C linux diff --check -- mm/mmap.c`

Deferred:
No `make linux-update`, OpenSBI/Agent rebuild, QEMU run, or workload 1..8 proof was run by coder. Heavy build/runtime validation remains deferred to reviewer/test_runner per packet instructions.

## 2026-05-14 11:45:50 +0800 - reviewer

Verdict: approve for `test_runner`. I reviewed the packet first, then the concrete Linux/OpenSBI/Agent diffs and the bounded repair in `linux/mm/mmap.c`. I did not use repo-level state docs.

What I checked directly:
- `linux/mm/mmap.c`: the new active/private/anonymous VMA predicate and the `__mmap_region()` / `do_brk_flags()` flag insertion points.
- `linux/mm/memory.c`: the existing `nacc_should_install_private_leaf()` gate that requires `VM_MIXEDMAP`, plus the fault/COW/fork/zap lifecycle shape from the prior review.
- `linux/arch/riscv/mm/nacc.c`: existing attach detach still marks walked VMAs as `VM_MIXEDMAP`.
- OpenSBI/Agent touched paths at review scope to confirm the route did not expand into owner records, batch ABI, or large-folio support.

Most important finding:
The previous fidelity blocker is repaired. Active NaCC protected private anonymous `mmap()` and `brk` ranges are now marked `VM_MIXEDMAP` before VMA merge/new-VMA creation, so later anonymous fault/COW leaves can satisfy the existing direct `pte_special` private-leaf gate. The repair is narrow and stays inside the packet's PFN-global trusted metadata model.

Short code explanation:
The patch stores trusted private-PFN refcounts in protected Agent memory and makes OpenSBI clear `PRIVATE_DATA` only after the trusted count reaches zero. Linux still does normal layout/accounting work, but it reports acquire/release events for attach/fault/fork/COW/zap. The latest mmap repair makes new active anonymous VMAs enter the same special-leaf lifecycle instead of bypassing it as ordinary anonymous pages.

What the human should watch next:
Heavy proof is still missing. Test_runner should build/package the touched Linux/OpenSBI/Agent components, run exactly one bounded workload 1..8 batch, and preserve logs showing boot-time refcount arena fit, private-data acquire/release/tag behavior, and RSS/fork/COW/zap-sensitive behavior. Do not broaden this into marathon mode or new workloads from this handoff.

## 2026-05-14 11:55:16 +0800 - coder

Repaired the OpenSBI build failure reported by test_runner.

Changed files:
- `opensbi/lib/sbi/sm/sm.c`: changed the child-attach validation call from `(pgtbl_t)SATP_PA(satp)` to `(pgtbl_t)(SATP_PA(satp))`.
- `docs/workflow/tasks/active/TASK_20260514_103148_nacc_fix_refcount_metadata.md`: updated owner/status, `Next Handoff`, and `Coder Result` for reviewer handoff.

Why it was needed:
`SATP_PA(satp)` expands to a shift expression. Without parentheses, the cast to `pgtbl_t` bound before the shift, so the compiler saw a pointer value being shifted and failed with `invalid operands to binary <<`. The fixed call now matches the existing parenthesized cast pattern used elsewhere in `sm.c`.

Intentionally left unchanged:
No lifecycle semantics were changed. The child-attach no-resync model, trusted PFN refcount path, Linux VMA repair, Agent carve-out, and SBI ABI remain as previously reviewed. I did not run or modify the workload validation plan.

Cheap sanity checks run:
- `git diff --check -- opensbi/lib/sbi/sm/sm.c`
- Targeted compile of `opensbi/lib/sbi/sm/sm.c` using the `-Werror` OpenSBI compile command from `opensbi/compile_commands.json`, which was produced by the failed `make opensbi` run. This passed.

Deferred:
No full `make opensbi`, `make agent-update`, QEMU run, or workload 1..8 validation was run by coder. Full build/package and runtime proof remain deferred to reviewer/test_runner per packet workflow.

## 2026-05-14 11:59:59 +0800 - reviewer

Verdict: approve for `test_runner`. I reviewed the packet first, then the failed OpenSBI build log and the bounded `opensbi/lib/sbi/sm/sm.c` repair. I did not use repo-level state docs.

What I checked directly:
- `logs/test_runner_build_opensbi_TASK_20260514_103148_20260514_115213.log`: the failure was at `sm.c:490`, where `(pgtbl_t)SATP_PA(satp)` caused the cast to bind before the macro's shift expression.
- `opensbi/include/sm/vm.h`: `SATP_PA(satp)` expands to `SATP_PPN(satp) << 12`.
- `opensbi/lib/sbi/sm/sm.c`: the repaired call now uses `(pgtbl_t)(SATP_PA(satp))`, matching the surrounding OpenSBI pattern.

Most important finding:
The build repair is faithful and minimal. It fixes macro/cast precedence without changing the child-attach no-resync model, the trusted PFN refcount route, or the packet's OpenSBI-authoritative tag-retirement control model.

Short code explanation:
`SATP_PA(satp)` computes a physical address by shifting the SATP PPN. The repaired code casts the completed physical-address expression to `pgtbl_t`; before the fix, the compiler saw a pointer value being shifted, which produced the OpenSBI build error.

What the human should watch next:
This approval is not runtime proof. Test_runner still needs a normal build/package pass for Linux, OpenSBI, and Agent as needed, followed by exactly one workload 1..8 T1 validation batch with private-data refcount/tag evidence and RSS/fork/COW/zap-sensitive evidence preserved.

## 2026-05-14 13:00:47 +0800 - log_analyzer

Verdict: acceptable for the requested T1 build/runtime smoke, with one observability caveat.

Dominant signal:
The run is successful-but-noisy. OpenSBI, Linux, Agent, and `final_image.bin` were freshly rebuilt, the workload 1..8 wrapper exited 0, all eight batch entries ended `status=ok`, and every VM auto command exited `code=0`.

Key evidence:
- Build logs: `logs/test_runner_build_opensbi_TASK_20260514_103148_20260514_122101.log`, `logs/test_runner_build_linux_update_TASK_20260514_103148_20260514_122117.log`, and `logs/test_runner_build_agent_update_TASK_20260514_103148_20260514_122533.log` all ended with `EXIT_CODE=0`.
- Fresh artifacts: `fw_jump.*` timestamp 12:21:11, Linux `Image` 12:24:21, `agent.*` 12:25:41, and `final_image.bin` 12:25:42.
- Wrapper log: `logs/test_runner_batch_TASK_20260514_103148_20260514_122601.log` ran exactly one workload 1..8 batch and ended `EXIT_CODE=0`.
- Runtime logs: all eight VM logs show SSH ready plus `[NaCC][ssh-auto-exit] code=0`; visible workload markers include `kernel_read_done`, `kernel_write_done`, `fork_private_done`, `done`, `alpha`, or `6` where expected.
- QEMU logs: every run reported `Boot HART PMP Count : 16` and `The Agent is loaded into PMP protection region, and the original part is cleared.`
- Private-data evidence: all QEMU logs contain nonzero `PRIVATE_DATA context` updates/clears/hits and `private-sum-census-total`; all checked summaries have `context_overflow=0`. Fork-sensitive runs logged child validation, including `Child user page tables validated; inherited private refs came from fork-copy.`
- Failure search: zero hits for refcount-arena panic, refcount overflow, private PFN release failure, SIGBUS, `BUG: Bad rss-counter state`, `BUG:`, or `Oops` across the eight QEMU logs.

What remains uncertain:
The current logs do not print individual PFN acquire/release refcount values. The evidence shows no visible refcount failure and coherent lifecycle activity, but it does not directly prove exact PFN refcount balance.

Next decision:
Hand back to `planner`. There is no concrete first-bad runtime point for direct coder repair. Planner should decide whether this T1 evidence is enough for closeout/reviewer signoff or whether to open a narrow follow-up for explicit PFN refcount diagnostics.

## 2026-05-14 13:55:38 +0800 - planner

Route decision: accept the completed T1 build/runtime smoke as sufficient for this prototype tier, then route to reviewer for final closeout/signoff.

Why this is not going back to coder:
The fresh run has no concrete runtime failure, RSS/refcount panic, `BUG`, `Oops`, SIGBUS, or private-PFN release failure to repair. The missing direct per-PFN acquire/release values are an observability caveat, not evidence of a broken lifecycle path.

Prepared handoff:
The packet now names `reviewer` as the next owner, with a manual approval gate. Reviewer should decide closeout with the caveat, or request a narrow follow-up diagnostics packet if exact trusted-refcount balance visibility is required.
