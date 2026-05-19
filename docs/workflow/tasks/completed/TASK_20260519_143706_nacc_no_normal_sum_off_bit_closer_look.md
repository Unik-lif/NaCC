# Task Packet

- Task ID: TASK_20260519_143706_nacc_no_normal_sum_off_bit_closer_look
- Created: 2026-05-19 14:37:06 +0800
- Priority: P1
- Lane: A
- Packet Type: execution
- Owner Role: human
- Status: done
- Goal: Design a narrow Linux-side sniff/printk diagnostic for the workload 3 SUM-off private-source COW path, so the next run can show which Linux branch and predicate causes the private NaCC source page to reach direct-map copy.
- Critical Intent: Move slowly and collect branch evidence before attempting another repair. The immediate purpose is to expose the exact Linux-side COW decision path, not to change the COW architecture or prove a final fix.
- Preferred Shape: Small manual diagnostic slice. Add bounded, temporary Linux prints around the COW decision points only after human approval: `do_wp_page()`, `wp_page_copy()`, and `__wp_page_copy_user()`. Prefer first-hit or ratelimited output with enough fields to decide the next repair branch.
- Disallowed Shape: Do not repair in this packet. Do not broaden to workloads 1-8. Do not add broad mediation/shared-buffer/agent-copy infrastructure. Do not revive the archived `PTE_SPECIAL` / `VM_MIXEDMAP` route. Do not treat OpenSBI strict-deny output alone as sufficient for this slice. Do not set a machine next owner until the human approves handoff.
- Allowed Freedom: Planner may inspect the directly relevant Linux COW code and prior named task packets to shape sniff points. A later coder may adjust exact printk formatting and local helper names to fit kernel style, but should keep the diagnostic bounded and temporary.
- Scope: Current branch, workload 3, Linux COW/page-copy branch localization around `linux/mm/memory.c`. Primary scope is `do_wp_page()` -> `wp_page_copy()` -> `__wp_page_copy_user()` for a private `PTE_NACC` source. Fork-time `copy_present_ptes()` / `copy_present_page()` is adjacent evidence only unless the human explicitly broadens scope.
- Constraints: Manual continuation. No validation runs or code implementation from the planner bootstrap/planning turn. Preserve the existing NaCC identity model (`PTE_NACC` plus OpenSBI private bitmap/refcount). Keep prints temporary, low-volume, and diagnostic-only.
- Open Semantic Questions: Resolved for this slice by human approval in-session: instrument the current baseline Linux COW branch only, do not repair yet, and run workload 3 once to identify the branch state.
- Human Concern: The previous repair attempt likely did not cover the actual Linux branch. We know the broad function path, but not the concrete Linux predicate/branch state that allowed the private source page to reach generic copy.
- Key Assumptions: The relevant first workload 3 failure remains the private-source COW path previously observed as `do_wp_page()` / `wp_page_copy()` / `__memcpy`. Current source shows `vm_normal_page()` excludes NaCC private leaves, while `do_wp_page()` reifies the same `PTE_NACC` leaf with `nacc_private_leaf_page()` into `vmf->page`; this can make `__wp_page_copy_user()` take its non-NULL `src` direct-map copy branch.
- Evidence / Inference Boundary: Facts read this turn: the prior strict-deny packet identified the first workload 3 trap in COW/page-copy; the prior repair packet recorded that the attempted SBI COW-copy repair built but still reached `__wp_page_copy_user()` / `__memcpy`; current `linux/mm/memory.c` has NaCC leaf recognition and `pte_mknacc()` install logic but no `nacc_cow*` SBI COW-copy path. Inference: the next useful slice is Linux-side branch/predicate sniffing, not another repair attempt.
- Reconciliation Required: no
- Post-Run Analysis Required: no
- Human Checkpoint Required: hard
- Continuation Mode: manual
- Preflight Resolved: yes
- Commit Policy: manual
- Definition Of Done: Human-approved sniff-point plan or patch captures the Linux-side branch evidence needed for workload 3: whether `vm_normal_page()` returned NULL, whether `nacc_private_leaf_page()` reified the source, the source PFN / `PTE_NACC` state, anon/exclusive/reuse decisions, `nacc_new_private`, and whether `__wp_page_copy_user()` took the non-NULL `src` direct-map copy branch. No repair is required in this packet.
- Related State:
  - task-local artifacts only; do not list `CURRENT_STATE.md`, `HYPOTHESES.md`, or `NEXT_STEPS.md` here unless the human explicitly says they are current authority for this packet
  - Prior strict-deny diagnostic: `docs/workflow/tasks/completed/TASK_20260518_222250_nacc_no_normal_sum_off_bit.md`
  - Prior failed COW repair attempt: `docs/workflow/tasks/completed/TASK_20260518_231819_nacc_cow_sumoff_private_copy_repair.md`
- Related Ticket / Plan:
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

- Patch or commit: temporary Linux diagnostic patch was removed before closeout; root-level OpenSBI gitlink update and diagnostic record are intended for commit
- Minimal compile result: `git -C linux diff --check -- mm/memory.c` passed; `make linux-update` passed; binary string check found `[NACC][cow-sniff]` in `riscv-linux/mm/memory.o`, `riscv-linux/vmlinux`, and `final_image.bin`.
- Test command or batch plan: workload 3 only via `config/debug-batch.sh --session-name TASK_20260519_143706_cow_sniff_w3_v2_20260519_153045 --tag-prefix TASK_20260519_143706_cow_sniff_w3_v2 --ssh-ready-timeout 240 --ssh-auto-timeout 600 --wait-after-auto 720 --cmd "docker run --security-opt seccomp=unconfined --rm busybox sh -c 'a=seed; (a=0123456789abcdef...; :); echo fork_private_done'"`
- Primary log path: `logs/TASK_20260519_143706_cow_sniff_w3_v2_01_20260519_153056_qemu_tmux_capture_live.log`
- Log path if validation fails: same primary QEMU capture; VM pane capture at `logs/TASK_20260519_143706_cow_sniff_w3_v2_01_20260519_153056_vm_tmux_capture_live.log`
- Closeout record: `record/20260519_nacc_cow_private_copy_sniff_closeout.md`

## Latest Summary

- Human wants a slower, smaller diagnostic step. The immediate target is not another COW repair, but choosing and later adding Linux-side sniff prints that reveal the exact branch/predicate path for the workload 3 SUM-off private-source COW trap.
- Code readout so far: current `linux/mm/memory.c` does not contain the failed `nacc_cow*` SBI COW-copy implementation. It does contain the path where `vm_normal_page()` returns NULL for a private `PTE_NACC` leaf, `do_wp_page()` reifies it into `vmf->page`, and `wp_page_copy()` then unconditionally calls `__wp_page_copy_user()` for non-zero PFNs.
- First sniff run was invalid as sniff evidence: after source edits and an apparent rebuild, `[NACC][cow-sniff]` was absent from `riscv-linux/vmlinux` and `final_image.bin`. This was an operator verification mistake; the run still reproduced strict-deny / `__memcpy`, but could not prove whether the sniff points were missed.
- Second sniff patch broadened the enable predicate to active NaCC protected user VAs, not only `pte_nacc(orig_pte)`, and added bounded prints in `do_wp_page()`, `wp_page_copy()`, and `__wp_page_copy_user()`.
- Verified image freshness before rerun: `rg -a -n -o '\[NACC\]\[cow-sniff\] [a-z_-]+' riscv-linux/vmlinux final_image.bin riscv-linux/mm/memory.o` found the strings in all three artifacts.
- Workload 3 rerun hit the sniff point before panic. Key QEMU capture lines: `logs/TASK_20260519_143706_cow_sniff_w3_v2_01_20260519_153056_qemu_tmux_capture_live.log:298` shows `[NACC][cow-sniff] stage=do_wp_page reuse_check ... page_pfn=11f08f folio_anon=1 anon_exclusive=0 can_reuse=0 branch=copy`; line 300 shows strict deny on `pa=0x11f08f000 pfn=0x11f08f`; lines 309-310 show `epc : __memcpy+0x3c/0xf8` and `ra : do_wp_page+0x4a8/0x18c6`; lines 332-333 show kernel panic.
- Current inference boundary: confirmed branch state is `do_wp_page()` private anon COW with `branch=copy` after `nacc_private_leaf_page()` reified the source page. The `wp_page_copy()` / `__wp_page_copy_user()` stage prints did not appear in this capture, likely because `printk_ratelimited` plus immediate panic suppressed later diagnostics; the stack and strict-deny still confirm the eventual direct-map `__memcpy` read.
- Human closeout decision: discard the uncommitted Linux `cow-sniff` diagnostics, keep the useful OpenSBI strict-deny/private-leaf resolution gitlink update, record the lesson in `record/`, and archive this task. The Linux temporary patch was restored out of `linux/mm/memory.c`.

## Next Handoff

- Next owner: none
- Trigger: Task complete and archived after human closeout decision.
- Exact artifact to read first: `docs/workflow/tasks/active/TASK_20260519_143706_nacc_no_normal_sum_off_bit_closer_look.md`
- Exact task for next owner: no automatic next owner; a future repair should use the closeout record and focus on the `copy_mc_user_highpage(to, from, vaddr, vma)` private-source copy boundary.
- Expected deliverable: no further deliverable for this task.
- Stop condition: archived closeout.
- If blocked: Keep discussing one small semantic question at a time; do not infer missing intent from task name or prior route.
- Do not do in this turn: Do not repair or broaden to workloads 1-8.

## Coder Result

- Implementation summary: Added temporary Linux diagnostics in `linux/mm/memory.c`: helper `nacc_cow_sniff_enabled()` plus `printk_ratelimited()` probes around `do_wp_page()`, `wp_page_copy()`, and `__wp_page_copy_user()` for current-branch workload 3 COW branch localization.
- Commit or patch: temporary Linux diagnostic patch only; removed before closeout and not committed.
- Route chosen and why: Current baseline COW branch instrumentation, because human explicitly wanted slow branch sniffing before another repair and the previous repair route did not cover the observed path.
- Escalations made: Used escalated `config/debug-batch.sh` / `tmux` operations to run and capture the VM workload; stopped the panicked task-local tmux/debug-batch session after preserving logs.
- Remaining risks: The Linux diagnostic patch is no longer present. Future repair should rely on OpenSBI strict-deny evidence plus symbol lookup to target the lower-level page-copy helper boundary.

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
  - `git -C linux diff --check -- mm/memory.c` (exit 0)
  - `make linux-update` (exit 0)
  - `rg -a -n -o '\[NACC\]\[cow-sniff\] [a-z_-]+' riscv-linux/vmlinux final_image.bin riscv-linux/mm/memory.o` (exit 0)
  - workload 3 via `config/debug-batch.sh --session-name TASK_20260519_143706_cow_sniff_w3_v2_20260519_153045 --tag-prefix TASK_20260519_143706_cow_sniff_w3_v2 --ssh-ready-timeout 240 --ssh-auto-timeout 600 --wait-after-auto 720 --cmd "docker run --security-opt seccomp=unconfined --rm busybox sh -c 'a=seed; (a=0123456789abcdef...; :); echo fork_private_done'"`
- Build actions: Linux rebuilt successfully, modules installed, and `final_image.bin` regenerated.
- Outcome: Runtime intentionally still fails by the known strict-deny panic, but the sniff point is now present in the image and emitted evidence before the panic. The task-local debug session was stopped after manual log capture.
- Cleanup: `linux/mm/memory.c` was restored to discard temporary `cow-sniff` diagnostics before closeout.
- Artifact / log path:
  - Primary QEMU capture: `logs/TASK_20260519_143706_cow_sniff_w3_v2_01_20260519_153056_qemu_tmux_capture_live.log`
  - VM capture: `logs/TASK_20260519_143706_cow_sniff_w3_v2_01_20260519_153056_vm_tmux_capture_live.log`
  - Auto command file: `logs/test_runner/TASK_20260519_143706_cow_sniff_w3_v2_01_20260519_153056_auto_cmd.txt`

## Analysis Result

- Observed symptom: On workload 3 child COW fault, `do_wp_page()` reaches the private anon copy branch (`branch=copy`) with `page_pfn=11f08f`; strict deny immediately follows when kernel `__memcpy` reads that same private source PFN through the direct map.
- Verdict: acceptable diagnostic result; runtime still fails as expected.
- Key evidence: QEMU capture lines 298-300 show `[NACC][cow-sniff] stage=do_wp_page reuse_check ... can_reuse=0 branch=copy` followed by `[NACC][strict-sumoff-first-deny] ... pa=0x11f08f000 pfn=0x11f08f`; lines 309-310 show `epc : __memcpy+0x3c/0xf8` and `ra : do_wp_page+0x4a8/0x18c6`.
- Likely cause: The current path reifies a private `PTE_NACC` anon source as `vmf->page`; because it is not exclusive/reusable, `do_wp_page()` chooses the generic COW copy path, which performs a direct-map source read while SUM is off.
- Confidence: high for the `do_wp_page()` copy-branch localization; medium for later helper details because rate-limited later-stage sniff prints were not captured.
- Human-facing summary: The sniff now proves we are on the private anon `do_wp_page()` copy path, not a reuse/shared branch. The remaining choice is whether to add one more narrower non-ratelimited print inside the copy helper, or proceed from this branch evidence to a repair route.
- Recommended next owner: none
- Recommended next step: For a new repair task, prefer the lower-level `copy_mc_user_highpage(to, from, vaddr, vma)` boundary: if `from` is a NaCC private data page, replace the ordinary Linux direct-map copy with a trusted OpenSBI copy/deny path.

## Open Questions

- 
