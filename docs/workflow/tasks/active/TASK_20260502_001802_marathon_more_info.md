# Task Packet

- Task ID: TASK_20260502_001802_marathon_more_info
- Created: 2026-05-02 00:18:02 +0800
- Priority:
- Lane: A
- Packet Type: execution
- Owner Role: planner
- Status: in_progress
- Goal: Run a marathon-mode closeout for `record/count_task_packet.md`: produce a decision-oriented PRIVATE_DATA hotspot attribution report that identifies the dominant concrete MEPC family, dominant protected object kind, expected highest-payoff optimization candidate, and whether evidence is sufficient to begin optimization or one narrow attribution repair is still required.
- Critical Intent: This is attribution closeout and optimization target selection only. Do not infer intent from this packet name or child packet names. Preserve the all-private baseline; no ordinary user page may be unsealed, and no enforcement behavior may be relaxed. Continue through child packets until machine review/log analysis finds the `record/count_task_packet.md` targets fulfilled; organizer is only an auto-dispatch script, not an agent owner.
- Preferred Shape: Use this packet as the marathon parent/anchor. Split work into small, concrete child packets in `docs/workflow/tasks/active/`, with only one active child representing the current piece of the marathon work at a time. First use existing artifacts; only create minimal attribution-only code changes if existing evidence cannot answer the required questions.
- Disallowed Shape: Do not implement optimizations. Do not implement shared memory portals, syscall staging buffers, VVAR reclassification, rseq fast paths, robust futex fast paths, teardown batching, or broad Linux hot-path patches. Do not clear, relax, or bypass private bitmap policy. Do not use Linux VMA metadata or ELF-derived manifests as authority to unseal pages. Do not modify application code.
- Allowed Freedom: Planner may create small child packets, assign next owners, and route through coder/test_runner/log_analyzer/reviewer as needed. Coder may make minimal attribution-only changes only after existing artifacts prove insufficient. Long-running validation may continue unattended under marathon assumptions.
- Scope: PRIVATE_DATA trap attribution and closeout reporting for the known hot families in `record/count_task_packet.md`: VDSO_TIME_UPDATE, RSEQ_ABI, ROBUST_FUTEX_EXIT, USER_STRING_COPY, GENERIC_UACCESS, KERNEL_MEMCPY_ADJACENT, MAPPING_TEARDOWN, NACC_RUNTIME, OTHER_KERNEL, and UNKNOWN_MEPC. Required outputs are the workload pass/fail table, MEPC family summary, object-kind summary, family-by-workload, family-by-broad-category, candidate optimization ranking, unknown breakdown, and final ten explicit answers.
- Constraints: Start by parsing existing evidence before editing code. Avoid open-ended Linux hot-path hunting. If code edits become necessary, keep them minimal and attribution-only. Keep original workload behavior unchanged. Under marathon policy, completed implementation/reporting units should be committed before handoff or final review. Treat `record/count_task_packet.md` as immutable canonical input; do not edit it, and ensure following agents read the original count task packet. Do not ask the human for mid-run review; the human is assumed unavailable during the marathon. Only hard blockers may stop for the human. Treat project-level docs as auxiliary context only after this seed is established; they may reveal conflicts or constraints but must not override this human seed.
- Open Semantic Questions: None blocking for initial planning; see Key Assumptions for marathon preflight assumptions.
- Human Concern: The human wants a long unattended marathon run that does not stop merely because the human is asleep or unavailable, while avoiding huge confusing active packets. The work should continue until machine review/log analysis says all targets in `record/count_task_packet.md` are fulfilled. Organizer is only the auto-dispatch script, not the next agent owner.
- Key Assumptions: Marathon mode is approved for multi-hour unattended execution. The human may be asleep or otherwise unavailable, so child packets should continue through machine-owned review/analyzer/planner handoffs instead of asking for human review. Child packets may be created and handed off one at a time. Existing logs/artifacts should be preferred over rerunning heavy workloads. Heavy rebuilds or QEMU/test batches are allowed only when necessary to satisfy the attribution report or validate minimal attribution instrumentation. Commit-per-completed-unit is allowed by the marathon contract, while the canonical `record/count_task_packet.md` must remain unchanged.
- Evidence / Inference Boundary: Evidence must come from existing QEMU logs, final PRIVATE_DATA summaries, MEPC hotspot summaries, `vmlinux.asm`, `System.map`/symbols, prior T4 baseline artifacts, or newly produced attribution-only artifacts if needed. MEPC is kernel instruction address, not user PC. Classifications must distinguish measured evidence from heuristic object-kind inference, and UNKNOWN must be broken down instead of collapsed.
- Campaign ID: TASK_20260502_001802_marathon_more_info
- Parent Packet:
- Active Child Packet: docs/workflow/tasks/active/TASK_20260502_005408_count_fresh_validation_rerun.md
- Return To Parent On Done: no
- Continuation Mode: marathon
- Preflight Resolved: yes
- Commit Policy: commit_each_completed_unit
- Reconciliation Required: no
- Post-Run Analysis Required: no
- Human Checkpoint Required: soft
- Definition Of Done: The marathon is done only when the required report answers all ten final questions in `record/count_task_packet.md`, includes all required tables, symbolizes and groups top MEPCs, breaks down `syscall_buffer_path` by concrete MEPC family, produces object-kind and UNKNOWN breakdown summaries, ranks candidate optimizations, recommends exactly one first optimization target or exactly one narrow attribution repair task, and machine review/log analysis accepts that all target requirements have been fulfilled.
- Related State:
  - `docs/workflow/CURRENT_STATE.md`
  - `docs/workflow/NEXT_STEPS.md`
- Related Ticket / Plan:
- Branch / Worktree:
- Validation Tier:

## Reference Values

- Priority: `P0` / `P1` / `P2` / `P3`
- Lane: `A` / `B` / `C`
- Packet Type: `execution` / `planning` / `analysis`
- Owner Role: `human` / `planner` / `coder` / `reviewer` / `test_runner` / `log_analyzer`
- Status: `draft` / `in_progress` / `needs_review` / `changes_requested` / `needs_test` / `needs_analysis` / `test_failed` / `blocked` / `done`
- Validation Tier: `T0` / `T1` / `T2` / `T3`
- Reconciliation Required: `yes` / `no`
- Post-Run Analysis Required: `yes` / `no`
- Return To Parent On Done: `yes` / `no`
- Continuation Mode: `manual` / `marathon` (`overnight` is a legacy alias)
- Preflight Resolved: `yes` / `no`
- Commit Policy: `manual` / `commit_each_completed_unit`
- Human Checkpoint Required: `no` / `soft` / `hard` (`yes` is treated as `hard` for older packets)

## Required Artifacts

- Patch or commit: documentation/workflow closeout only so far; no source-code patch yet.
- Minimal compile result: deferred to test_runner if the fresh validation requires rebuild.
- Test command or batch plan: run a fresh bounded T1/T4-style validation batch before closeout; do not rely only on the accepted replacement baseline.
- Primary log path: pending fresh validation child.
- Log path if validation fails: pending fresh validation child.

## Latest Summary

- Human seed received: use marathon mode to fulfill `record/count_task_packet.md` by decomposing the long attribution closeout into small active child packets and continuing until machine review/log analysis confirms completion. Human clarified that `record/count_task_packet.md` must remain unchanged, child packets should not infer missing intent or ask the sleeping human for review, and organizer is only an auto-dispatch script rather than an agent owner.
- First child spawned and completed: `docs/workflow/tasks/completed/TASK_20260502_002719_count_existing_evidence_inventory.md` for existing-artifact inventory and feasibility review.
- Completed child result: existing evidence is sufficient; no attribution repair, source-code edit, rebuild, QEMU rerun, or extra log collection is required before closeout.
- Closeout artifact accepted for this campaign: `record/20260430_t4_3_private_data_hotspot_closeout.md` answers the required workload table, broad split, MEPC symbolization, family/object summaries, family-by-workload, family-by-broad-category, candidate ranking, UNKNOWN breakdown, and ten final questions from immutable `record/count_task_packet.md`.
- Auxiliary project state conflict check: `CURRENT_STATE.md`, `HYPOTHESES.md`, and `NEXT_STEPS.md` are older Phase 2 / runtime-context background and do not override this marathon packet's PRIVATE_DATA attribution closeout seed.
- Human correction on 2026-05-02: do not close this marathon from old evidence only. A fresh validation/test slice is required before final closeout; the previous evidence-inventory child remains useful but is not sufficient to mark the campaign complete.
- Campaign status: reopened. Next step is a bounded fresh validation child owned by test_runner.
- Planner update on 2026-05-02: the fresh validation child already exists at `docs/workflow/tasks/active/TASK_20260502_005408_count_fresh_validation_rerun.md`; do not spawn a sibling. The child has been tightened for a test_runner handoff with an exact batch command, log expectations, and a required `log_analyzer` follow-up before parent closeout.

## Next Handoff

- Next owner: test_runner
- Trigger: human rejected old-evidence-only closeout because no new test was run; this parent now has exactly one active fresh-validation child.
- Exact artifact to read first: docs/workflow/tasks/active/TASK_20260502_005408_count_fresh_validation_rerun.md
- Exact task for next owner: Continue the active child, not the parent directly. Run the child's exact fresh validation batch, record launcher/per-run logs and workload pass/fail evidence, then route the child to `log_analyzer` for count closeout evidence reduction. Do not mark this parent done until fresh validation is analyzed.
- Expected deliverable: Updated fresh-validation child packet with concrete Test Result and a `log_analyzer` handoff, followed later by parent closeout only if machine analysis confirms the `record/count_task_packet.md` requirements.
- Stop condition: Stop only after fresh validation evidence exists and the child is handed to `log_analyzer`, or after a concrete test infrastructure blocker is recorded in the child.
- If blocked: Record the exact test infrastructure blocker in the child packet, including command, error, and bounded stale-owner/session evidence if relevant; do not close from old evidence only.
- Do not do in this turn: Do not edit `record/count_task_packet.md`, do not implement optimization, do not spawn a sibling child, and do not mark this parent done until the active child has completed fresh validation and analysis.

## Coder Result

- Implementation summary:
- Commit or patch:
- Route chosen and why:
- Escalations made:
- Remaining risks:

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

- Observed symptom: Prior marathon parent closeout relied on existing evidence only and did not run a fresh test.
- Verdict: suspicious
- Key evidence: The parent's prior Required Artifacts explicitly said "no new test command"; the human rejected that as insufficient for this marathon run.
- Likely cause: Planner treated `record/count_task_packet.md` section 4 as permission to close from existing artifacts, but did not confirm whether this marathon run required fresh validation for acceptance criterion 1.
- Confidence: high that the workflow closeout was premature.
- Human-facing summary: Reopen the campaign and run a fresh validation child before final closeout.
- Recommended next owner: test_runner via active child `docs/workflow/tasks/active/TASK_20260502_005408_count_fresh_validation_rerun.md`
- Recommended next step: Run the active fresh-validation child and require logs plus log analysis before marking the parent complete.

## Open Questions

- No blocking preflight questions remain under current assumptions. If the human wants a different commit policy, runtime limit, or stricter approval gate before minimal attribution-only code changes, update this packet before launching child work.
