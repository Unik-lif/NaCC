# Task Packet

- Task ID: TASK_20260502_001802_marathon_more_info
- Created: 2026-05-02 00:18:02 +0800
- Priority:
- Lane: A
- Packet Type: execution
- Owner Role: human
- Status: done
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
- Active Child Packet: 
- Return To Parent On Done: no
- Continuation Mode: marathon
- Preflight Resolved: yes
- Commit Policy: commit_each_completed_unit
- Reconciliation Required: no
- Post-Run Analysis Required: no
- Human Checkpoint Required: no
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

- Patch or commit: documentation/workflow closeout only; no source-code patch, attribution code, rebuild, or QEMU rerun was needed for this planner closeout.
- Minimal compile result: not required; campaign closed from existing attribution artifacts and completed child inventory.
- Test command or batch plan: no new test command; evidence source is the accepted replacement baseline and existing closeout report.
- Primary log path: `record/20260430_t4_3_private_data_hotspot_closeout.md`
- Log path if validation fails: not applicable; completed child analysis accepted existing evidence as sufficient.

## Latest Summary

- Human seed received: use marathon mode to fulfill `record/count_task_packet.md` by decomposing the long attribution closeout into small active child packets and continuing until machine review/log analysis confirms completion. Human clarified that `record/count_task_packet.md` must remain unchanged, child packets should not infer missing intent or ask the sleeping human for review, and organizer is only an auto-dispatch script rather than an agent owner.
- First child spawned and completed: `docs/workflow/tasks/completed/TASK_20260502_002719_count_existing_evidence_inventory.md` for existing-artifact inventory and feasibility review.
- Completed child result: existing evidence is sufficient; no attribution repair, source-code edit, rebuild, QEMU rerun, or extra log collection is required before closeout.
- Closeout artifact accepted for this campaign: `record/20260430_t4_3_private_data_hotspot_closeout.md` answers the required workload table, broad split, MEPC symbolization, family/object summaries, family-by-workload, family-by-broad-category, candidate ranking, UNKNOWN breakdown, and ten final questions from immutable `record/count_task_packet.md`.
- Auxiliary project state conflict check: `CURRENT_STATE.md`, `HYPOTHESES.md`, and `NEXT_STEPS.md` are older Phase 2 / runtime-context background and do not override this marathon packet's PRIVATE_DATA attribution closeout seed.
- Campaign status: complete. The next semantic direction, if the human wants to continue, is a new narrow VDSO/VVAR classification experiment packet. Do not continue optimization work under this closeout packet.

## Next Handoff

- Next owner: human
- Trigger: marathon attribution closeout campaign completed from existing evidence
- Exact artifact to read first: record/20260430_t4_3_private_data_hotspot_closeout.md
- Exact task for next owner: Read the completed closeout if desired and decide whether to seed a new, separate VDSO/VVAR classification experiment. No machine-owned continuation remains in this packet.
- Expected deliverable: Human acknowledgment or a fresh task seed for the next optimization-planning campaign; this packet itself needs no further machine route.
- Stop condition: Stop here for this packet. The count closeout requirements are satisfied and the campaign is complete.
- If blocked: Not applicable for this completed packet. Any future semantic concern should be seeded as a new packet rather than reopening this closeout campaign.
- Do not do in this turn: Do not edit `record/count_task_packet.md`, do not implement optimization, do not run QEMU/rebuild for this closeout, and do not start VDSO/VVAR implementation under this packet.

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

- Observed symptom: Marathon parent returned from the completed existing-evidence inventory child with sufficient closeout evidence already available.
- Verdict: acceptable
- Key evidence: `record/20260430_t4_3_private_data_hotspot_closeout.md` contains all required count-packet outputs and final answers; `docs/workflow/tasks/completed/TASK_20260502_002719_count_existing_evidence_inventory.md` records that no attribution repair, code edit, rebuild, QEMU rerun, or extra collection is needed.
- Likely cause: The accepted replacement baseline already exposed a dominant `VDSO_TIME_UPDATE` / `VDSO_VVAR_TIME_DATA` pattern, making extra attribution work unnecessary for first-target selection.
- Confidence: high for campaign closeout sufficiency; medium for PFN-origin/object-origin precision, which remains documented as an evidence boundary rather than a blocker.
- Human-facing summary: The closeout campaign is complete. Existing evidence points to VDSO/VVAR special classification or kernel-maintained ABI-data treatment as the single first optimization target while preserving all-private ordinary user memory.
- Recommended next owner: human
- Recommended next step: If continuing, seed a new narrow VDSO/VVAR classification experiment packet; do not continue under this attribution closeout packet.

## Open Questions

- No blocking preflight questions remain under current assumptions. If the human wants a different commit policy, runtime limit, or stricter approval gate before minimal attribution-only code changes, update this packet before launching child work.
