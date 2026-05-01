# Task Packet

- Task ID: TASK_20260502_005408_count_fresh_validation_rerun
- Created: 2026-05-02 00:54:08 +0800
- Priority:
- Lane: A
- Packet Type: execution
- Owner Role: test_runner
- Status: in_progress
- Goal: Run a fresh bounded validation batch for the count closeout so the marathon result is not based only on old evidence.
- Critical Intent: Produce fresh validation evidence for the parent count closeout. This child is test execution and evidence capture only; it must not decide the optimization target, close the parent, or replace the canonical requirements in `record/count_task_packet.md`.
- Preferred Shape: Run one bounded T1-style batch using `config/debug-batch.vma_guided_bitmap_t1.txt`, capture a launcher log plus per-workload QEMU/VM logs, summarize workload pass/fail and exit markers, then route to `log_analyzer` for evidence reduction before the parent closeout.
- Disallowed Shape: Do not edit `record/count_task_packet.md`, do not edit source code, do not implement or prototype optimizations, do not relax PRIVATE_DATA/private-bitmap enforcement, do not unseal ordinary user pages, do not spawn sibling slices, and do not mark the parent campaign done.
- Allowed Freedom: Test runner may skip rebuilds if only workflow/docs/record files changed, or rebuild only changed runtime components per `docs/workflow/AGENT_TEST_RUNNER.md`. If the fixed batch session name already exists, use a unique suffix and record it instead of deleting unknown sessions. If the run fails, preserve the relevant failed window/logs when the runner policy says to do so.
- Scope: Execute the eight commands in `config/debug-batch.vma_guided_bitmap_t1.txt`; record component dirty/build status, batch command, launcher log, per-run QEMU logs, per-run VM logs, workload output/exit status, and whether final PRIVATE_DATA summaries are present for analyzer use.
- Constraints: Do not edit record/count_task_packet.md. Do not implement optimization. Run validation only; preserve all-private enforcement. Record launcher, QEMU, and VM log paths. If infrastructure blocks the run, record the exact blocker instead of marking the parent done. Do not perform broad VM/image cleanup from this packet unless a stale owner is concretely identified and the cleanup target is bounded by captured evidence.
- Open Semantic Questions: None blocking. If validation infrastructure cannot launch due an image lock, stale tmux session, or missing artifact, record the exact blocker and route instead of closing from old evidence.
- Human Concern: The human rejected the previous old-evidence-only closeout; this child exists specifically to add a fresh run before final analysis and parent closeout.
- Key Assumptions: Marathon mode is approved for multi-hour unattended execution. The human may be asleep or otherwise unavailable, so child packets should continue through machine-owned review/analyzer/planner handoffs instead of asking for human review. Child packets may be created and handed off one at a time. Existing logs/artifacts should be preferred over rerunning heavy workloads. Heavy rebuilds or QEMU/test batches are allowed only when necessary to satisfy the attribution report or validate minimal attribution instrumentation. Commit-per-completed-unit is allowed by the marathon contract, while the canonical `record/count_task_packet.md` must remain unchanged.
- Evidence / Inference Boundary: Test runner may report observed command output, exit markers, build actions, and log paths. MEPC family attribution, object-kind inference, optimization ranking, and final count-task answers belong to `log_analyzer`/parent closeout after fresh logs exist.
- Campaign ID: TASK_20260502_001802_marathon_more_info
- Parent Packet: docs/workflow/tasks/active/TASK_20260502_001802_marathon_more_info.md
- Active Child Packet: 
- Return To Parent On Done: yes
- Continuation Mode: marathon
- Preflight Resolved: yes
- Commit Policy: commit_each_completed_unit
- Reconciliation Required: no
- Post-Run Analysis Required: no
- Human Checkpoint Required: soft
- Definition Of Done: Fresh validation logs exist, workload results are summarized, and the packet routes to log_analyzer for evidence reduction before parent closeout.
- Related State:
  - `docs/workflow/CURRENT_STATE.md`
  - `docs/workflow/NEXT_STEPS.md`
- Related Ticket / Plan:
- Branch / Worktree:
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
- Return To Parent On Done: `yes` / `no`
- Continuation Mode: `manual` / `marathon` (`overnight` is a legacy alias)
- Preflight Resolved: `yes` / `no`
- Commit Policy: `manual` / `commit_each_completed_unit`
- Human Checkpoint Required: `no` / `soft` / `hard` (`yes` is treated as `hard` for older packets)

## Required Artifacts

- Patch or commit: none expected; this is validation-only unless test_runner records workflow packet/report updates.
- Minimal compile result: record component status for `qemu/`, `linux/`, `opensbi/`, and `agent/`; rebuild only changed runtime components per `docs/workflow/AGENT_TEST_RUNNER.md`.
- Test command or batch plan: config/debug-batch.sh --session-name t4-count-fresh-20260502_005408 --tag-prefix t4_count_fresh --wait-after-auto 180 --cmd-file config/debug-batch.vma_guided_bitmap_t1.txt > logs/t4-count-fresh-20260502_005408.launcher.log 2>&1
- Primary log path: expected launcher log `logs/t4-count-fresh-20260502_005408.launcher.log`; expected per-run logs `logs/t4_count_fresh_*_qemu_*.log` and `logs/t4_count_fresh_*_vm_*.log`.
- Log path if validation fails: record the launcher log plus any kept tmux session/window, live VM log, and partial QEMU/VM logs printed by `config/debug-batch.sh`.

## Latest Summary

- Parent campaign is reopened because the human required fresh validation before final closeout.
- This child is the single active fresh-validation slice for the campaign; no sibling slice should be spawned while it is active.
- Route is validation-first: run the existing T1-style batch, collect fresh logs, then hand the child to `log_analyzer` for comparison against `record/count_task_packet.md` and the existing closeout evidence.

## Next Handoff

- Next owner: test_runner
- Trigger: human rejected the previous old-evidence-only marathon closeout; the parent campaign already points to this child as the active fresh-validation slice.
- Exact artifact to read first: record/count_task_packet.md
- Exact task for next owner: Run the exact batch command in `Test command or batch plan`, waiting for completion. Record component status/build actions, launcher log, per-run QEMU/VM logs, workload output/exit markers, and whether each run produced final PRIVATE_DATA summaries. Then set the child to `needs_analysis` and route to `log_analyzer` using `scripts/request_post_run_analysis.sh` or an equivalent fully filled handoff.
- Expected deliverable: Fresh validation logs and a concise Test Result summary in this child packet, followed by a concrete `log_analyzer` handoff for MEPC/object/count-task evidence reduction.
- Stop condition: Stop after fresh validation evidence exists and this child is handed to `log_analyzer`, or after an exact infrastructure blocker is recorded with command, error, and ownership/session evidence.
- If blocked: Record the exact failing command and stderr/log evidence. For stale sessions or image ownership, capture bounded evidence such as session name, window/pane, PID, and lock owner; do not mark the parent done from old evidence.
- Do not do in this turn: Do not edit `record/count_task_packet.md`, do not edit source code, do not implement optimization, do not perform attribution analysis beyond pass/fail/log-path summary, do not spawn sibling slices, and do not close the parent campaign.

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
