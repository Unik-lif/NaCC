# Task Packet

- Task ID: TASK_<timestamp>_<slug>
- Created: <yyyy-mm-dd hh:mm:ss zzz>
- Priority:
- Lane: <lane>
- Packet Type: <packet_type>
- Owner Role:
- Status: draft
- Goal:
- Critical Intent:
- Preferred Shape:
- Disallowed Shape:
- Allowed Freedom:
- Scope:
- Constraints:
- Open Semantic Questions:
- Human Concern:
- Key Assumptions:
- Evidence / Inference Boundary:
- Reconciliation Required: no
- Post-Run Analysis Required: no
- Human Checkpoint Required: no
- Definition Of Done:
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
- Human Checkpoint Required: `yes` / `no`

## Required Artifacts

- Patch or commit:
- Minimal compile result: bounded coder sanity only; if the only useful proof is a heavy Linux / OpenSBI / QEMU / image rebuild, write `deferred to test_runner`
- Test command or batch plan: required before `test_runner` handoff
- Primary log path:
- Log path if validation fails:

## Latest Summary

- 

## Next Handoff

- Next owner:
- Trigger:
- Exact artifact to read first:
- Exact task for next owner:
- Expected deliverable:
- Stop condition:
- If blocked:
- Do not do in this turn:

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
