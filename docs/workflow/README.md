# NaCC Workflow Layer

This directory is the lightweight coordination layer shared by humans and agents.
It exists for three purposes:

- capture the current state
- capture the next step
- capture role boundaries

It does not replace `docs/agent/`:

- `docs/agent/` stores long-lived project knowledge, stable design conclusions, and code-entry references
- `docs/workflow/` stores the current round's state, plans, experiment logs, and collaboration docs

## What Human Readers Should Open First

If you only want to know what the project is doing right now, read these files in order:

1. `HUMAN_BOOTSTRAP_TLDR.md`
2. `CURRENT_STATE.md`
3. `NEXT_STEPS.md`
4. `PLAN_20260327_secure_runtime_context.md`
5. `PLAN_20260322_container_validation.md`
6. `PLAN_20260318_linux_friendly_fork.md`

These answer:

- what the project is currently doing
- what should happen next
- how the trusted runtime-context problem is currently framed
- how the current validation plan is structured
- what the long-term fork direction is

## Minimum Read Set For A New Session

Usually these are enough to start useful work:

- `CURRENT_STATE.md`
- `NEXT_STEPS.md`
- `HYPOTHESES.md`
- `HUMAN_BOOTSTRAP.md`
- `HARNESS_V2.md`
- `HARNESS_V2_PLAN.md` when reviewing or shaping the next automation step
- `SESSION_RECYCLE.md` when the current session is getting noisy or a fresh role handoff is needed

Only read `HARNESS_V1.md` if you need the historical foundation for the packet-based workflow.

## When To Read More

- For long-term decisions:
  - `DECISIONS.md`
- For structural understanding:
  - `ARCHITECTURE_NOTES.md`
  - `IMPLEMENTATION_NOTES.md`
- For executable commands:
  - `KNOWN_GOOD.md`
  - `PLAN_20260322_container_validation.md`
- For single-run or batch testing:
  - `AGENT_TEST_RUNNER.md`
  - `KNOWN_GOOD.md`
  - Batch runs should normally report only the `launcher.log` path first; agents do not need to keep following the foreground log unless asked.
- For minimal compile sanity checks:
  - start from the project `Makefile`
  - for Linux quick checks, reuse the `ARCH` / `O` / `CROSS_COMPILE` parameters used by `make linux`
  - compile a single object when possible; do not default to `make linux-update`
- For experiment history:
  - `EXPERIMENT_LOG.md`
- For role boundaries:
  - `AGENT_PLANNER.md`
  - `AGENT_CODER.md`
  - `AGENT_REVIEWER.md`
  - `AGENT_ORGANIZER.md`
  - `AGENT_LOG_ANALYZER.md`
  - `AGENT_PAPER_SCOUT.md`
  - `AGENT_TEST_RUNNER.md`
- For guardrails:
  - `WORKFLOW_GUARDRAILS.md`
  - `HUMAN_OPERATOR_CHECKLIST.md`

## Recommended Iteration Loop

1. Update `CURRENT_STATE.md`
2. Review `NEXT_STEPS.md`
3. Use `HUMAN_BOOTSTRAP.md` / `HARNESS_V2.md` as the current harness entrypoint
4. Create a task packet for any bounded implementation round
5. Revise `HYPOTHESES.md` if needed
6. Let organizer or the current packet route work through coder -> reviewer -> test runner as needed
7. Let coder / reviewer / log_analyzer append human-readable turn summaries to the task's separate human report file
8. Write the result back to `EXPERIMENT_LOG.md`
9. Archive finished packets and promote only stable conclusions into durable memory files

## Maintenance Rules

- Write the state first, then work
- Every experiment should point to a log path or another concrete artifact
- Keep current-round state in `docs/workflow/`
- Promote only stable conclusions into `docs/agent/`
- If a file starts turning into a long essay, split or move it

## Small Utilities

- `scripts/new_experiment.sh "goal text"`
  - inserts an experiment stub at the top of `EXPERIMENT_LOG.md`
- `scripts/new_ticket.sh ticket_name`
  - copies `IMPLEMENTATION_TICKET_TEMPLATE.md`
- `scripts/new_task_packet.sh task_name`
  - creates a bounded task packet in `docs/workflow/tasks/active/`
  - also initializes a separate human report file under `docs/workflow/tasks/reports/active/`
- `scripts/seed_task_packet.sh <task-packet> --goal "..." [--constraints "..."] [--dod "..."]`
  - writes the first human intent seed into an existing packet without opening an editor
- `scripts/new_task_packet.sh --type planning next_step_name`
  - creates a planning packet in lane `B` so planner can shape the next round while an execution packet is still moving
- `scripts/task_human_report.sh <task-packet>`
  - prints the path to the task's cumulative human-facing report file
- `scripts/spawn_next_planning_lane.sh <current-packet> next_step_name "rough idea"`
  - creates and seeds a lane `B` planning packet from the current execution packet, then optionally launches planner
- `scripts/archive_task_packet.sh <task-packet>`
  - moves a finished packet from `active/` to `completed/`
  - organizer now treats this as a same-lane prerequisite: follow-on packets do not continue until the finished predecessor is archived
- `scripts/harness_audit.sh`
  - performs first-cut mechanical checks on active packet metadata and warns when finished packets should be archived
- `scripts/harness_status.sh`
  - prints a compact view of active task packets, including lane and packet type
- `scripts/harness_next.sh <task-packet>`
  - suggests the next owner based on the packet status
- `scripts/render_handoff_brief.sh <task-packet> <role>`
  - renders a compact brief for launching a fresh role-specific session
- `scripts/bootstrap_harness.sh`
  - human-first entrypoint that either continues active work or helps create one new packet
  - add `--launch` to create a new packet and immediately launch the inferred next role
- `scripts/launch_prompt.sh <task-packet> <role>`
  - prints a copy-paste-ready launch prompt for a fresh role session
- `scripts/start_next_role.sh <task-packet>`
  - infers the next role from the packet state and prints the matching launch prompt
- `scripts/start_next_role.sh --launch <task-packet>`
  - infers the next role and launches it directly in tmux; if the V2 control room exists, it reuses the matching role pane
- `scripts/request_post_run_analysis.sh <task-packet> --log <path>`
  - marks a packet as `needs_analysis`, records the primary log path if provided, and prepares a log-analyzer handoff
- `scripts/run_role_session.sh <task-packet> <role>`
  - internal helper used to start an interactive `codex` role session from a packet
  - `test_runner` is launched with a more permissive Codex execution policy by default and no approval prompts unless you explicitly override that policy
- `scripts/start_control_room.sh`
  - creates or focuses the fixed tmux control room (`agents`, `tests`, `debug`) with stable role panes
- `scripts/tmux_launch_role.sh <task-packet> <role>`
  - internal tmux launcher that prefers fixed role panes and falls back to a disposable window only when the control room is absent
- `scripts/organizer_status.sh`
  - shows active packets with inferred next roles, lane/type, and organizer dispatch state, including role-busy deferrals
- `scripts/organizer_loop.sh --launch`
  - first-cut organizer loop that watches active packets and dispatches next roles automatically
- `scripts/start_organizer.sh`
  - starts the organizer inside the fixed `agents` window and keeps dispatch running from the organizer pane
