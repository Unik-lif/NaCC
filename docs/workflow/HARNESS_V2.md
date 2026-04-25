# NaCC Harness V2

This is the current harness entrypoint for NaCC.

Use this document when you want to understand how the repository should operate today.

Do not start from `HARNESS_V1.md` unless you are reviewing the historical evolution of the workflow.
V1 remains useful as background, but V2 is the active operating model.

## Read Order

1. `docs/workflow/HUMAN_BOOTSTRAP_TLDR.md`
2. `docs/workflow/HUMAN_BOOTSTRAP.md`
3. `docs/workflow/README.md`
4. `docs/workflow/HARNESS_V2_PLAN.md`
5. `docs/workflow/AGENT_ORGANIZER.md`
6. `docs/workflow/STATUS_BOARD.md`

## Current V2 Model

- task packets are the durable source of execution state
- each task also has a separate cumulative human report file for plain-English progress summaries from coder / reviewer / log_analyzer
- organizer is the default dispatcher
- tmux control room is the default role UI
- reviewer is `spec fidelity` first, `risk` second
- coder must stop and escalate at semantic gaps
- test_runner is launched with a higher-permission, no-approval-by-default Codex policy so packet-owned validation does not stall on repeated approval prompts
- log_analyzer is not failure-only; it may compress long successful runs or trap-heavy logs into evidence before human closeout
- packets may run in multiple lanes:
  - lane `A`: execution
  - lane `B`: planning
  - lane `C`: analysis / reconciliation
- finished packets should be archived out of `active/`
- a same-lane follow-on packet must not dispatch until its finished predecessor has been archived out of `active/`

## Current V2 Commands

Minimal human-first path:

```bash
cd /home/link/NaCC
scripts/bootstrap_harness.sh
```

Stable tmux control room:

```bash
cd /home/link/NaCC
scripts/start_control_room.sh
scripts/start_organizer.sh
```

Full multi-window execution start:

```bash
cd /home/link/NaCC
tmux
scripts/start_control_room.sh --restart
scripts/start_organizer.sh --restart
scripts/bootstrap_harness.sh --type execution task_name --goal "..." --constraints "none" --dod "help me refine this"
```

Create a new execution packet:

```bash
scripts/bootstrap_harness.sh --launch --type execution task_name --goal "..." --constraints "none" --dod "help me refine this"
```

Create a parallel planning packet:

```bash
scripts/bootstrap_harness.sh --type planning next_step_name
```

Create and launch a seeded lane `B` planning packet from the current execution packet:

```bash
scripts/spawn_next_planning_lane.sh --launch docs/workflow/tasks/active/<current>.md next_step_name "rough next-step idea"
```

Mark a successful-but-long run for post-run analysis:

```bash
scripts/request_post_run_analysis.sh --launch docs/workflow/tasks/active/<current>.md --log logs/<run>.log
```

Show the human-facing cumulative report for a task:

```bash
scripts/task_human_report.sh docs/workflow/tasks/active/<current>.md
```

Check packet hygiene:

```bash
scripts/harness_audit.sh
```

Archive a finished packet:

```bash
scripts/archive_task_packet.sh docs/workflow/tasks/active/<task>.md
```

## Document Roles

- `HUMAN_BOOTSTRAP.md`: shortest human entrypoint
- `HARNESS_V2_PLAN.md`: durable V2 design and rollout status
- `AGENT_ORGANIZER.md`: organizer behavior and routing rules
- `STATUS_BOARD.md`: lane and board model
- `HARNESS_V1.md`: historical foundation only
