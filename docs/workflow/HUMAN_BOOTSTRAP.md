# Human Bootstrap

This document is the human-first entrypoint to the NaCC harness.

If the fuller harness docs feel too mechanical, start here.
If you want the shortest possible version, read `docs/workflow/HUMAN_BOOTSTRAP_TLDR.md` first.

Current companion docs:

- `docs/workflow/HUMAN_BOOTSTRAP_TLDR.md`
- `docs/workflow/HARNESS_V2.md`
- `docs/workflow/HARNESS_V2_PLAN.md`

## TL;DR

If you forget how to start, use this:

```bash
cd /home/link/NaCC
scripts/bootstrap_harness.sh
```

If the previous task is finished, archive it:

```bash
scripts/archive_task_packet.sh docs/workflow/tasks/active/<task>.md
```

If you want a new real task:

```bash
scripts/bootstrap_harness.sh --launch --type execution my_new_task \
  --goal "..." \
  --constraints "none" \
  --dod "help me refine this"
```

That creates a seeded packet and launches `planner` directly. Let the packet carry the rest.

If you want the full multi-window organizer workflow instead, use this:

```bash
cd /home/link/NaCC
tmux
scripts/start_control_room.sh --restart
scripts/start_organizer.sh --restart
scripts/bootstrap_harness.sh --type execution my_new_task
```

That is the control-room path with fixed panes and organizer auto-dispatch.

Do not use `HARNESS_V1.md` as the default operator path anymore. It is historical background only.

## Recommended Real-Run Path

For real work, the most repeatable V2 path is usually the full control-room flow:

```bash
cd /home/link/NaCC
tmux
scripts/start_control_room.sh --restart
scripts/start_organizer.sh --restart
scripts/bootstrap_harness.sh --type execution my_new_task
```

What happens next:

1. the control room creates fixed role panes
2. organizer starts its dispatch loop
3. the new execution packet appears in `active/`
4. organizer routes it to `planner` once the packet has a real human seed
5. you continue from the planner route instead of teaching planner the task title by hand

Use the lighter single-role path only when you do not want the full multi-window setup.

## The Simple Version

You do not need to orchestrate every agent at once.

Start with one role only:

- talk to the planner first

Then let the planner tell you which role should go next.

Your job is not to manually relay every piece of chat history.
Your job is to keep one task packet current and launch the next fresh role session when needed.
When you want the compact human-readable view, read the task's human report file instead of reconstructing the whole packet history from scratch.

## Default Human Workflow

### Case A: there is already active work

Run:

```bash
cd /home/link/NaCC
scripts/bootstrap_harness.sh
```

If there is an active packet:

1. open the packet
2. look at `Status`, `Owner Role`, and `Next Handoff`
3. continue from there

### Case B: there is no active work yet

Run:

```bash
cd /home/link/NaCC
scripts/bootstrap_harness.sh
```

Then:

1. pick one pending item
2. create one packet:

```bash
scripts/bootstrap_harness.sh --launch my_task_name
```

3. seed the packet before launching planner
   - minimum recommended: `Goal`
   - optional if you already know them: `Constraints`, `Definition Of Done`, `Scope`
   - helper:

```bash
scripts/seed_task_packet.sh docs/workflow/tasks/active/<task>.md \
  --goal "..." \
  [--constraints "..."] \
  [--dod "..."]
```

4. planner should start from that seeded packet and turn it into a route

Do not expect planner to infer the task from the packet filename alone.
A blank draft packet should stay with human until it has a real seed.
That rule is for organizer auto-dispatch. If you explicitly want planner to ask follow-up questions, a human-triggered planner launch on a blank draft packet is still valid:

```bash
scripts/start_next_role.sh --launch docs/workflow/tasks/active/<task>.md
```

In short:

- organizer should not auto-launch blank planner packets
- human may still explicitly launch planner on a blank packet for interactive clarification

## The Only Rule You Need At First

Do not try to manage planner, coder, reviewer, test runner, and analyzer all at once.

Use this rule:

- one active packet
- one current owner
- one next handoff

That is enough to start.

Later, once V2 organizer and control-room flow feel stable, the next useful expansion is:

- one execution packet in lane `A`
- one planning packet in lane `B`

## Human Responsibilities

At first, keep your role minimal:

1. choose the task
2. approve the packet definition
3. launch the planner first
4. after each handoff, launch the next role using the packet
5. make the final judgment on merge / push / architecture

You are the conductor, not the data bus.
The packet is the bus.

## Recommended Starting Prompt

When you open the planner session, keep it simple:

```text
Use this task packet as the source of truth. Refine the route, update the packet if needed, and tell me the exact next owner and artifact for handoff.
```

After that:

- if planner says `coder`, launch a fresh coder session
- if coder finishes, launch a fresh reviewer session
- if reviewer approves, launch a fresh test runner session
- launch log analyzer whenever the log is long, the trap evidence still needs interpretation, or the run looks suspicious, even if the command technically succeeded

If you do not want to manually rephrase the role prompt each time, use:

```bash
scripts/launch_prompt.sh <task-packet> <role>
```

This prints the fixed launch wording plus the packet brief in one block.

To find the cumulative human-facing report for a task packet, use:

```bash
scripts/task_human_report.sh <task-packet>
```

That report is separate from the packet. `coder`, `reviewer`, and `log_analyzer` should append new timestamped sections there instead of overwriting older explanations.

If you do not even want to choose the role manually, use:

```bash
scripts/start_next_role.sh <task-packet>
```

This reads the packet state, infers the next role, and prints the corresponding launch prompt automatically.

If you are already in tmux and want to skip copying entirely, use:

```bash
scripts/start_next_role.sh --launch <task-packet>
```

This launches the inferred next role directly in `codex`. If the V2 control room exists, it reuses the matching role pane instead of opening another disposable window.

If you want seeded packet creation plus immediate planner launch in one command for a new task, use:

```bash
scripts/bootstrap_harness.sh --launch --type execution my_new_task \
  --goal "..." \
  --constraints "none" \
  --dod "help me refine this"
```

If you prefer the conversational path, you can also create a blank packet and let the explicit human launch put you into planner directly:

```bash
scripts/bootstrap_harness.sh --launch --type execution my_new_task
```

If you want a stable tmux control room first, run:

```bash
scripts/start_control_room.sh
```

This creates fixed windows and panes for:

- `agents`: planner / coder / reviewer / organizer
- `tests`: test_runner / log_analyzer
- `debug`: qemu / vm / gdb / logger

If you want the harness to keep dispatching next roles for active packets with less manual work, start organizer:

```bash
scripts/start_organizer.sh
```

This ensures the control room exists, then starts the organizer loop in the organizer pane inside `agents`.

If you want planner to work on the next bounded task while the current execution packet is still moving, create a planning packet:

```bash
scripts/bootstrap_harness.sh --type planning next_step_name
```

That packet defaults to lane `B`, which is the intended planning lane.

If you already have a current execution packet and want a more guided shortcut, use:

```bash
scripts/spawn_next_planning_lane.sh --launch <current-packet> next_step_name "rough next-step idea"
```

Use lane `B` before lane `A` finishes if:

- the current execution packet is already with coder / reviewer / test_runner
- you already have a rough next-step idea, even if it is not fully formed yet
- you want planner to shape the next bounded task without interrupting the current run

Minimal starting prompt for the lane `B` planner:

```text
This is the next-step planning lane while lane A is still executing.
Do not reopen the current execution packet unless I explicitly ask.
Help me turn this rough next-step idea into a bounded planning packet:
<your rough idea>
```

Good times to start lane `B`:

- after coder has handed off to reviewer
- while test_runner is rebuilding or running
- after log_analyzer has already compressed the current run enough that you do not need to keep reading raw logs yourself

If a run succeeds but still leaves you with a long log or trap dump you do not want to read directly, mark it for post-run analysis:

```bash
scripts/request_post_run_analysis.sh --launch <task-packet> --log <log-path>
```

That moves the packet to `needs_analysis` and hands it to `log_analyzer` instead of forcing you to read the raw artifact yourself.

When a packet is finished, archive it explicitly:

```bash
scripts/archive_task_packet.sh docs/workflow/tasks/active/<task>.md
```

If you want a quick mechanical sanity check on the active packet set, run:

```bash
scripts/harness_audit.sh
```

## Minimal Operating Mode

If this still feels too complex, use the smallest version:

- you
- one planner session
- one coder session
- one reviewer session

Add test runner and log analyzer only when needed.

That already removes most of the old serialization burden.

## If You Feel Lost

Return to this command:

```bash
scripts/bootstrap_harness.sh
```

It should answer:

- do I already have active work?
- if not, what should I create next?
- if yes, which packet should I continue?

## After You Get Comfortable

Later you can expand to:

- multiple packets
- detached validation lanes
- explicit reviewer-first code flow
- aggressive session recycling

But do not start there.
Start with one packet and one planner.
