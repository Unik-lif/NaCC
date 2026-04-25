# Human Bootstrap TL;DR

Use this file when you forget how to start.

If you only remember one rule, remember this:

- one active packet
- one current owner
- one next handoff

## 0. Default Full V2 Flow

If you want the normal multi-window organizer workflow, use this:

```bash
cd /home/link/NaCC
tmux
scripts/start_control_room.sh --restart
scripts/start_organizer.sh --restart
scripts/bootstrap_harness.sh --type execution my_new_task
```

That gives you the full control room:

- `agents`: planner / reviewer / coder / organizer
- `tests`: test_runner / log_analyzer
- `debug`: qemu / vm / gdb / logger

After that, organizer should dispatch the new packet to `planner` automatically if the packet was created with a real human seed.

## 1. If You Just Want To Know What To Do Next

Run:

```bash
cd /home/link/NaCC
scripts/bootstrap_harness.sh
```

That is the default "where am I?" command.

## 2. If The Previous Task Is Finished

Archive it:

```bash
cd /home/link/NaCC
scripts/archive_task_packet.sh docs/workflow/tasks/active/<task>.md
```

## 3. If You Want To Start A New Real Task

Create one execution packet:

```bash
cd /home/link/NaCC
scripts/bootstrap_harness.sh --launch --type execution my_new_task \
  --goal "..." \
  --constraints "none" \
  --dod "help me refine this"
```

That creates a seeded packet and launches `planner` directly.

If you already created a blank packet, seed it without editing by hand:

```bash
scripts/seed_task_packet.sh docs/workflow/tasks/active/<task>.md \
  --goal "..." \
  --constraints "none" \
  --dod "help me refine this"
```

If you prefer the conversational path, an explicit human launch is also allowed on a blank draft packet:

```bash
scripts/start_next_role.sh --launch docs/workflow/tasks/active/<task>.md
```

That is different from organizer auto-dispatch. Organizer should keep a blank draft at `waiting-human`, but a human may still launch planner explicitly and let planner gather the first seed interactively.

## 4. If There Is Already Active Work

Keep the current packet moving:

```bash
cd /home/link/NaCC
scripts/bootstrap_harness.sh
```

If you want the harness to launch the next role directly:

```bash
scripts/start_next_role.sh --launch docs/workflow/tasks/active/<task>.md
```

If you want the short human-readable progress summary first:

```bash
scripts/task_human_report.sh docs/workflow/tasks/active/<task>.md
```

## 5. If You Want The Organizer / tmux Version

```bash
cd /home/link/NaCC
scripts/start_control_room.sh
scripts/start_organizer.sh
```

Then the normal pattern is:

1. create or continue a packet
2. let organizer dispatch the next role
3. read the human report when you want the short version

## 6. If You Want To Plan The Next Step While Lane A Is Still Running

Create a lane `B` planning packet:

```bash
cd /home/link/NaCC
scripts/spawn_next_planning_lane.sh --launch docs/workflow/tasks/active/<current>.md next_step_name "rough next-step idea"
```

## 7. If A Run Succeeded But The Log Is Too Long

Send it to `log_analyzer`:

```bash
cd /home/link/NaCC
scripts/request_post_run_analysis.sh --launch docs/workflow/tasks/active/<task>.md --log logs/<run>.log
```

## 8. The Smallest Working Human Flow

If everything else feels like too much, use only this:

1. `scripts/bootstrap_harness.sh`
2. `scripts/bootstrap_harness.sh --launch --type execution my_task --goal "..." --constraints "none" --dod "help me refine this"`
3. talk to `planner`
4. let the packet tell you the next role
5. use `scripts/task_human_report.sh <task>` when you need the short version

## 9. If You Feel Lost Again

Return to:

```bash
scripts/bootstrap_harness.sh
```

That is the reset point.
