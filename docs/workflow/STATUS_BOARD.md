# Status Board

This file defines the operational board format for active task packets.

Do not use this file as a second source of truth.
The real task state lives in:

- `docs/workflow/tasks/active/*.md`

Use this board as a compact human-facing view of active packets and lanes.

Recommended live command:

```bash
scripts/harness_status.sh
```

## Lane Model

Keep at most a few active lanes at once:

| Lane | Typical owner | Purpose |
| --- | --- | --- |
| A | coder / reviewer / test_runner | current execution packet |
| B | planner | next-step planning packet |
| C | log_analyzer / planner | log analysis, reconciliation, or failure diagnosis |

Recommended packet types:

| Packet Type | Default lane | Meaning |
| --- | --- | --- |
| `execution` | `A` | current implementation / review / test work |
| `planning` | `B` | shaping the next bounded task while execution continues |
| `analysis` | `C` | failure diagnosis or architecture reconciliation |

## Handoff Rule

At most one role should own a given packet at a time.

The normal path is:

- `coder -> reviewer -> test runner`

Escalate only when needed:

- `test runner -> log analyzer`
- `reviewer -> planner`
- `coder -> planner`

`log_analyzer` is not failure-only in V2.
Use it whenever the log is too large for direct human reading or when a successful run still needs evidence reduction before a design decision.

## Human Use

The human should check:

- which packets are active
- which lane each packet occupies
- which role owns each packet
- which packet is waiting on human judgment

In the fixed tmux control room, each role has only one stable pane.
That means organizer may defer a packet when its target role pane is already busy with a higher-priority or earlier-sorted packet.

The human should not need to read all underlying artifacts just to answer those questions.
