# NaCC Harness V1

Historical foundation document.

Do not use this as the default operator entrypoint anymore.
The current harness path is:

- `docs/workflow/HUMAN_BOOTSTRAP.md`
- `docs/workflow/HARNESS_V2.md`
- `docs/workflow/HARNESS_V2_PLAN.md`

Keep this document only as background on why the packet-based workflow exists and how V2 evolved from it.

This document defines the lightweight execution harness for faster multi-agent work inside NaCC.

The point is not to add another process layer.
The point is to reduce human dispatch work between coding, review, testing, and analysis.

## Operating Model

Keep the current durable memory model:

- `docs/workflow/` is the source of truth for current-round work
- `docs/agent/` is the source of truth for stable design conclusions

Change the execution model:

- the human sets direction
- one task packet owns one bounded implementation round
- agent sessions are disposable and should be recycled aggressively
- the coder keeps ownership until it can either:
  - hand off a reviewable artifact
  - or emit a blocker summary
- the reviewer becomes the default first reader of code
- the test runner validates the approved change
- the log analyzer only enters on failed validation or evidence-heavy diagnosis
- the planner only enters when the blocker is architectural

Default chain:

1. human or planner creates a task packet
2. coder implements inside the packet scope
3. reviewer checks the patch and summarizes what changed
4. test runner executes the minimum required gates
5. if tests fail, log analyzer identifies the first bad point
6. human reviews the compressed result, not every raw artifact

## Human Role

The human should mostly do four things:

1. approve `goal / scope / constraints / definition of done`
2. decide whether a blocker is architectural or local
3. review escalated summaries and high-risk diffs
4. decide merge / push / broader roadmap direction

The human should not have to manually stitch together every small handoff.

## Task Packet

Every committed implementation round should start from one task packet under:

- `docs/workflow/tasks/active/`

The packet carries:

- the bounded goal
- scope limits
- constraints
- definition of done
- current owner
- current status
- required artifacts
- latest handoff summary

This replaces repeated ad-hoc restating of the same task.

## Session Recycling

Do not try to preserve one giant session across planning, coding, review, testing, and diagnosis.

Preferred model:

- durable knowledge lives in repo files
- execution context lives in task packets
- individual agent sessions are cheap and replaceable

Default rule:

- new role, new session

Use a fresh session especially when:

- the packet changes owner
- the current session read large logs
- the session drifted across multiple rejected paths
- the current agent is becoming less precise

Reference:

- `docs/workflow/SESSION_RECYCLE.md`
- `scripts/render_handoff_brief.sh <task-packet> <role>`

## Statuses

Recommended status values:

- `draft`
- `in_progress`
- `needs_review`
- `changes_requested`
- `needs_test`
- `test_failed`
- `blocked`
- `done`

Recommended meaning:

- `draft`: packet exists but has not yet been assigned
- `in_progress`: current owner is still working
- `needs_review`: coder produced a reviewable artifact
- `changes_requested`: reviewer found issues for coder
- `needs_test`: reviewer approved or conditionally approved
- `test_failed`: test runner produced a failing artifact
- `blocked`: current owner cannot proceed without higher-level input
- `done`: required artifacts exist and the round is complete

## Minimal Gates

Do not gate every coding round on the heaviest test.

Use validation tiers:

- `T0`: minimal compile sanity, usually single-object or narrow build
- `T1`: one or two canonical smoke commands
- `T2`: detached batch validation
- `T3`: longer real-app or stress runs

Default rule:

- coder should usually satisfy `T0` when practical
- reviewer should decide whether the change is ready for `T1`
- test runner should not default to `T2` or `T3` unless the packet asks for it

## Review Before Human Review

Human review is expensive.

Default flow:

- coder does not hand raw code directly to human unless explicitly requested
- reviewer reads the patch first
- reviewer explains:
  - what changed
  - what could be wrong
  - what still needs validation

This keeps the human focused on judgment instead of first-pass diff reading.

## Commit Policy

Do not require a commit after every tiny edit.
That creates too much noise and many low-signal checkpoints.

Recommended policy:

- commit when the step is independently describable
- commit when the diff stays inside one bounded task packet
- commit when the step has at least the minimum agreed verification for that scope
- do not force a commit for a clearly exploratory or broken intermediate state

Good default for NaCC subrepos:

- coder should usually make a small commit before handoff if:
  - the step is isolated
  - the diff is reviewable
  - the minimum compile / validation gate for that step passed

Do not force a commit when:

- the patch is still being actively reworked after reviewer findings
- the state is only diagnostic instrumentation
- the compile or sanity gate is still failing
- the packet is explicitly exploratory

## Parallel Work

Parallelism should happen across lanes, not inside one confused task.

Recommended parallel lanes:

- lane A: implementation
- lane B: detached validation batch
- lane C: failure analysis or state upkeep

This lets work continue while tests run and keeps the human out of the dispatcher role.

## Operational Files

- `docs/workflow/TASK_PACKET_TEMPLATE.md`
- `docs/workflow/STATUS_BOARD.md`
- `docs/workflow/AGENT_REVIEWER.md`
- `docs/workflow/SESSION_RECYCLE.md`
- `scripts/new_task_packet.sh`
- `scripts/harness_status.sh`
- `scripts/harness_next.sh`
- `scripts/render_handoff_brief.sh`

## Fast Start

1. create a packet with `scripts/new_task_packet.sh task_name`
2. assign one owner role
3. keep the packet status current at handoff points
4. use `scripts/harness_status.sh` to see active lanes
5. use `scripts/harness_next.sh <packet>` to decide the next owner
