# Session Recycle

This document defines how NaCC should recycle agent context instead of stretching one session too far.

## Core Rule

Treat agent sessions as disposable workers.

Do not treat a long chat as the system of record.
The system of record is the repository:

- `docs/workflow/` for current-round state
- `docs/agent/` for stable conclusions
- task packets for bounded execution state

If a session becomes bloated, ambiguous, or role-confused, the default recovery is:

1. update the packet or state file
2. generate a compact handoff brief
3. start a fresh role-specific session

## Why

Long context degrades agent quality even when the important facts are technically still present.

Typical failure modes:

- the agent overfits stale earlier discussion
- the agent mixes role responsibilities
- the agent keeps irrelevant logs, plans, and rejected routes in working memory
- the agent responds to the conversation history instead of the current bounded task

Compact or summarization helps, but it is not enough when the session has become structurally noisy.

## Fresh-Session Bias

Prefer a fresh session when any of these are true:

- ownership changes from one role to another
- the task packet moves to a new status
- a large log was inspected
- the session spent too long in exploratory discussion
- the agent had to backtrack across multiple rejected paths
- the human notices the agent becoming less precise
- the packet has a clean artifact handoff already

Good default:

- new role, new session

## Recycle Triggers By Role

### Planner

Recycle when:

- planning is complete and execution should begin
- the discussion is drifting into coding mechanics
- the planner had to inspect too many implementation details

### Coder

Recycle when:

- the patch is ready for review
- reviewer requested substantial changes and the original session is noisy
- a large failing log arrived and diagnosis should move elsewhere

### Reviewer

Recycle when:

- the artifact changed materially after findings
- the session starts accumulating raw test output
- the issue is becoming architectural instead of reviewable

### Test Runner

Recycle when:

- a run completed and the next step is diagnosis
- multiple unrelated run attempts have accumulated in one session

### Log Analyzer

Recycle when:

- the first bad point is identified and the next move is implementation or planning
- the session starts turning into broad architecture discussion

## Handoff Artifact

Every recycle should point to one compact handoff artifact:

- the task packet
- the latest summary inside the packet
- the exact artifact to read first

Optional additional artifacts:

- one commit id
- one patch path
- one log path
- one plan or ticket

Avoid handing a new session a pile of mixed chat context.

## Scripted Support

Use:

- `scripts/render_handoff_brief.sh <task-packet> <role>`

This produces a compact brief suitable for launching a fresh agent session.

## Human Rule

If the current session feels "sticky" or confused, do not rescue it with more explanation first.

Prefer:

1. update packet summary
2. render a new handoff brief
3. launch a fresh role-specific session
