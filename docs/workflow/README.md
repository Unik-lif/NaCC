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

1. `CURRENT_STATE.md`
2. `NEXT_STEPS.md`
3. `PLAN_20260327_secure_runtime_context.md`
4. `PLAN_20260322_container_validation.md`
5. `PLAN_20260318_linux_friendly_fork.md`

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
  - `AGENT_LOG_ANALYZER.md`
  - `AGENT_PAPER_SCOUT.md`
  - `AGENT_TEST_RUNNER.md`
- For guardrails:
  - `WORKFLOW_GUARDRAILS.md`
  - `HUMAN_OPERATOR_CHECKLIST.md`

## Recommended Iteration Loop

1. Update `CURRENT_STATE.md`
2. Review `NEXT_STEPS.md`
3. Revise `HYPOTHESES.md` if needed
4. Make a controlled code change or run a controlled test
5. Write the result back to `EXPERIMENT_LOG.md`
6. Promote only stable conclusions into durable memory files

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
