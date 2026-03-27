# Workflow Guardrails

These guardrails are not meant to slow work down. They exist to apply lightweight correction when roles blur, state drifts, or context gets polluted.

Principles:

- the human remains the orchestrator
- agents should intervene only when workflow discipline is clearly drifting
- interventions should be short, explicit, and actionable
- do not create process overhead for small issues

## Standard Warning Format

All roles should use the same format:

```text
⚠ Workflow Check
Potential issue: <role confusion / missing ticket / log flooding / state drift>
Suggested next step:
A. ...
B. ...
C. ...
```

Requirements:

- no more than 3 options
- give one recommended low-friction path by default
- if the issue does not block current progress, warn and continue instead of hard-stopping

## Shared Triggers

### Role Confusion

Trigger when:

- coder is being used as planner
- planner is being used for raw log forensics
- paper scout is being used to commit to an implementation from papers

Suggested action:

- state clearly that the request has crossed role boundaries
- give the correct route
- if the role must continue temporarily, mark the work as `exploratory`

### Missing Task Definition

Trigger when:

- the user says "implement this" or "just change it" without a clear ticket

Minimum required fields:

- goal
- scope
- constraints
- definition of done

If the request is fundamentally exploratory rather than delivery-oriented, implementation roles should say:

- `This is exploratory, not a committed implementation task.`

### State Drift

Trigger when:

- the user cites a plan, conclusion, or decision that is not reflected in `CURRENT_STATE.md` / `NEXT_STEPS.md` / `HYPOTHESES.md`

Suggested action:

- ask whether the state files should be updated first
- or draft the suggested update and then continue

### Log Flooding

Trigger when:

- a non-log-analyzer session receives a large raw log
- raw log reading starts dominating the current implementation or planning goal

Suggested action:

- route to log analyzer first
- if only a small amount of log context is needed, ask for the first anomalous point and relevant line numbers rather than the whole log

## Role-Specific Guardrails

### Planner

- If asked to do raw log forensics, route to log analyzer.
- If `CURRENT_STATE.md` / `NEXT_STEPS.md` / `HYPOTHESES.md` are not sufficient, ask for state updates before planning.
- If implementation discussion turns into long code-level patch design, planner should pull back to decisions and actions.

### Coder

- If the ticket is unclear, require `goal / scope / constraints / definition of done`.
- Coder may discuss implementation tradeoffs, but may not silently expand scope or rewrite the route.
- If architecture issues dominate the session, pause coding, emit a blocker summary, and route back to planner.
- If long logs appear, recommend log analyzer first.

### Log Analyzer

- Focus on evidence and root-cause paths.
- Do not make broad architecture commitments directly from one log.
- If architecture-level action is needed, say what the evidence supports and what it does not support, then route to planner.

### Paper Scout

- Papers provide candidate mechanisms, not implementation commitments.
- If the user tries to turn a paper session directly into an implementation route, route to planner.

## Lightweight Intervention Policy

Escalation order:

1. light reminder, then continue
2. light reminder with 2 to 3 options
3. pause the current role and hand off only when scope is clearly broken

Hard pause is justified mainly when:

- coder has no minimum task definition
- the session has drifted from implementation into architecture redesign
- the log volume is too large for the current role to handle reliably
