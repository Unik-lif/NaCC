# NaCC Harness V2 Plan

This is the durable V2 design and rollout record.

Because slices 1 through 5 are already implemented in a first cut, treat this as the current V2 reference for design intent and rollout status.

If you only want the current operator-facing entrypoint, start with:

- `docs/workflow/HUMAN_BOOTSTRAP.md`
- `docs/workflow/HARNESS_V2.md`

This document captures the confirmed lessons from the first real V1 loop and defines the next harness upgrade before implementation.

V2 is not meant to replace V1 blindly.
It is meant to fix the specific friction that appeared in real use:

- human dispatch work is still too manual
- reviewer is still too weak as a fidelity gate
- coder still has too much freedom when the packet leaves a semantic gap
- one active packet is not enough for a research workflow
- tmux role UX is still clumsy for human supervision

## 0. Rollout Status

This plan should remain the durable source of truth for V2, even while implementation happens in slices.

- Slice 1: packet schema + planner/coder/reviewer semantics + launch/brief wiring
  - status: implemented in repo
- Slice 2: organizer / dispatcher behavior
  - status: implemented in repo (first cut)
- Slice 3: tmux fixed-pane control room
  - status: implemented in repo (first cut)
- Slice 4: multi-packet / multi-lane operational support
  - status: implemented in repo (first cut)
- Slice 5: mechanical audit and closeout hygiene
  - status: implemented in repo (first cut)

If later implementation diverges from this plan, update this document explicitly instead of letting the plan disappear into chat history.

## 1. Confirmed V1 Lessons

These are no longer speculative.
They are grounded in the first full packet loop.

### What Worked

- More detailed planning materially increased coder step size.
- Packet-based handoff was strong enough to complete one real loop.
- Reviewer could provide useful checks in some cases.
- Test runner flow was acceptable once the packet reached it with the right intent.

### What Did Not Work Well Enough

- Human still had to act as the message bus too often.
- Reviewer was not consistently acting as a true "did this faithfully implement the intended spec?" gate.
- Coder sometimes filled semantic gaps with plausible but wrong design decisions instead of escalating.
- The current packet format does not yet encode "preferred shape" versus "disallowed shape" strongly enough.
- The current `--launch` flow improves copying friction but still assumes one role at a time and one packet at a time.
- One active packet is too restrictive; it blocks planning the next step while the current packet is still under test or review.

## 2. V2 Goals

V2 should change the operator experience in these ways:

1. The human should no longer manually dispatch every next role.
2. Reviewer should become a spec-fidelity gate before it becomes a risk gate.
3. Coder should stop and escalate at semantic gaps instead of inventing a route.
4. The harness should support at least two active packets at the same time.
5. tmux should become a stable control room instead of a stream of disposable role windows.
6. Human should be able to interrupt, reopen, or redirect a packet at any point.

## 3. Core V2 Principle

Keep the same durable-memory rule:

- repo artifacts are the source of truth
- chat history is not the source of truth

But change the control model:

- V1: human manually routes most handoffs
- V2: organizer routes most handoffs, human interrupts or corrects intent when needed

## 4. New Role: Organizer

V2 introduces a persistent `organizer` role.

Organizer is not planner, coder, reviewer, or test runner.
Organizer is the lifecycle manager for task execution.

### Organizer Responsibilities

- watch active packet state
- decide the next role from packet state plus explicit human interrupts
- launch, resume, or refresh role sessions
- prevent stale conclusions from flowing forward blindly
- reopen planner when human concern invalidates the current handoff
- keep the human informed with compressed operational status

### Organizer Is Not Allowed To Do

- rewrite architecture direction on its own
- silently change packet intent
- replace reviewer judgment with "looks okay"
- replace human decision on high-risk route changes

### Organizer As Session Manager

Organizer should not try to "repair" a rotten session by adding more summary text.
Its job is to choose between:

- continue current session
- resume current role session
- launch a fresh role session

That makes organizer a session lifecycle manager, not just a prompt forwarder.

## 5. Packet Schema Changes

The V1 packet is too good at describing scope and too weak at constraining interpretation.

V2 should add these fields:

- `Critical Intent`
  - what semantic meaning must be preserved
- `Preferred Shape`
  - the intended control model or implementation shape
- `Disallowed Shape`
  - routes that may look plausible but are explicitly not the target design
- `Allowed Freedom`
  - where coder may choose local implementation details freely
- `Open Semantic Questions`
  - unresolved meaning-level points that still require clarification
- `Human Concern`
  - a human correction that should interrupt the current flow
- `Reconciliation Required`
  - explicit flag for "planner must revisit before coding/testing continues"

### Why These Fields Are Needed

The first real loop exposed a pattern like this:

- human intent: preserve a monitor-owned control path
- coder route: choose a broader, more invasive Linux-mediated route
- reviewer: accept the route because the packet did not explicitly forbid it

That is not mainly a code-quality failure.
It is a packet-shape failure.

## 6. Reviewer Changes

Reviewer must become a two-stage gate.

### Stage 1: Spec Fidelity Gate

Reviewer must answer:

1. Did the patch faithfully implement the packet intent?
2. Which packet requirements are clearly satisfied, one by one?
3. Which requirement is ambiguous, stretched, or possibly violated?
4. Did the patch preserve the packet's intended control model?
5. Did the coder choose a more invasive route than the packet allowed?

### Stage 2: Risk Gate

Only after fidelity is acceptable should reviewer focus on:

- regression risk
- bug risk
- edge conditions
- missing validation

### Reviewer Must Not

- trust coder summary as the primary truth source
- collapse spec fidelity into generic "looks reasonable"
- let a packet flow to test merely because the code compiles and seems self-consistent

### Reviewer Output Must Explicitly State

- `Spec fidelity: pass / conditional / fail`
- `Risk review: pass / conditional / fail`
- `Can this proceed to test? yes / no`

If fidelity fails, the packet must not proceed to test.

## 7. Coder Changes

V1 already says "stay in scope."
V2 must make that sharper.

### New Default Coding Rule

When multiple viable solutions exist, prefer the least invasive route that preserves the packet's intended control model.

### New Stop Rule

Coder must stop and escalate when:

- semantic timing is unclear
- packet wording and human intent may not be equivalent
- continuing requires inventing a new architectural assumption
- a local implementation choice would change the control model
- packet does not clearly justify an invasive route change

### Ask-vs-Assume Rule

Coder may assume low-level local details.
Coder may not assume intent-level semantics.

In other words:

- local syntax gap -> may choose locally
- semantic or architectural gap -> must escalate

### Expected Escalation Targets

- back to planner if the packet itself is insufficient
- back to human only if the packet and planner both remain ambiguous

## 8. Human Interrupt Path

V2 must support a clean interrupt even after reviewer or test_runner has already moved forward.

### Example

- packet says `Next owner: test_runner`
- human notices the implementation still violates intent
- current chain must not continue blindly

Organizer should support:

- reopen packet
- set `Human Concern`
- set `Reconciliation Required`
- redirect next owner to `planner`

`Human Concern` records the human's note or correction.
The actual organizer-side routing trigger is `Reconciliation Required: yes`.

That interrupt path should be first-class, not an ad hoc exception.

## 9. Multi-Packet Model

V2 should stop treating "one packet at a time" as the default.

At minimum, support two active packets:

- one execution packet
- one planning packet

Preferred minimum lane model:

- `lane A`: current implementation / review / test packet
- `lane B`: next-step planning packet
- `lane C`: optional analysis packet when a failure demands separate diagnosis

### Why This Matters

With only one packet, a test run blocks productive planning.
That is too serial for a research workflow.

## 10. tmux Layout

V1 used tmux mainly as a launch surface.
V2 should use tmux as a stable control room.

### Proposed Layout

#### Window 1: `agents`

- pane 1: planner
- pane 2: coder
- pane 3: reviewer
- pane 4: organizer / control

#### Window 2: `debug`

- qemu
- vm
- gdb
- logger

#### Window 3: `tests`

- test_runner
- batch status / launcher log

### Important Boundary

tmux panes are for observability and operator UX.
They are not the inter-agent memory layer.

Repo artifacts still carry the handoff state.

## 11. Session Reuse Policy

V2 should not treat every handoff as "always fresh" or "always reuse."

### Recommended Default

- organizer: persistent
- planner: medium-lived, refresh after major reconciliation
- coder: refresh at natural commit boundaries or after large route changes
- reviewer: refresh more often
- test_runner: usually fresh
- log_analyzer: usually fresh

### Recycle Triggers

- packet owner changes
- major reconciliation
- large log ingestion
- repeated rejected paths
- visible loss of precision

## 12. Automation Scope

The correct V2 automation target is:

- `coder -> reviewer`
- `reviewer -> test_runner`
- `test_runner -> log_analyzer` on failure or when a long/successful run still needs evidence reduction
- `reviewer/test_runner -> planner` on `Reconciliation Required`

Small operator helpers that fit this model well:

- a direct `needs_analysis` helper for post-run log compression
- a direct lane `B` planning helper so the next step can be shaped before lane `A` closes

The incorrect first automation target would be:

- letting coder continue through semantic ambiguity
- letting test follow reviewer if fidelity was never explicitly passed

## 13. V2 Operational Flow

### Happy Path

1. planner or human defines a packet
2. organizer assigns coder
3. coder implements and updates packet
4. organizer assigns reviewer
5. reviewer passes fidelity and risk
6. organizer assigns test_runner
7. test passes
8. organizer returns packet to human for closeout

### Reconciliation Path

1. coder or human identifies intent mismatch
2. packet gets `Human Concern` plus `Reconciliation Required`, or an equivalent explicit reconciliation flag
3. organizer redirects packet to planner
4. planner revises route and packet fields
5. organizer relaunches coder or reviewer as appropriate

## 14. Rollout Order

V2 should be implemented in this order:

1. packet schema upgrade
2. reviewer role upgrade
3. coder role upgrade
4. organizer role and dispatcher logic
5. tmux fixed-pane control room
6. multi-packet lane support
7. smarter resume / refresh heuristics

This order matters.
If we automate dispatch before fixing packet/reviewer/coder semantics, we will just make the wrong loop faster.

## 15. Acceptance Criteria For V2

V2 should be considered successful only if all of these improve:

- human enters fewer manual dispatch commands
- reviewer catches more "wrong intent, locally plausible code" cases
- coder escalates more semantic gaps instead of hallucinating them away
- one packet being under test no longer blocks planning the next step
- tmux role supervision becomes easier rather than more fragmented

## 16. Open Questions Before Implementation

- Should organizer be purely script-driven at first, or should there also be an explicit `AGENT_ORGANIZER.md` role doc from the start?
- Should V2 add a packet state distinct from `blocked`, such as `needs_reconciliation`?
- Should planner and organizer be separate roles from the beginning, or should planner temporarily absorb organizer behavior during the first implementation cut?
- Should multi-packet status be grouped by lane, packet type, or both?

## 17. Immediate Next Step

Slice 1 and the first cut of Slice 2 are now in the repo.

The next implementation focus should be:

- stronger organizer UX on top of the current dispatcher loop
- smarter session reuse / refresh heuristics
- broader mechanical checks and periodic doc-gardening
