# NaCC Bitter Lessons

This document records only mistakes that were already made and were costly enough to deserve institutional memory.

## 1. 2026-03-15: Misreading the log shifted the whole reasoning chain

### 1.1 What happened

- The user explicitly asked to continue from the latest 2026-03-15 fork+exec debugging state.
- The analysis accidentally reused conclusions from an older 2026-03-14 log.
- On top of that wrong starting point:
  - new root-cause guesses were made about exit behavior
  - another round of `invoke ptp list / shared reclaim`-style changes was added
  - after the user noticed the wrong log, the rollback was broader than necessary
- Result:
  - analysis drifted away from the real current runtime state
  - rollback scope exceeded the actual mistake
  - the code branch moved away from the last known state that could still wake the agent and initialize correctly

### 1.2 Direct lessons

1. **Before making any root-cause claim, pin down the one log that actually belongs to this round.**
   - confirm:
     - exact file name
     - exact timestamp
     - whether it is really the current experiment
   - never substitute "the most recent log I remember reading" for "the log the user specified"

2. **Do not carry old conclusions into a new round by default.**
   - even if the symptoms look similar, a new timestamp means a new minimum context must be rebuilt
   - this is especially true for fork / exec / reexec lines, where symptoms can look similar while the first bad point has moved

3. **During rollback or restore, do not reconstruct logic from memory.**
   - if the user asks to restore one earlier change set, restore that explicit diff and nothing larger
   - do not roll back or reapply inferred "related logic" casually

4. **Compressed conversation memory is not ground truth.**
   - historical summaries are an index, not a substitute for checking the current files and the current logs again

### 1.3 Mandatory workflow after this lesson

When a similar multi-round debugging scenario appears:

1. If the user specifies a log:
   - restate and verify the exact path first
2. Extract only the minimum facts from that round:
   - first fatal point
   - relevant call chain
   - phenomena newly appearing or disappearing in this round
3. Before changing code, separate:
   - facts directly supported by this round's log
   - guesses inherited from older rounds
4. If the user asks to restore earlier changes:
   - restore by explicit file / explicit diff
   - do not add extra inferred repairs in the same step

### 1.4 Specific reminder for NaCC

- fork / exec / reexec lines easily contaminate each other's diagnosis
- `VM_NACC`, `agent aperture`, `NACC_RECLAIM`, `ptp_list`, and `agent init` may appear in many rounds but do not imply the same root cause
- if the log round is wrong, even careful code reading can produce a "correct optimization for the wrong problem"

This record is not about blame. It exists to make an expensive mistake explicit and procedural.
