# Hackbench Follow-Up Checklist After Matched-Wrapper Breakdown

Date: 2026-06-09
Related packet:
- `docs/workflow/tasks/completed/TASK_20260609_091408_breakdown.md`

Related artifacts:
- `logs/test_runner/TASK_20260609_091408_breakdown/summary.normalized.tsv`
- `logs/test_runner/TASK_20260609_091408_breakdown/commands.log`
- `logs/test_runner/TASK_20260609_091408_breakdown/runtime_identity.log`
- `logs/test_runner/TASK_20260609_091408_breakdown/precheck.log`
- `record/20260608_hackbench_wrapper_timing_observation.md`
- `record/20260607_hackbench_nacc_metadata_dynamicization.md`

## Current Accepted Facts

- The matched-wrapper measurement is valid and completed successfully for both origin and NaCC.
- Both sides used the same Docker daemon and the same outer wrapper shape; only the runtime changed:
  - origin: `--runtime runc-origin`
  - NaCC: `--runtime runc`
- The old `dockero` versus `docker` wrapper mismatch is no longer the primary explanation for the large NaCC wrapper gap in this `-l 5` run.
- The dominant extra NaCC elapsed time is localized only coarsely to the post-mode/pre-`Time:` window.

Reference numbers from `summary.normalized.tsv`:
- origin: `wrapper_elapsed_ms=36586`, `hackbench_time_seconds=16.188`, `wrapper_minus_hackbench_ms=20399`, `mode_to_time_observed_ms=19530`
- NaCC: `wrapper_elapsed_ms=168035`, `hackbench_time_seconds=24.320`, `wrapper_minus_hackbench_ms=143715`, `mode_to_time_observed_ms=150133`

## Evidence Boundary

What the current evidence supports:
- Docker startup is not the dominant difference in the matched-wrapper run.
- Container entry is not the dominant difference in the matched-wrapper run.
- Final outer return/teardown is not the dominant difference in the matched-wrapper run.
- The large NaCC-side excess is inside the benchmark process window after the mode line is observed and before the final `Time:` line is observed.

What the current evidence does not support:
- a source-level root-cause claim inside Hackbench, runc, Linux, OpenSBI, or Agent
- a claim that the extra time is entirely inside Hackbench's internal timed interval
- a claim that the extra time is entirely before Hackbench starts timing
- a direct repair task without finer in-process attribution

## Main Follow-Up Question

The next useful question is not "why is wrapper elapsed large?" in the abstract.
It is:

"Inside the observed `mode line -> Time:` window, which parts are outside Hackbench's own timer and which parts are inside it, and which NaCC paths dominate the extra time?"

## Checklist For The Next Investigation Packet

1. Confirm Hackbench timing boundaries from source.
- Read the exact `hackbench.c` used by the guest build.
- Identify where the threaded mode line is printed.
- Identify where the benchmark start time is recorded.
- Identify where the final `Time:` value is computed and printed.
- Record whether worker/thread/process creation and readiness happen before or after the internal start timestamp.
- Record whether join/wait/cleanup happen before or after the printed `Time:`.

2. Reconstruct the thread/task fan-out shape for `-T -g 25 -f 40 -s 100 -l 5`.
- Count how many pthreads or Linux tasks are created.
- Record where socketpair or pipe setup occurs.
- Record where group-level synchronization or readiness barriers occur.
- Keep the distinction between shared address-space threads and per-task PID/TID bookkeeping explicit.

3. Reconcile the source structure with existing NaCC evidence.
- Compare the source-level sequence with the coarse buckets in `summary.normalized.tsv`.
- Compare with earlier debug evidence showing `clone`, `socketpair`, `mmap`, `mprotect`, and NaCC child-attach activity under target-scale Hackbench fan-out.
- State clearly which parts are already evidenced and which parts remain inference.

4. Design minimal extra instrumentation before attempting any repair.
- Prefer small timestamp cut points over broad debug logging.
- If instrumenting Hackbench, add timestamps around:
  - just before worker/task creation begins
  - just after all workers are ready
  - immediately before the internal timed interval starts
  - immediately after the internal timed interval ends
  - just before the final `Time:` line is printed
- If instrumenting outside Hackbench, consider bounded tracing around clone/thread creation and NaCC attach/registration paths only.
- Avoid a high-volume debug configuration that can itself distort runtime or trigger timeout noise.

5. Keep the next packet narrowly scoped.
- Do not reopen the matched-wrapper packet for direct repair.
- Do not jump to `-l 100` until the `-l 5` timing window is better split.
- Do not treat old `dockero` evidence as the primary comparator for the current question.
- Do not mix source attribution, repair, and scale-up validation into one packet.

## Good Deliverable Shape For The Next Packet

A good follow-up deliverable should produce:
- a short code-reading note for Hackbench timing boundaries
- a precise statement of what the mode line and `Time:` do and do not cover
- one minimally invasive instrumentation plan
- a bounded test shape to validate that plan
- an explicit evidence/inference boundary before any repair routing

## Likely Hypotheses Worth Testing

These are hypotheses, not accepted facts:
- Hackbench may print the mode line before a large worker/thread/task creation and readiness phase.
- NaCC may incur substantial per-task or per-thread registration/attach cost during that phase.
- Some of the NaCC-side excess may still be inside Hackbench's internal timed interval, but the current evidence does not isolate that split.

## Human-Safe Next Step

If a new task is opened, it should be framed as a source-and-instrumentation packet:
- first read Hackbench source and define timing boundaries
- then propose or add the smallest instrumentation needed to split the `mode -> Time` window
- only after that decide whether a repair route is justified
