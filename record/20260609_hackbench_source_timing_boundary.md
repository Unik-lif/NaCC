# Hackbench Source Timing Boundary And Follow-Up Decision

Date: 2026-06-09

Related packets:
- `docs/workflow/tasks/completed/TASK_20260609_091408_breakdown.md`
- `docs/workflow/tasks/completed/TASK_20260609_120217_breakdown_with_src.md`

Related artifacts:
- `record/20260609_hackbench_followup_checklist.md`
- `logs/test_runner/TASK_20260609_091408_breakdown/summary.normalized.tsv`
- `logs/test_runner/TASK_20260609_091408_breakdown/commands.log`
- `logs/test_runner/TASK_20260609_091408_breakdown/precheck.log`

## Context

The matched-wrapper Hackbench breakdown showed that the NaCC arm still had a large wrapper-minus-Hackbench gap after removing the old `dockero` versus `docker` wrapper mismatch.

The dominant coarse bucket was:
- origin `mode_to_time_observed_ms=19530`
- NaCC `mode_to_time_observed_ms=150133`

The matching Hackbench internal times were much smaller:
- origin `Time: 16.188`
- NaCC `Time: 24.320`

This raised the question of what Hackbench's own `Time:` line actually covers.

## Source Boundary Read

The guest build recorded in `precheck.log` used:
- repo: `https://github.com/jlelli/rt-tests.git`
- commit: `857cdd5320ce1f293f5dbcbec79cc8fe22b0bebf`
- source: `src/hackbench/hackbench.c`

In that source, the benchmark prints the mode line before worker setup:
- `Running in threaded mode with ...`
- `Each sender will pass ...`

For the current payload, `hackbench -T -g 25 -f 40 -s 100 -l 5`, threaded mode creates:
- `25` groups
- `40` receiver threads per group
- `40` sender threads per group
- `25 * 40 * 2 = 2000` pthread workers total

The relevant sequence is:
1. parse options
2. print the mode and message-count lines
3. allocate `child_tab`
4. create ready/wake fd pairs
5. for each group, create socketpairs and pthread workers
6. wait until all workers have written their ready byte
7. call `gettimeofday(&start, NULL)`
8. write the wake byte so workers begin message traffic
9. join all workers
10. call `gettimeofday(&stop, NULL)`
11. print `Time:`

Therefore Hackbench's internal `Time:` starts only after all worker threads are created and have reached the ready barrier. It does not include the 2000-thread setup cost, socketpair setup, or worker startup-to-ready latency.

## Interpretation

The previous `mode -> Time` external window should not be interpreted as only Hackbench's internal timed workload.

It contains at least:
- post-mode worker setup: socketpair creation, pthread creation, and worker startup
- worker readiness synchronization before the internal timer starts
- Hackbench's internal timed traffic and join interval
- stdout observation delay around the final `Time:` line

Given the source boundary, the large NaCC excess outside Hackbench's printed `Time:` is plausibly concentrated in setup, especially high fan-out thread creation and NaCC per-task/thread attach or bookkeeping paths. This remains a source-informed hypothesis, not a proven repair target.

## Decision

Do not route a direct Hackbench optimization or repair from this packet.

Record the finding and defer Hackbench-specific optimization until the project has broader benchmark coverage. The immediate next direction should be to run other benchmarks with controlled, scriptable command shapes, so later optimization work has more than one workload signal.

If Hackbench is revisited, the next useful instrumentation should split:
- mode-line printed
- worker creation begins
- all workers created
- all workers ready
- internal timer starts
- internal timer stops
- final `Time:` printed

Any future Hackbench route should keep the same-daemon `runc-origin` versus `runc` shape and the same `-T -g 25 -f 40 -s 100 -l 5` payload unless the human explicitly changes the controlled variables.
