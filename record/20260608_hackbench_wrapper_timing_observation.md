# Hackbench Wrapper Timing Observation

Date: 2026-06-08
Related tasks:
- `TASK_20260606_165146_hackbench`
- `TASK_20260608_110148_free_formalize`

## Observation

The current NaCC Hackbench evidence separates two different timing surfaces:

- Hackbench-reported workload time: the `Time:` line emitted by `hackbench`.
- Harness/wrapper elapsed time: the script's `wrapper_elapsed_ms`, measured around the container command.

The latest accepted NaCC diagnostic completed:

- Command shape: `docker run --rm --runtime runc ... hackbench -T -g 25 -f 40 -s 100 -l 5`
- VM log: `logs/TASK_20260608_110148_free_formalize_hackbench_T_nacc_l5_nolog_20260608_163301_01_20260608_163355_vm_20260608_164130.log`
- Result: `HACKBENCH_RUN_RESULT side=nacc mode=thread loop=5 aggregate_messages=5000 rc=0`
- Hackbench `Time:`: `24.482s`
- Wrapper elapsed: `163806ms`
- Wrapper-minus-Hackbench delta: about `139.3s`

The prior native/origin thread-mode reference completed:

- Command shape: `dockero run ... hackbench -T -g 25 -f 40 -s 100 -l 100`
- VM capture: `logs/test_runner/TASK_20260606_165146_hackbench/manual_stop_thread_l100_vm_20260606_201357.log`
- Result: `HACKBENCH_RUN_RESULT side=native mode=thread loop=100 aggregate_messages=100000 rc=0`
- Hackbench `Time:`: `291.984s`
- Wrapper elapsed: `307514ms`
- Wrapper-minus-Hackbench delta: about `15.5s`

## Important Boundary

The two wrapper values are not same-mechanism measurements:

- native/origin used `dockero` and direct command-output capture;
- NaCC used `docker --runtime runc`, `timeout --foreground`, `sh -c`, and streamed target output through `tee`;
- the small shell/timeout/tee differences are unlikely to explain a roughly 139s delta by themselves;
- the dominant candidate is NaCC runtime/container lifecycle work around registration, attach, task/thread context setup, or teardown.

Hackbench's own `Time:` does not appear to cover the whole container/runtime lifecycle. In the known rt-tests Hackbench structure, the benchmark creates worker groups and waits for readiness before the main timed message-passing interval. Therefore worker creation and readiness can inflate wrapper time without being fully reflected in `Time:`.

## Workload-Side Signal

The workload-side signal is still not free:

- native/origin thread-mode `-l 100`: `291.984 / 100 = 2.92s` per loop
- NaCC thread-mode `-l 5`: `24.482 / 5 = 4.90s` per loop

This rough comparison suggests NaCC is already slower inside the Hackbench-timed interval, around `1.7x` by this coarse per-loop estimate. However, the larger observed anomaly is outside the Hackbench timer: the NaCC wrapper-minus-Hackbench delta is about `139.3s` for the `-l 5` diagnostic.

## Current Interpretation

The recent evidence does not point to ordinary single fork+exec or final exit as the whole explanation. Previous small probes completed:

- NaCC `/bin/true` completed.
- NaCC tiny Hackbench completed.
- Direct guest Hackbench smoke completed.

The suspicious shape is target-scale thread fan-out: `-T -g 25 -f 40` reports 25 groups, 80 file descriptors per group, and 2000 tasks. The likely hidden cost is concentrated around worker/task creation and readiness, or NaCC's per-thread registration/attach path under that fan-out. This also fits the earlier `TASK_20260606_165146_hackbench` failure boundary, where the debug run hit `CONTAINER_FULL`, early fork-child registration failure, missing child registration before `sm_nacc_attach_forked_child`, and fatal attach failure under target-scale Hackbench.

## Recommended Next Measurement

Before treating `wrapper_elapsed_ms` as a single opaque regression number, add timestamp cut points around the NaCC target command:

- before outer `docker run`;
- immediately inside the container before invoking Hackbench;
- after Hackbench prints its mode line;
- after Hackbench prints `Time:`;
- immediately before container process exit;
- after outer `docker run` returns.

This would split the current wrapper-minus-Hackbench delta into:

- Docker/runc/NaCC startup and registration;
- Hackbench worker creation and readiness before its timed interval;
- Hackbench timed message-passing interval;
- container/NaCC teardown and cleanup.

## Closeout Note

The current allocator reclaim task is being archived by human decision before running the held normal/no-log NaCC-only `-l 100` Phase B. That does not mark the original pressure validation as passed. It records that the allocator patch passed build/workload-3 baseline and the shorter no-log Hackbench fan-out diagnostic, while the larger Hackbench timing and review questions should move into the next review or performance-analysis task.
