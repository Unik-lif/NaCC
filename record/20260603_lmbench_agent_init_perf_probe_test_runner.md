# lmbench Agent Init Perf Probe

Task: `TASK_20260603_094210_lmbench_agent_init_perf_probe`
Role: `test_runner`
Date: 2026-06-03 +0800

## Command Path

- Command file: `logs/test_runner/TASK_20260603_094210_lmbench_agent_init_perf_probe/lmbench_agent_init_perf_probe_cmds.txt`
- Batch command:

```sh
NACC_LOG_DEBUG=0 config/debug-batch.sh --cmd-file logs/test_runner/TASK_20260603_094210_lmbench_agent_init_perf_probe/lmbench_agent_init_perf_probe_cmds.txt --tag-prefix TASK_20260603_094210_lmbench_agent_init_perf_probe --ssh-ready-timeout 240 --ssh-auto-timeout 1200 --wait-after-auto 1260
```

## Artifacts

- Batch log: `logs/test_runner/TASK_20260603_094210_lmbench_agent_init_perf_probe/debug_batch_20260603_095955.log`
- VM log: `logs/TASK_20260603_094210_lmbench_agent_init_perf_probe_01_20260603_095955_vm_20260603_100615.log`
- QEMU log: `logs/TASK_20260603_094210_lmbench_agent_init_perf_probe_01_20260603_095955_qemu_20260603_100615.log`
- Live VM pane log: `logs/live_vm_pane_667.log`
- Guest run directory: `/root/lmbench_nacc_runs/TASK_20260603_094210_lmbench_agent_init_perf_probe_20260603_020337`

## Build and Harness Status

- Submodule preflight: `linux`, `qemu`, and `agent` were clean; `opensbi` was dirty (`M lib/sbi/sm/sm.c`).
- Build action: `make opensbi` completed successfully before validation.
- Debug-batch status: `run=1 status=ok`.
- SSH banner: observed after 87 attempts.
- Authenticated SSH readiness: observed after 5 attempts.
- `[NaCC] Auto-running:` appeared once.
- SSH auto-command exit: `code=0`.
- Configured timeouts: SSH ready `240s`, SSH auto `1200s`, batch wait-after-auto `1260s`.

## Case Summary

| Mode | Case | rc | elapsed_ms | Output |
| --- | --- | ---: | ---: | --- |
| guest | `lat_syscall_null` | 0 | 191 | `Simple syscall: 4.9074 microseconds` |
| guest | `lat_syscall_read` | 0 | 165 | `Simple read: 9.1538 microseconds` |
| default_docker | `lat_syscall_null` | 0 | 21827 | `Simple syscall: 6.5116 microseconds`; also printed `Failed to write to log, write logpipe: file already closed` |
| default_docker | `lat_syscall_read` | 0 | 16533 | `Simple read: 10.4151 microseconds`; also printed `Failed to write to log, write logpipe: file already closed` |
| true_nacc | `lat_syscall_null_1` | 0 | 18989 | `Simple syscall: 7.2185 microseconds` |
| true_nacc | `lat_syscall_null_2` | 0 | 17411 | `Simple syscall: 60.8280 microseconds` |
| true_nacc | `lat_syscall_null_3` | 0 | 19550 | `Simple syscall: 72.9167 microseconds` |
| true_nacc | `lat_syscall_read_1` | 0 | 22249 | `Simple read: 182.6981 microseconds` |
| true_nacc | `lat_syscall_read_2` | 0 | 15388 | `Simple read: 22.2308 microseconds` |
| true_nacc | `lat_syscall_read_3` | 0 | 16359 | `Simple read: 206.0943 microseconds` |

## Marker Counts

- Full-init predicate count: `0`
- Full-init predicate: `[SBI] NaCC agent completed first full initialization; future invokes use lightweight attach.`
- Lightweight attach predicate count: `0`
- Lightweight attach predicate: `[SBI] NaCC ready-agent lightweight attach:`
- Matching marker lines: none for either predicate in the preserved QEMU log.

## Fault Scan

No `Kernel panic`, `Oops`, `BUG:`, `segfault`, `qemu-owner-block`, `ssh-ready-timeout`, `ssh-auto-timeout`, or `ssh-auto-exit code=255` markers were found in the preserved batch, VM, QEMU, or live VM logs.

## Handoff Question

Log analyzer should compress the VM/QEMU evidence and answer whether the successful repeated true-NaCC lmbench run is marker-inconclusive because both required OpenSBI marker predicates are absent, and whether any other preserved QEMU evidence can classify full initialization versus lightweight attach without using latency as proof.
