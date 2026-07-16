# lmbench Direct Smoke Under NaCC

Task: `TASK_20260603_011348_lmbench_test`
Role: `test_runner`
Date: 2026-06-03 +0800

## Command Path

- Command file: `logs/test_runner/TASK_20260603_011348_lmbench_test/lmbench_direct_smoke_cmds.txt`
- Batch command:

```sh
NACC_LOG_DEBUG=0 config/debug-batch.sh --cmd-file logs/test_runner/TASK_20260603_011348_lmbench_test/lmbench_direct_smoke_cmds.txt --tag-prefix TASK_20260603_011348_lmbench_test_lmbench_direct_smoke --ssh-ready-timeout 240 --ssh-auto-timeout 600 --wait-after-auto 720
```

## Artifacts

- Batch log: `logs/test_runner/TASK_20260603_011348_lmbench_test/debug_batch_20260603_013033.log`
- VM log: `logs/TASK_20260603_011348_lmbench_test_lmbench_direct_smoke_01_20260603_013033_vm_20260603_013543.log`
- QEMU log: `logs/TASK_20260603_011348_lmbench_test_lmbench_direct_smoke_01_20260603_013033_qemu_20260603_013543.log`
- Live VM pane log: `logs/live_vm_pane_662.log`
- Guest run directory: `/root/lmbench_nacc_runs/TASK_20260603_011348_lmbench_test_direct_smoke_20260602_173410`
- OpenSBI build log: `logs/test_runner/TASK_20260603_011348_lmbench_test/build_opensbi_20260603_012456.log`

## Build and Harness Status

- Submodule preflight: `linux`, `qemu`, and `agent` were clean; `opensbi` was dirty.
- Build action: `make opensbi` completed successfully before validation.
- SSH banner: observed after 84 attempts.
- Authenticated SSH readiness: observed after 5 attempts.
- `[NaCC] Auto-running:` appeared.
- SSH auto-command exit: `code=0`.
- Configured timeouts: SSH ready `240s`, SSH auto `600s`, batch wait-after-auto `720s`.

## Direct lmbench Result

All requested direct Docker cases completed with `rc=0`:

| Case | rc | Output |
| --- | ---: | --- |
| `path_probe` | 0 | `lat_syscall` and `bw_mem` existed and were executable |
| `lat_syscall null` | 0 | `Simple syscall: 55.8503 microseconds` |
| `lat_syscall read` | 0 | `Simple read: 261.8889 microseconds` |
| `bw_mem 1m rd` | 0 | empty output, 0-byte per-case log |

## Observed Exception

No lmbench exception, SSH timeout, auto-command timeout, QEMU owner block, kernel panic, Oops, segfault, or obvious fault marker was observed in the bounded marker scan of the preserved VM/QEMU/live/batch logs.

## Likely Failure Area / Next Lead

No direct-smoke failure was captured in this run. The only notable item for follow-up review is that `bw_mem 1m rd` returned `rc=0` with an empty output file. Log analyzer should confirm whether that empty-output success is expected for this workload under the current `nacc-lmbench:jammy` image and NaCC Docker path, then planner can decide whether a separate wrapper/script probe is still needed.
