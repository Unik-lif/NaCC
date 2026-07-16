# lmbench Agent Init Perf Probe: Debug Request Types

Task: `TASK_20260603_094210_lmbench_agent_init_perf_probe`
Role: `test_runner`
Date: 2026-06-03 +0800
Validation Tier: `T2`

## Preflight

Submodule status was inspected before validation:

| Submodule | Status |
| --- | --- |
| `linux` | clean |
| `qemu` | clean |
| `opensbi` | dirty: `M lib/sbi/sm/sm.c` |
| `agent` | clean |

Required debug build/update actions:

| Command | Result | Log |
| --- | --- | --- |
| `NACC_LOG_DEBUG=1 make opensbi` | rc=0 | `logs/test_runner/TASK_20260603_094210_lmbench_agent_init_perf_probe/build_debug_opensbi_20260603_102425.log` |
| `scripts/cleanup_stale_qemu_owner.sh --apply --test-runner-sessions` | rc=0, no owner found | `logs/test_runner/TASK_20260603_094210_lmbench_agent_init_perf_probe/cleanup_before_linux_update_20260603_102443.log`; helper log `logs/cleanup_stale_qemu_owner_20260603_102443.log` |
| `NACC_LOG_DEBUG=1 make linux-update` | rc=0 | `logs/test_runner/TASK_20260603_094210_lmbench_agent_init_perf_probe/build_debug_linux_update_20260603_102458.log` |
| `scripts/cleanup_stale_qemu_owner.sh --apply --test-runner-sessions` | rc=0, no owner found | `logs/test_runner/TASK_20260603_094210_lmbench_agent_init_perf_probe/cleanup_before_agent_update_20260603_102952.log`; helper log `logs/cleanup_stale_qemu_owner_20260603_102952.log` |
| `NACC_LOG_DEBUG=1 make agent-update` | rc=0 | `logs/test_runner/TASK_20260603_094210_lmbench_agent_init_perf_probe/build_debug_agent_update_20260603_103009.log` |

`make qemu` was not run because `qemu` was clean and the packet did not require a QEMU rebuild.

## Command Path

- Command file: `logs/test_runner/TASK_20260603_094210_lmbench_agent_init_perf_probe/lmbench_agent_init_perf_probe_debug_cmds.txt`
- Materialized auto command: `logs/test_runner/TASK_20260603_094210_lmbench_agent_init_perf_probe_debug_01_20260603_103106_auto_cmd.txt`
- Batch status summary: `logs/test_runner/TASK_20260603_094210_lmbench_agent_init_perf_probe/debug_batch_20260603_103106_summary.log`

Batch command:

```sh
NACC_LOG_DEBUG=1 config/debug-batch.sh --cmd-file logs/test_runner/TASK_20260603_094210_lmbench_agent_init_perf_probe/lmbench_agent_init_perf_probe_debug_cmds.txt --tag-prefix TASK_20260603_094210_lmbench_agent_init_perf_probe_debug --ssh-ready-timeout 240 --ssh-auto-timeout 1200 --wait-after-auto 1260
```

## Artifacts

- VM log: `logs/TASK_20260603_094210_lmbench_agent_init_perf_probe_debug_01_20260603_103106_vm_20260603_103847.log` (`109` lines)
- QEMU log: `logs/TASK_20260603_094210_lmbench_agent_init_perf_probe_debug_01_20260603_103106_qemu_20260603_103847.log` (`69467` lines)
- Live VM pane log: `logs/live_vm_pane_672.log`
- Guest run directory: `/root/lmbench_nacc_runs/TASK_20260603_094210_lmbench_agent_init_perf_probe_debug_20260603_023443`

## Harness Status

- Debug-batch status: `run=1 status=ok`.
- SSH banner: observed after `84` attempts.
- Authenticated SSH readiness: observed after `5` attempts.
- `[NaCC] Auto-running:` appeared in the VM log.
- SSH auto-command exit: `code=0`.
- Configured timeouts: SSH ready `240s`, SSH auto `1200s`, batch wait-after-auto `1260s`.

## Case Summary

These are debug-mode timings only; verbose logging perturbs latency and this record does not treat them as production performance numbers.

| Mode | Case | rc | elapsed_ms | Output |
| --- | --- | ---: | ---: | --- |
| true_nacc | `marker_visibility` | 0 | 51347 | `MARKER_VISIBILITY_TRUE_NACC`; `Simple syscall: 15522.0000 microseconds` |
| true_nacc | `lat_syscall_null_1` | 0 | 32580 | `Simple syscall: 16118.0000 microseconds` |
| true_nacc | `lat_syscall_null_2` | 0 | 30512 | `Simple syscall: 13215.0000 microseconds` |
| true_nacc | `lat_syscall_null_3` | 0 | 31168 | `Simple syscall: 15712.0000 microseconds` |
| true_nacc | `lat_syscall_read_1` | 0 | 29564 | `Simple read: 13419.0000 microseconds` |
| true_nacc | `lat_syscall_read_2` | 0 | 29291 | `Simple read: 19299.0000 microseconds` |
| true_nacc | `lat_syscall_read_3` | 0 | 28111 | `Simple read: 15580.0000 microseconds` |

## Marker Counts

Previously missing init predicates in the QEMU log:

| Predicate | Count | Representative lines |
| --- | ---: | --- |
| `[SBI] NaCC agent completed first full initialization; future invokes use lightweight attach.` | 1 | `logs/TASK_20260603_094210_lmbench_agent_init_perf_probe_debug_01_20260603_103106_qemu_20260603_103847.log:1330` |
| `[SBI] NaCC ready-agent lightweight attach:` | 6 | `...qemu_20260603_103847.log:28002`, `:35170`, `:42127`, `:49116`, `:56083`, `:63209` |

Request-family marker counts from the QEMU log:

| Family / marker pattern | Count |
| --- | ---: |
| lifecycle: `register a new NACC process` | 7 |
| lifecycle: `nacc unregister` | 18 |
| lifecycle: full-init predicate | 1 |
| lifecycle: lightweight attach predicate | 6 |
| user syscall trap: `do_trap_ecall_u.*syscall:` | 1153 |
| user syscall trap: `sys_mmap` | 183 |
| user syscall trap: `sys_getrusage` | 182 |
| user syscall trap: `sys_getppid` | 151 |
| user syscall trap: `sys_close` | 137 |
| user syscall trap: `sys_read` | 105 |
| page fault/private leaf: `do_page_fault` | 18998 |
| page fault/private leaf: `handle_page_fault` | 164 |
| page fault/private leaf: `unmap_page_range` | 808 |
| page fault/private leaf: `unmap_single_vma` | 808 |
| page fault/private leaf: `zap_pte_range` | 1136 |
| secure PTP/PTE: `page_nacc_register_ptp` | 288 |
| secure PTP/PTE: `__pte_alloc` | 168 |
| secure PTP/PTE: `free_pte_range` | 240 |
| secure PTP/PTE: `sm_reclaim_ptp` | 31 |
| secure PTP/PTE: literal `pte` | 14158 |
| secure PTP/PTE: literal `ptp` | 618 |
| private uaccess/copy-user: `copy-user` | 693 |
| private data/debug: `PRIVATE_DATA` | 382 |
| private data/debug: `private_data_stats` | 80 |
| scheduler/context: `context_switch from user to kernel` | 2581 |
| scheduler/context: `Thread has been Switched` | 7215 |
| scheduler/context: `thread_ctx save` | 3608 |
| scheduler/context: `thread_ctx load` | 3641 |
| scheduler/context: `thread_ctx ensure` | 40 |

Representative marker samples:

- Lifecycle/register: `logs/TASK_20260603_094210_lmbench_agent_init_perf_probe_debug_01_20260603_103106_qemu_20260603_103847.log:453`
- Full init: `logs/TASK_20260603_094210_lmbench_agent_init_perf_probe_debug_01_20260603_103106_qemu_20260603_103847.log:1330`
- Lightweight attach: `logs/TASK_20260603_094210_lmbench_agent_init_perf_probe_debug_01_20260603_103106_qemu_20260603_103847.log:28002`
- User syscall trap: `logs/TASK_20260603_094210_lmbench_agent_init_perf_probe_debug_01_20260603_103106_qemu_20260603_103847.log:1642`
- Secure PTP/PTE allocation: `logs/TASK_20260603_094210_lmbench_agent_init_perf_probe_debug_01_20260603_103106_qemu_20260603_103847.log:629`
- Page table allocation: `logs/TASK_20260603_094210_lmbench_agent_init_perf_probe_debug_01_20260603_103106_qemu_20260603_103847.log:631`
- Page fault/unmap marker: `logs/TASK_20260603_094210_lmbench_agent_init_perf_probe_debug_01_20260603_103106_qemu_20260603_103847.log:725`
- Context switch marker: `logs/TASK_20260603_094210_lmbench_agent_init_perf_probe_debug_01_20260603_103106_qemu_20260603_103847.log:462`
- Thread context marker: `logs/TASK_20260603_094210_lmbench_agent_init_perf_probe_debug_01_20260603_103106_qemu_20260603_103847.log:456`

Visibility boundary: the debug log exposes verbose PTE/PTP and private data/debug markers, but this test-runner record does not prove that every successful secure ecall category has a one-line wrapper marker. Log analyzer should treat literal pattern counts as marker visibility, not as exhaustive ecall accounting.

## Fault Scan

No `Kernel panic`, `Oops`, `BUG:`, `segfault`, `qemu-owner-block`, `ssh-ready-timeout`, `ssh-auto-timeout`, `ssh-auto-exit code=255`, `auto-timeout`, `pane-timeout`, or `logger-failed` markers were found in the preserved VM, QEMU, live VM pane, or materialized auto-command logs.

## Handoff Question

Log analyzer should compress the debug VM/QEMU evidence and answer: given one full initialization marker, six lightweight attach markers, and the high-volume request-family markers above, which visible request families dominate the true-NaCC `lat_syscall null/read` debug path, and what visibility boundaries prevent treating these debug marker counts as final production performance attribution?
