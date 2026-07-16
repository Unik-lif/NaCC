# lmbench Same-Daemon `runc-origin` vs NaCC `runc` Closeout

Date: 2026-06-04

## Context

This record closes
`TASK_20260604_160118_lmbench_same_daemon_runc_origin_compare`.

The task was opened because the previous repeat packet
`TASK_20260604_130858_lmbench_three_repeat_runc_compare` compared:

- origin: `/usr/local/bin/dockero` using `/usr/local/sbin/runc-origin`;
- NaCC: `docker` using `/usr/local/sbin/runc`.

That split made the syscall microbenchmark result suspicious. The corrected
run removed the CLI/daemon split by using one Docker daemon and explicit OCI
runtime selection for both arms.

## Runtime Setup

The corrected run registered only a non-reserved Docker runtime:

- `runc-origin` -> `/usr/local/sbin/runc-origin`

It did not define or override Docker's reserved built-in `runc` runtime name.

The measured arms were:

- origin: `docker run --runtime runc-origin ...`
- NaCC: `docker run --runtime runc ...`

Runtime identity evidence:

- `identity/daemon.json.after` registers only `runc-origin`.
- `identity/docker_info_after_runtime_config.txt` lists
  `io.containerd.runc.v2 runc runc-origin` and `Default Runtime: runc`.
- origin probe inspect shows `HostConfig.Runtime=runc-origin`.
- NaCC probe inspect shows `HostConfig.Runtime=runc`.
- `/usr/local/sbin/runc-origin` sha256:
  `f5a95d20c59ea942abb54f3d9114e370dcc48b6d9b37329155e49e3e23eee0d0`.
- `/usr/local/sbin/runc` sha256:
  `7f7caabb464ddf40a2638e60f0666e5f05cbf6d572ec22f9903850e0b3372b5d`;
  this binary is dirty and contains NaCC marker strings.

## Artifacts

Primary packet:

- `docs/workflow/tasks/completed/TASK_20260604_160118_lmbench_same_daemon_runc_origin_compare.md`

Primary logs and artifacts:

- VM log:
  `logs/TASK_20260604_160118_lmbench_same_daemon_01_20260604_164636_vm_20260604_171529.log`
- QEMU log:
  `logs/TASK_20260604_160118_lmbench_same_daemon_01_20260604_164636_qemu_20260604_171529.log`
- launcher log:
  `logs/test_runner/TASK_20260604_160118_lmbench_same_daemon_runc_origin_compare/debug_batch_20260604_164624.log`
- extracted guest artifacts:
  `logs/test_runner/TASK_20260604_160118_lmbench_same_daemon_runc_origin_compare/extracted_guest_artifacts_20260604_085037/`
- key tables:
  `selected_metrics.tsv`, `repeat_vs_prior.tsv`, `summary.tsv`,
  `metric_candidates.tsv`, `container_names.txt`

The run completed 84 expected executions:

- 3 repeats
- 2 runtime arms
- 14 selected direct-binary lmbench cases
- all 84 rows returned `rc=0`
- all selected metric values came from `stderr`
- 76/84 rows had selected numeric values

## Score Summary

Latency rows are lower-is-better. Bandwidth rows are higher-is-better.

| Case | Unit | Origin repeats | Origin avg | NaCC repeats | NaCC avg | Readout |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| `lat_syscall_null` | us | 4.9865, 4.9909, 4.9283 | 4.9686 | 4.9533, 4.9204, 4.8097 | 4.8945 | NaCC lower by about 1.5%, 3/3 repeats |
| `lat_syscall_read` | us | 8.5738, 8.3252, 8.6695 | 8.5228 | 8.5692, 8.2462, 8.3511 | 8.3888 | NaCC lower by about 1.6%, 3/3 repeats |
| `lat_syscall_write` | us | 5.9086, 5.9070, 5.8610 | 5.8922 | 5.9704, 5.8763, 5.9255 | 5.9241 | mixed; NaCC about 0.5% slower by average |
| `lat_pipe` | us | 617.2878, 777.8753, 795.9081 | 730.3571 | 638.1589, 806.3544, 670.5241 | 705.0125 | average favors NaCC, repeats are mixed |
| `bw_pipe` | MB/s | 40.51, 50.64, 52.26 | 47.8033 | 51.33, 44.14, 48.48 | 47.9833 | effectively tied |
| `bw_mem_1m_rd` | MB/s | 3924.80, 14994.96, 15279.80 | 11399.9 | 14577.05, 14922.81, 14880.45 | 14793.4 | origin has one large low outlier; do not claim |
| `bw_mem_1m_wr` | MB/s | 11397.57, 11672.46, 11459.85 | 11510.0 | 11710.90, 11715.93, 4743.04 | 9389.96 | NaCC has one large low outlier; do not claim |
| `lat_proc_fork` | us | 10477, 10185, 9946 | 10202.7 | 10932, 15183, 9824 | 11979.7 | average worse for NaCC, but noisy |
| `lat_proc_exec` | us | 26224, 10540, 20406 | 19056.7 | 10444, 10516, 10256 | 10405.3 | origin has high outliers; do not claim architectural win |
| `lat_unix` | us | 1182, 1122, 1056.5 | 1120.2 | 1066, 5050, 1128 | 2414.7 | NaCC has one large high outlier; do not claim |
| `bw_unix` | MB/s | 91.88, 80.00, 78.90 | 83.5933 | 85.96, 91.57, 86.81 | 88.1133 | average favors NaCC, noisy |

The following file-syscall rows are diagnostic-contaminated and should not be
used as clean performance data:

| Case | Origin selected values | NaCC selected values | Problem |
| --- | ---: | ---: | --- |
| `lat_syscall_stat` | 14754.0000 only | 5905.0000, 0.0002 | missing candidates and near-zero/diagnostic outliers |
| `lat_syscall_fstat` | none | 4079.0000, 30.1250 | missing candidates and diagnostic outliers |
| `lat_syscall_open` | 7259.0000, 0.0000 | 0.7387, 4576.0000, 2.4453 | missing candidates and near-zero/diagnostic outliers |

## Interpretation

The same-daemon runtime-selection question is resolved: Docker can select
`/usr/local/sbin/runc-origin` through `docker run --runtime runc-origin` while
using the same Docker daemon for the NaCC arm through `docker run --runtime
runc`.

The old large NaCC-faster syscall result weakens sharply after removing the
`/usr/local/bin/dockero` versus `docker` split. In the corrected run:

- `lat_syscall_null` and `lat_syscall_read` retain a small NaCC-lower signal
  around 1.5 to 1.6 percent across all three repeats.
- `lat_syscall_write` no longer supports the earlier NaCC-faster conclusion.
- memory bandwidth, process, Unix socket, and file-syscall rows are too noisy
  for broad performance claims.

The likely readout is that the prior larger NaCC advantage was amplified by
baseline impurity or run-environment differences between `dockero` and
`docker`. This is an inference from the origin arm becoming much faster under
the corrected same-daemon setup, not proof of a specific architectural
mechanism.

## Follow-Up Boundary

No source repair follows directly from this packet.

Future work should be opened as separate human-approved tasks if needed:

- a narrow statistical repeat focused only on `lat_syscall_null/read/write`;
- a cleaned or replaced method for `lat_syscall_stat/fstat/open`;
- a stronger benchmark design for explaining why any small NaCC-lower signal
  remains in simple syscall rows.
