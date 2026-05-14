# 2026-05-14 NaCC refcount T1 SUM trap readout

## Context

Task: `TASK_20260514_103148_nacc_fix_refcount_metadata`

The T1 validation rebuilt OpenSBI, Linux, and Agent, then ran the workload
1..8 batch from `config/debug-batch.private_baseline_t1.txt`.

Primary wrapper log:

- `logs/test_runner_batch_TASK_20260514_103148_20260514_122601.log`

The workload completed successfully: all eight entries ended with `status=ok`
and the VM-side auto commands exited with code 0. No searched RSS/refcount
failure marker reappeared (`BUG: Bad rss-counter state`, `Oops`, SIGBUS,
private-PFN release failure, refcount overflow, or refcount-arena panic).

## SUM on/off private-data census

The table below records the final `private-sum-census-total` and
`private-sumoff-profile-total` values from the eight QEMU logs.

| Run | Workload shape | Private total | SUM-on | SUM-off | SUM-off load | SUM-off store |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | `printf alpha >/dev/null` | 1318 | 1318 | 0 | 0 | 0 |
| 2 | `read </etc/hostname` | 1907 | 1907 | 0 | 0 | 0 |
| 3 | fork/COW shell repro | 7075 | 1955 | 5120 | 5120 | 0 |
| 4 | `cat /etc/hostname` | 7052 | 2956 | 4096 | 4096 | 0 |
| 5 | `echo alpha | cat` | 12356 | 3652 | 8704 | 8704 | 0 |
| 6 | `wc -c /etc/hostname` | 7147 | 3051 | 4096 | 4096 | 0 |
| 7 | `echo alpha | wc -c` | 12893 | 3677 | 9216 | 9216 | 0 |
| 8 | shared-memory repro | 2566 | 518 | 2048 | 2048 | 0 |

## Immediate interpretation

The current refcount/lifecycle prototype did not fully eliminate SUM-off
private-data traps. Workload 1 and 2 had no SUM-off private-data traps, but
workload 3 through 8 still did.

The remaining SUM-off traps are more concentrated than the earlier broad
ordinary-page lifecycle problem:

- every remaining SUM-off event in this run was a load, not a store;
- the access class was `kernel_high`, not `user_like_low`;
- the top PCs mapped to `__pi___memcpy` in
  `linux/arch/riscv/lib/memcpy.S`;
- the repeated PC cluster starts around `0xffffffff80a21834`.

Address resolution used:

```text
riscv64-linux-gnu-addr2line -e riscv-linux/vmlinux -f -C \
  0xffffffff80a21834 0xffffffff80a21880
```

Result:

```text
__pi___memcpy
/home/link/NaCC/linux/arch/riscv/lib/memcpy.S:43
__pi___memcpy
/home/link/NaCC/linux/arch/riscv/lib/memcpy.S:63
```

## Security note

This is not only a performance concern. A SUM-off private-data trap means the
kernel still reached toward a protected private PFN through a path where the
trusted side had to classify or mediate the access. The current work improved
the lifecycle boundary and kept the T1 workloads running, but it has not yet
fully narrowed the access surface.

The next task should treat this as a security-boundary tightening problem:
identify the remaining memcpy-driven SUM-off read paths, decide whether they
are legitimate user-copy style accesses or avoidable Linux-private-data
touches, and then choose a narrower policy for allowing, redirecting, or
eliminating them.

## Suggested follow-up boundary

Open a separate task for SUM-off trap convergence rather than extending the
PFN-refcount packet. The follow-up should start from these artifacts:

- this readout file;
- `logs/test_runner_batch_TASK_20260514_103148_20260514_122601.log`;
- the eight QEMU logs named in that wrapper log;
- the `private-sumoff-pc-top` blocks for runs 3 through 8;
- `linux/arch/riscv/lib/memcpy.S` at the resolved PC offsets.

Initial questions:

- Why do workloads 1 and 2 stay at `sum_off=0` while 3 through 8 do not?
- Which call sites reach `__pi___memcpy` with SUM off and a private-data PFN?
- Are these remaining reads expected user-copy accesses, file/pipe/shm helper
  copies, or residual ordinary Linux lifecycle touches?
- Should the next policy reduce the trap surface, add stricter provenance
  checks, or move the remaining data path into an explicit trusted copy path?
