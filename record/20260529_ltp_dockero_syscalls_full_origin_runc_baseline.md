# LTP Syscalls Through dockero / runc-origin: Full Baseline

Date: 2026-05-29

## Goal

Rerun the upstream LTP `runtest/syscalls` baseline through a cleaner Docker
runtime path:

- Docker daemon wrapper: `/usr/local/bin/dockero`
- Docker socket: `/run/dockero.sock`
- Default runtime: `runc-origin`
- Runtime binary: `/usr/local/sbin/runc-origin`

This checks whether the previous default-Docker `rc=2` population was caused by
the local NaCC-patched `runc` binary.

## Setup

- Guest LTP tree: `/root/ltp`
- Docker image: `ubuntu:22.04`
- LTP runner: `scripts/ltp_docker_syscalls_runner.sh`
- Runner switch: `LTP_DOCKER_CLI=/usr/local/bin/dockero`
- Selected suite: `runtest/syscalls`
- Selected entries: `1506`
- Syscall executable symlinks prepared by runner: `1520`
- Per-case timeout: `120s` with `timeout --kill-after=10s`
- Guest run directory:
  `/root/ltp_docker_runs/syscalls_full_20260529_060427`

The runner uses the already-built guest LTP tree and bind-mounts it into the
container at `/root/ltp`. It does not rebuild LTP inside Docker.

## Artifacts

- Local summary:
  `logs/ltp_dockero_syscalls_full_default_01_20260529_140000_summary.tsv`
- Local counts:
  `logs/ltp_dockero_syscalls_full_default_01_20260529_140000_counts.txt`
- Command-missing list:
  `logs/ltp_dockero_syscalls_full_default_01_20260529_140000_rc127.tsv`
- Timeout/kill list:
  `logs/ltp_dockero_syscalls_full_default_01_20260529_140000_timeout_kill.tsv`
- Diff against previous default Docker baseline:
  `logs/ltp_dockero_vs_default_rc_diff_20260529_140000.txt`
- Batch VM log:
  `logs/ltp_dockero_syscalls_full_default_01_20260529_140000_01_20260529_135754_vm_20260529_151739.log`
- Batch QEMU log:
  `logs/ltp_dockero_syscalls_full_default_01_20260529_140000_01_20260529_135754_qemu_20260529_151739.log`

## Result

The full run reached all `1506` entries and produced a complete summary.

Return-code summary:

- Total entries attempted: `1506`
- `rc=0`: `896`
- Non-zero: `610`
- `rc=2`: `269`
- `rc=32`: `204`
- `rc=127`: `45`
- `rc=124`: `11`
- `rc=137`: `3`
- Other non-zero return codes: `78`

LTP sub-result fields accumulated from per-test output:

- `passed=5081`
- `failed=356`
- `broken=299`
- `skipped=474`
- `warnings=36`

As before, `passed=5081` is the sum of LTP sub-assertions, not the number of
`runtest/syscalls` entries. The entry-level pass count is `896/1506` by wrapper
return code.

## Comparison With Previous Default Docker Baseline

Previous default-Docker baseline:

- Record:
  `record/20260529_ltp_docker_syscalls_full_default_baseline.md`
- Summary:
  `logs/ltp_docker_syscalls_full_default_01_20260529_102240_summary.tsv`
- Entry-level result: `898/1506` with `rc=0`
- `rc=2`: `269`
- `rc=127`: `45`

`dockero` / `runc-origin` baseline:

- Entry-level result: `896/1506` with `rc=0`
- `rc=2`: `269`
- `rc=127`: `45`

Only six entries changed wrapper return code:

```text
accept02          old rc=0    new rc=2
clock_gettime04   old rc=1    new rc=0
fcntl12           old rc=0    new rc=124
nice05            old rc=2    new rc=6
sendfile09_64     old rc=0    new rc=124
futex_waitv02     old rc=34   new rc=32
```

The `rc=2` set changed by one swap:

- old `rc=2` but not new `rc=2`: `nice05`
- new `rc=2` but not old `rc=2`: `accept02`

Therefore the total `rc=2` count is identical: `269` in both runs.

The `rc=127` count is also identical: `45`. This reinforces the earlier
interpretation that these are command/build-helper gaps rather than a runtime
specific effect.

## Timeout / Cleanup Notes

The LTP loop completed and wrote all `1506` summary rows. After completion,
the `dockero` Docker client again remained stuck waiting for cleanup of a
`Dead` container, similar to the previous default-Docker full run.

Observed container state:

```text
STATUS: Dead
COMMAND: bash /results/runner.sh docker-loop full
```

`docker rm -f` reported that removal was already in progress. Since the LTP
summary was already complete and copied to the host, the stuck guest Docker
client was killed to let the batch command continue and print the saved
summary. The batch log then exited with `code=0`.

Treat this as a Docker/container cleanup artifact after test completion, not as
an LTP suite failure.

Timeout/kill entries in the `dockero` run:

```text
creat05
epoll01
fcntl12
fcntl14
fcntl14_64
fork09
inotify09
keyctl01
msgstress01
open04
sendfile09
sendfile09_64
timerfd_settime02
futex_cmp_requeue01
```

Compared with the previous default baseline, `fcntl12` and `sendfile09_64`
moved from slow `rc=0` to timeout. This looks like run-to-run timing variance
around near-timeout tests, not a clean-runtime semantic difference.

## Interpretation

The main conclusion is negative but useful:

The large `rc=2` population in the default native Docker LTP baseline is not
explained by the NaCC-patched `runc` binary. A clean upstream `runc-origin`
runtime path produced the same `rc=2` count (`269`) and nearly the same overall
return-code distribution.

The remaining non-zero population should continue to be classified as a mix of:

- default Docker seccomp/capability/policy denials;
- LTP setup assumptions that do not hold inside an ordinary container;
- missing optional LTP helper binaries or build dependencies;
- kernel feature availability differences;
- timeout or cleanup artifacts;
- possible NaCC kernel/OpenSBI effects, which this experiment does not isolate.

This experiment only isolates the runtime-layer `runc` patch. It does not
provide a fully no-NaCC baseline because the VM still runs the current NaCC
kernel/OpenSBI environment.

## Recommended Next Steps

1. Keep the previous default-Docker baseline and this `dockero` baseline as two
   separate native-container baselines.
2. Do not spend more time on `runc-origin` as the primary explanation for the
   `rc=2` population.
3. Classify the `269` `rc=2` cases by first-line LTP error reason, grouping
   obvious Docker-policy cases such as seccomp, namespace, mount, keyctl,
   perf, and privileged operations.
4. For a fully clean native baseline, build or boot a stock kernel/OpenSBI RISC-V
   VM and rerun the same Docker/LTP runner there.
