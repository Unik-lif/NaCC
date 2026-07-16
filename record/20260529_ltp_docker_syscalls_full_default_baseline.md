# LTP Syscalls in Native RISC-V Docker: Full Default-Seccomp Baseline

Date: 2026-05-29

## Goal

Measure how many upstream LTP `runtest/syscalls` entries pass inside a normal
`ubuntu:22.04` Docker container running in the NaCC RISC-V Ubuntu guest.

This is intended as the native Docker baseline before comparing against NaCC
container modes or seccomp/capability variants.

## Setup

- Guest LTP tree: `/root/ltp`
- LTP checkout previously recorded: `e52eb4b`
- Docker image: `ubuntu:22.04`
- Docker mode: default Docker policy, no `--privileged`, no `--cap-add`, no
  `--security-opt seccomp=unconfined`
- Runner: `scripts/ltp_docker_syscalls_runner.sh`
- Selected suite: `runtest/syscalls`
- Selected entries: `1506`
- Syscall executable symlinks prepared by runner: `1520`
- Per-case timeout: `120s` with `timeout --kill-after=10s`
- Guest run directory: `/root/ltp_docker_runs/syscalls_full_20260529_022852`

The runner uses the already-built guest LTP tree and bind-mounts it into the
container at `/root/ltp`. It does not rebuild LTP inside Docker.

## Result

The full Docker run completed all `1506` `runtest/syscalls` entries and wrote a
complete local summary:

- Local summary: `logs/ltp_docker_syscalls_full_default_01_20260529_102240_summary.tsv`
- Counts: `logs/ltp_docker_syscalls_full_default_01_20260529_102240_counts.txt`
- Command-missing list: `logs/ltp_docker_syscalls_full_default_01_20260529_102240_rc127.tsv`
- Timeout/kill list: `logs/ltp_docker_syscalls_full_default_01_20260529_102240_timeout_kill.tsv`
- Batch VM log: `logs/ltp_docker_syscalls_full_default_01_20260529_102240_vm_20260529_114345.log`
- Batch QEMU log: `logs/ltp_docker_syscalls_full_default_01_20260529_102240_qemu_20260529_114345.log`
- Live pane log with final runner output: `logs/live_vm_pane_313.log`
- Cleanup log: `logs/cleanup_stale_qemu_owner_20260529_114353_ltp_full_default.log`

Return-code summary:

- Total entries attempted: `1506`
- `rc=0`: `898`
- Non-zero: `608`
- `rc=32`: `203`
- `rc=2`: `269`
- `rc=1`: `45`
- `rc=127`: `45`
- `rc=124`: `9`
- `rc=137`: `3`
- Other non-zero return codes: `34`

LTP sub-result fields accumulated from per-test output:

- `passed=5080`
- `failed=358`
- `broken=297`
- `skipped=474`
- `warnings=34`

Important interpretation: `passed=5080` is the sum of LTP sub-assertions, not
the number of `runtest/syscalls` entries. The entry-level pass count for this
baseline is `898/1506` by wrapper return code.

## Caveats

1. The batch status is `auto-exit-137`, but the test summary is complete.
   After the runner emitted all `1506/1506` results and the final summary, the
   Docker client remained stuck in cleanup/wait state. The summary was copied
   from the guest to the host before killing the stuck client and cleaning the
   QEMU owner. Treat the batch exit code as a cleanup artifact, not as a test
   suite failure.

2. `rc=127` is not a Docker/kernel failure. It means the command was not found
   from the current build-tree PATH. There are `45` such entries. Examples
   include `pipeio_*`, `dirtyc0w`, `dirtypipe`, `get_mempolicy*`, `mbind*`,
   `move_pages*`, and `io_*`. These likely split into:
   - helper binaries outside `testcases/kernel/syscalls` that the current
     runner did not symlink; and
   - syscall tests not built because optional dependencies such as NUMA/AIO
     support were missing.

3. Timeout/kill entries were separated from ordinary LTP failures. There are
   `12` entries with `elapsed >= 120s` or timeout/kill return codes:
   `creat05`, `epoll01`, `fcntl14`, `fcntl14_64`, `fork09`, `inotify09`,
   `keyctl01`, `msgstress01`, `open04`, `sendfile09`,
   `timerfd_settime02`, and `futex_cmp_requeue01`.

4. Many non-zero entries are expected in default Docker because LTP intentionally
   tests privileged operations or policy-sensitive features such as `seccomp`,
   `keyctl`, `mount`, `unshare`, `userfaultfd`, `perf_event_open`, `io_uring`,
   time setting, swap, and namespace operations. They should not be interpreted
   as NaCC-specific failures in this native Docker baseline.

## Bottom Line

The first complete native RISC-V Docker baseline for `runtest/syscalls` is:

- `1506` entries attempted.
- `898` entries returned `rc=0` in default Docker.
- `45` entries did not start due command-missing/build-tree runnable gaps.
- `12` entries hit timeout/kill behavior.
- The remaining non-zero entries are mostly Docker policy, missing capability,
  unsupported syscall, LTP broken/fail, or skip/config outcomes.

For a stricter "runnable denominator" that excludes `rc=127`, the current
entry-level pass count is `898/1461`. This is still not a semantic correctness
score, because many of the `1461` runnable entries intentionally require
privileges that default Docker with seccomp/capability filtering does not grant.

## Recommended Next Steps

1. Keep this as the default native Docker baseline artifact.
2. Add a targeted runner mode that symlinks all executable LTP test helpers
   under `testcases/`, not only `testcases/kernel/syscalls`, then rerun only the
   `45` `rc=127` entries to reduce the build-tree runnable gap.
3. Preserve default Docker and policy-relaxed Docker as separate modes:
   - default Docker: baseline for ordinary container behavior;
   - `seccomp=unconfined` / `--cap-add` / privileged: diagnostic mode for
     policy-sensitive LTP classes only.
4. When comparing NaCC against native Docker, classify failures before drawing
   conclusions:
   - command missing / build dependency gap;
   - timeout/hang;
   - Docker policy/capability/seccomp expected denial;
   - real syscall semantic failure;
   - NaCC-specific regression.
