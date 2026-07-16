# LTP Syscalls Directly in the RISC-V Guest: Native Baseline

Date: 2026-05-29

## Goal

Run upstream LTP `runtest/syscalls` directly in the NaCC RISC-V Ubuntu guest,
without Docker, dockerd, runc, Docker seccomp profile, or container namespaces.

This baseline answers a narrower question than a fully stock native baseline:

- It isolates the Docker/container layer from the previous native Docker runs.
- It does not remove the current NaCC kernel/OpenSBI environment.

## Setup

- Guest LTP tree: `/root/ltp`
- LTP checkout previously recorded: `e52eb4b`
- Runner: `scripts/ltp_native_syscalls_runner.sh`
- Selected suite: `runtest/syscalls`
- Selected entries: `1506`
- Syscall executable symlinks prepared by runner: `1520`
- All executable files under `testcases`: `2333`
- Per-case timeout: `120s` with `timeout --kill-after=10s`
- Guest run directory:
  `/root/ltp_native_runs/syscalls_full_20260529_075300`

The runner executes from the LTP build tree directly in the guest root
environment. It does not use Docker and does not rebuild LTP.

## Probe

A native probe was run first after fixing a runner inefficiency in symlink
setup.

Probe artifacts:

- VM log:
  `logs/ltp_native_syscalls_probe_02_20260529_154200_01_20260529_154138_vm_20260529_154651.log`
- QEMU log:
  `logs/ltp_native_syscalls_probe_02_20260529_154200_01_20260529_154138_qemu_20260529_154651.log`

Probe result:

```text
getpid01   rc=0
seccomp01  rc=0
```

This is an important contrast with Docker: `seccomp01` is broken under default
Docker, but passes directly in the guest.

## Full Run Artifacts

- Local summary block:
  `logs/ltp_native_syscalls_full_default_01_20260529_155000_summary.tsv`
- Local counts:
  `logs/ltp_native_syscalls_full_default_01_20260529_155000_counts.txt`
- Name/return-code table:
  `logs/ltp_native_syscalls_full_default_01_20260529_155000_name_rc.tsv`
- Command-missing list:
  `logs/ltp_native_syscalls_full_default_01_20260529_155000_rc127.tsv`
- Timeout/kill list:
  `logs/ltp_native_syscalls_full_default_01_20260529_155000_timeout_kill.tsv`
- Diff against clean Docker/dockero:
  `logs/ltp_native_vs_dockero_rc_diff_20260529_155000.txt`
- Dockero `rc=2` cases that became native `rc=0`:
  `logs/ltp_dockero_rc2_to_native_rc0_20260529_155000.tsv`
- All dockero non-zero cases that became native `rc=0`:
  `logs/ltp_dockero_nonzero_to_native_rc0_20260529_155000.tsv`
- Dockero `rc=0` cases that became native non-zero:
  `logs/ltp_dockero_rc0_to_native_nonzero_20260529_155000.tsv`
- Batch VM log:
  `logs/ltp_native_syscalls_full_default_01_20260529_155000_01_20260529_154801_vm_20260529_173501.log`
- Batch QEMU log:
  `logs/ltp_native_syscalls_full_default_01_20260529_155000_01_20260529_154801_qemu_20260529_173501.log`

Note: the summary block was captured through the VM/tmux log path, so some
trailing tabs near the `warnings/cmd` columns are visually compressed. The
runner's own final `RESULT`, `LTP_FIELDS`, and `RC code` lines are the authority
for aggregate counts. The `name_rc.tsv` artifact is used for return-code diffing.

## Result

The native guest run completed all `1506` entries.

Return-code summary:

- Total entries attempted: `1506`
- `rc=0`: `1181`
- Non-zero: `325`
- `rc=32`: `272`
- `rc=2`: `9`
- `rc=127`: `13`
- `rc=124`: `10`
- `rc=137`: `3`
- Other non-zero return codes: `18`

LTP sub-result fields accumulated from per-test output:

- `passed=7768`
- `failed=45`
- `broken=16`
- `skipped=602`
- `warnings=11`

As in the Docker records, `passed=7768` is the sum of LTP sub-assertions, not
the number of `runtest/syscalls` entries. The entry-level pass count is
`1181/1506` by wrapper return code.

## Comparison With clean Docker / dockero

Clean Docker/dockero baseline:

- Record:
  `record/20260529_ltp_dockero_syscalls_full_origin_runc_baseline.md`
- Entry-level result: `896/1506` with `rc=0`
- `rc=2`: `269`
- `rc=127`: `45`

Native guest baseline:

- Entry-level result: `1181/1506` with `rc=0`
- `rc=2`: `9`
- `rc=127`: `13`

The native guest run therefore adds `+285` entry-level `rc=0` passes compared
with clean Docker/dockero.

Return-code diff summary:

- Same return code: `1108`
- Different return code: `398`
- Dockero non-zero -> native `rc=0`: `293`
- Dockero `rc=0` -> native non-zero: `8`
- Dockero `rc=2` -> native `rc=0`: `198`
- Dockero `rc=2` -> native non-`rc=2`: `267`
- Native new `rc=2` compared with dockero: `7`

Only two `rc=2` cases overlap between clean Docker/dockero and native:

```text
semop02
perf_event_open02
```

Native `rc=2` cases:

```text
msgctl04
nftw01
nftw6401
semctl02
semop02
shmctl02
shmget04
symlink03
perf_event_open02
```

The `rc=127` population also drops from `45` in Docker to `13` native:

```text
ioctl02
pipeio_1
pipeio_2
pipeio_3
pipeio_4
pipeio_5
pipeio_6
pipeio_7
pipeio_8
prot_hsymlinks
dirtyc0w
dirtyc0w_shmem
dirtypipe
```

These remaining `rc=127` entries are still likely build-tree runnable/PATH
gaps. The runner currently links only executables under
`testcases/kernel/syscalls` by default. A targeted rerun with
`LTP_LINK_SCOPE=all` may reduce this list.

## Timeout / Kill Entries

Native timeout/kill entries:

```text
bind06
epoll01
fallocate06
fcntl14
fcntl14_64
fork13
inotify09
msgstress01
rename11
renameat01
setsockopt06
timerfd_settime02
futex_cmp_requeue01
```

Some slow/timeout behavior is still present without Docker, but several Docker
timeouts become native passes. For example, `fork09`, `keyctl01`, and
`sendfile09` passed natively during this run.

## Interpretation

This baseline strongly supports the idea that Docker/container policy and
container environment assumptions account for a large part of the previous
Docker non-zero population.

The most important signal is the `rc=2` collapse:

- clean Docker/dockero: `269`
- direct native guest: `9`

So the earlier Docker `rc=2` population is mostly not a RISC-V syscall
implementation failure and not a NaCC-patched `runc` issue. It is largely caused
by running LTP inside a default Docker container, where tests that expect host
root privileges, host namespaces, keyring behavior, seccomp manipulation,
mount/module/time/swap/perf operations, or full helper availability often do not
match the environment.

At the same time, this is still not a fully stock RISC-V baseline. The guest
uses the current NaCC kernel/OpenSBI environment. A fully clean baseline still
requires a stock kernel/OpenSBI RISC-V VM with the same LTP tree and runner.

## Recommended Next Steps

1. Treat `1181/1506` as the current direct-guest native baseline for this NaCC
   RISC-V VM.
2. Treat `896/1506` as the current default-container baseline with clean
   `runc-origin`.
3. Use the large gap (`+285` native passes and `rc=2` dropping from `269` to
   `9`) as evidence that Docker policy/environment explains much of the earlier
   result.
4. Rerun only the native `rc=127` entries with `LTP_LINK_SCOPE=all` to check
   whether helper linking eliminates the remaining command-missing cases.
5. For a no-NaCC claim, repeat the same native runner in a stock RISC-V
   kernel/OpenSBI VM.
