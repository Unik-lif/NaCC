# lmbench Full Attempt and Direct Subset Under True NaCC

Date: 2026-06-01

## Question

The earlier lmbench smoke only ran one binary:

```sh
/usr/lib/lmbench/bin/lat_syscall null
```

Therefore its output being only one line:

```text
Simple syscall: ...
```

was expected. lmbench has many more binaries and a Debian wrapper,
`lmbench-run`, for the full suite. This record captures the attempt to run that
full wrapper and a follow-up direct-binary subset.

## Full `lmbench-run` Attempt

Batch:

- tag: `lmbench_nacc_full_01_20260601_110557`
- command file:
  `logs/test_runner/lmbench_nacc_full_01_20260601_110557_auto_cmd.txt`
- manual QEMU capture:
  `logs/lmbench_nacc_full_01_20260601_110557_qemu_manual_20260601_111834.log`
- manual VM capture:
  `logs/lmbench_nacc_full_01_20260601_110557_vm_manual_20260601_111834.log`
- cleanup log:
  `logs/cleanup_stale_qemu_owner_20260601_111843.log`

The run first built a local RISC-V Docker image:

```text
nacc-lmbench:jammy
```

Guest run directory:

```text
/root/lmbench_nacc_runs/full_20260601_030939
```

The full wrapper was configured non-interactively with a small memory setting
and no remote/disk publishing path:

- multiple copies: default `1`
- scheduler placement: default
- memory size: `16 MB`
- subset: default `ALL`
- `FASTMEM=yes`
- `SLOWFS=yes`
- no disk benchmark target
- no remote benchmark target
- no result mail

The true-NaCC container command used:

```sh
docker run --runtime runc --security-opt seccomp=unconfined \
  --hostname lmbench-nacc \
  -v "$run_dir/varlib:/var/lib/lmbench:rw" \
  -v "$answers:/answers.txt:ro" \
  nacc-lmbench:jammy \
  /bin/sh -lc 'cat /answers.txt | lmbench-run ...'
```

### Full Attempt Result

The full wrapper did not complete and did not leave lmbench result output.

A follow-up inspection run confirmed:

- inspect batch:
  `lmbench_nacc_full_inspect_01_20260601_112545`
- VM log:
  `logs/lmbench_nacc_full_inspect_01_20260601_112545_vm_20260601_112921.log`
- QEMU log:
  `logs/lmbench_nacc_full_inspect_01_20260601_112545_qemu_20260601_112921.log`
- `docker-run.log`: `0 bytes`
- no files under `/root/lmbench_nacc_runs/full_20260601_030939/varlib/results`
- no stale `lmbench` container remained
- `nacc-lmbench:jammy` remained available in Docker

The QEMU log shows a kernel panic after true NaCC entry, during signal/core-dump
handling for a shell process:

```text
handle_signal pid=1856 comm=sh cid=14e3b2da1f74 sig=17
setup_rt_frame ... frame=0000003fec84fcb0
[NACC][private-copy-to-user-denied] ... ret=-14
...
[QEMU] deny PRIVATE_DATA load pa=13d3d1000
[NACC][strict-sumoff-first-deny] access=load reason=sum_off_kernel_high_private_data
Oops - load access fault
epc : __memcpy+0x3c/0xf8
ra  : copy_page_from_iter_atomic+0x446/0x8b2
Kernel panic - not syncing: Fatal exception in interrupt
```

Visible stack:

```text
__memcpy
copy_page_from_iter_atomic
generic_perform_write
ext4_buffered_write_iter
ext4_file_write_iter
vfs_iter_write
backing_file_write_iter
ovl_write_iter
__kernel_write_iter
dump_user_range
elf_core_dump
do_coredump
get_signal
arch_do_signal_or_restart
irqentry_exit_to_user_mode
do_page_fault
```

Interpretation: full `lmbench-run` currently hits a NaCC signal/core-dump path
before useful benchmark output is preserved. This is a different blocker from
the earlier LTP `move_page_tables()` panic, but it is in the same broad category:
full script suites quickly touch compatibility paths outside simple benchmark
binaries.

## Direct-Binary Subset

To get more benchmark signal without the full wrapper, a direct subset ran each
lmbench binary as the container command.

Important terminology: this was not a native-Docker baseline. It compared:

- `Native`: the lmbench binary run directly in the RISC-V VM Ubuntu rootfs,
  with no Docker and no NaCC container initialization.
- `NaCC`: the same lmbench binary run as the `docker run` command under true
  NaCC, using `--runtime runc --security-opt seccomp=unconfined`.

Therefore the table below should be read as guest-native versus true-NaCC
direct binary results. A separate native-Docker baseline was added later in the
phase triage section.

Batch:

- tag: `lmbench_nacc_direct_subset_01_20260601_113037`
- VM log:
  `logs/lmbench_nacc_direct_subset_01_20260601_113037_vm_20260601_113822.log`
- QEMU log:
  `logs/lmbench_nacc_direct_subset_01_20260601_113037_qemu_20260601_113822.log`
- guest run directory:
  `/root/lmbench_nacc_runs/direct_subset_20260601_033407`

Common environment:

```text
ENOUGH=1000
TIMING_O=0
LOOP_O=0
```

The true-NaCC side used:

```sh
docker run --rm --runtime runc --security-opt seccomp=unconfined \
  --ulimit core=0 \
  -e LANG=C -e LC_ALL=C \
  -e ENOUGH=1000 -e TIMING_O=0 -e LOOP_O=0 \
  nacc-lmbench:jammy <lmbench-binary> <args>
```

The batch completed with `status=ok`; no `Kernel panic`, `Oops`, or
`reject Linux-origin` signature was found in the direct-subset QEMU log.

### Direct Subset Results

| Case | Native rc | Native output | NaCC rc | NaCC output |
| --- | ---: | --- | ---: | --- |
| `lat_syscall null` | 0 | `Simple syscall: 4.8152 microseconds` | 0 | `Simple syscall: 15384.0000 microseconds` |
| `lat_syscall read` | 0 | `Simple read: 8.5530 microseconds` | 0 | `Simple read: 16947.0000 microseconds` |
| `lat_syscall write` | 0 | `Simple write: 6.3706 microseconds` | 0 | `Simple write: 15414.0000 microseconds` |
| `lat_pipe` | 0 | `Pipe latency: 1266.7314 microseconds` | 0 | empty |
| `bw_pipe` | 0 | `Pipe bandwidth: 25.37 MB/sec` | 0 | empty |
| `bw_mem 1m rd` | 0 | `1.05 13881.35` | 139 | empty |
| `bw_mem 1m wr` | 0 | `1.05 3690.17` | 139 | empty |
| `lat_proc fork` | 0 | `Process fork+exit: 22055.0000 microseconds` | 0 | empty |

The first three syscall latency tests are currently the cleanest usable
lmbench measurements under true NaCC. The pipe/fork cases need follow-up
because they return `rc=0` but do not emit benchmark text. The memory bandwidth
cases need follow-up because they exit with `rc=139` under true NaCC.

QEMU evidence shows that the direct-subset containers did enter true NaCC:

```text
[Linux] register a new NACC process.
[SBI]: cid: ...
```

The QEMU log also shows fork-child attach activity for child-producing
benchmarks, e.g.:

```text
sm_nacc_attach_forked_child for pid: ..., cid: ...
```

For one `bw_mem` case, the log shows a signal-frame copy denial rather than a
kernel panic:

```text
handle_signal pid=2409 comm=bw_mem cid=ffd9800df846 sig=17
setup_rt_frame ...
[NACC][private-copy-to-user-denied] ... err=-4
handle_signal setup_done ... ret=-14
```

This is likely related to the empty output / `rc=139` behavior, but it has not
yet been reduced to a minimal standalone reproducer.

## Current Takeaway

Full `lmbench-run` is not yet a stable NaCC benchmark workload. It crashes the
kernel through a signal/core-dump path before useful result files are written.

Direct lmbench binaries are a better near-term route. They let us collect some
measurements and classify failures one case at a time:

- usable now: direct `lat_syscall null/read/write`
- runnable but suspicious: `lat_pipe`, `bw_pipe`, `lat_proc fork`
- failing in user/container space: `bw_mem 1m rd/wr` with `rc=139`
- not useful yet: full `lmbench-run`

## Next Steps

1. Build a small direct-binary lmbench runner instead of using full
   `lmbench-run`.
2. Keep full `lmbench-run` as a later compatibility target.
3. Investigate why child-producing benchmarks can return `rc=0` with empty
   output under NaCC.
4. Reduce `bw_mem 1m rd/wr` `rc=139` to a minimal case.
5. Keep `--ulimit core=0` on exploratory NaCC benchmark containers to avoid
   core-dump paths masking the primary failure.

## Phase Triage: `lmbench-run` Startup

Follow-up batch:

- tag: `lmbench_nacc_phase_triage_01_20260601_122225`
- VM log:
  `logs/lmbench_nacc_phase_triage_01_20260601_122225_vm_20260601_123815.log`
- QEMU log:
  `logs/lmbench_nacc_phase_triage_01_20260601_122225_qemu_20260601_123815.log`
- guest run directory:
  `/root/lmbench_nacc_runs/phase_triage_20260601_042559`

This run separated the full wrapper startup path into smaller pieces and added
a real native-Docker baseline. The three modes were:

- `guest`: direct RISC-V VM execution, no Docker.
- `docker_default`: Docker with `--runtime runc`, default seccomp, no true NaCC
  initialization.
- `docker_nacc`: Docker with `--runtime runc --security-opt
  seccomp=unconfined`, true NaCC initialization.

The earlier `config-run-only` probe also left this preserved trace:

```text
/bin/sh -x ./config-run
 BINDIR=..
 SCRIPTSDIR=../scripts
 ../scripts/os
Segmentation fault
 OS=
 ...
 ../bin//enough
 ENOUGH=1000000
 ...
 ../bin//timing_o
 TIMING_O=0
 ...
 ../bin//loop_o
 LOOP_O=0.00000000
 ...
 grep MemTotal: /proc/meminfo
 awk {print $2}
```

So the first abnormal point in full `lmbench-run` is before any benchmark
result phase: it starts in `config-run`, specifically around `../scripts/os`
and the early calibration helpers.

### Phase Triage Results

| Case | Guest rc/output | Native Docker rc/output | True NaCC rc/output |
| --- | --- | --- | --- |
| `scripts/os` | rc0, `gnu-os` cannot identify `riscv64` | rc0, same `riscv64` identification failure | rc124, `Segmentation fault` twice |
| `msleep 250` | rc0, `msleep_done` | rc0, `msleep_done` | rc0, `msleep_done` |
| `enough` | rc0, `1000000` | rc0, `5000` | rc124, printed `1000000` then Docker/container teardown timed out |
| `timing_o` | rc0, `0` | rc0, `0` | rc139, empty output |
| `loop_o` | rc0, `0.00000891` | rc0, `0.00000000` | rc139, empty output |
| `lat_syscall null` | rc0, `Simple syscall: 4.9023 microseconds` | rc0, `Simple syscall: 6.3162 microseconds` | rc124, printed `Simple syscall: 15119.3699 microseconds` then teardown timed out |
| `bw_mem 1m rd` | rc0, `1.05 15196.96` | rc0, `1.05 14627.97` | rc139, empty output |

The default-Docker lines include the benign Docker warning
`Failed to write to log, write logpipe: file already closed`, but the cases
still returned `rc=0` and printed results.

QEMU did not show `Kernel panic`, `Oops`, or `Fatal exception` in this phase
triage run. It did show signal-frame trouble in the true-NaCC path:

```text
setup_rt_frame pid=4246 comm=sh cid=60ea076fcf29 sig=17 ...
[NACC][private-copy-to-user-denied] ... err=-4
handle_signal setup_done ... ret=-14
```

### Updated Interpretation

Native Docker itself is not the blocker for this lmbench subset: the same
`scripts/os`, calibration helpers, `lat_syscall null`, and `bw_mem 1m rd` all
complete under default Docker. The problematic behavior appears only in the
true-NaCC container path.

Full `lmbench-run` should not be treated as a benchmark failure yet. It first
exposes NaCC compatibility issues in:

- shell/script child execution around `config-run`;
- signal frame delivery/return for shell children (`SIGCHLD`);
- Docker/container teardown after some NaCC commands already printed output;
- user-space crashes for `timing_o`, `loop_o`, and `bw_mem`.

Near-term benchmark work should use direct binaries with explicit per-case
timeouts and a native-Docker comparison row. Full `lmbench-run` is better kept
as a compatibility stress target until the signal-frame and teardown behavior
is improved.

## OS Script Reduction

Follow-up batch:

- tag: `lmbench_nacc_os_reduce_01_20260601_124330`
- VM log:
  `logs/lmbench_nacc_os_reduce_01_20260601_124330_vm_20260601_125608.log`
- QEMU log:
  `logs/lmbench_nacc_os_reduce_01_20260601_124330_qemu_20260601_125608.log`
- guest run directory:
  `/root/lmbench_nacc_runs/os_reduce_20260601_044723`

This reduction focused on why `config-run` first becomes abnormal around
`../scripts/os`. The lmbench package uses an old `gnu-os` script
(`timestamp='2004-08-18'`). On RISC-V Linux, normal behavior is not a clean
platform match: `gnu-os` eventually prints its "unable to guess system type"
diagnostic. That fallback happens in direct guest execution and in default
Docker, so the `riscv64` identification failure is not itself a NaCC bug.

### Reduction Results

| Case | Default Docker | True NaCC |
| --- | --- | --- |
| `simple_tools` (`uname`, `arch`, `sed`, `awk`) | rc2 due a quoting bug in the probe's `awk` line, after earlier commands printed successfully | rc124, empty output |
| `gnu-os --time-stamp` | rc0, `2004-08-18` | rc124, printed `Segmentation fault` and `2004-08-18` |
| compiler probe (`mktemp`, temp C file, `cc/gcc/c89/c99`) | rc0, all tested compiler commands returned rc0 | rc124, reached `TRY:cc`, then timed out before printing the compiler child status |
| `CC_FOR_BUILD=false ./gnu-os` | rc1, normal fallback diagnostic | rc124, `Segmentation fault` twice |
| `CC_FOR_BUILD=no_compiler_found ./gnu-os` | rc1, normal fallback diagnostic | rc124, `Segmentation fault` twice |
| hand-built final diagnostic | rc0, normal diagnostic output | rc124, printed the full diagnostic, then timed out during container teardown |

QEMU did not show `Kernel panic`, `Oops`, or `Fatal exception` in this
reduction run. It did show signal-frame failures in the true-NaCC path,
including a failed `SIGCHLD` frame for `gnu-os`:

```text
setup_rt_frame pid=3450 comm=gnu-os cid=1d8b1636dc85 sig=17 ...
[NACC][private-copy-to-user-denied] pid=3450 comm=gnu-os cid=1d8b1636dc85 ... err=-4
handle_signal setup_done ... ret=-14
```

### Updated Interpretation

The first useful reproducer is now smaller than full `lmbench-run`. The
problem can be observed with generic shell/script child behavior around
`scripts/os` and `gnu-os`, especially child exit and `SIGCHLD` handling.

Some commands print their expected output before Docker returns rc124, which
points to child/signal/container-teardown compatibility rather than simply the
command body failing immediately. The compiler probe stopping at `TRY:cc`
further suggests the next focused test should reduce shell child creation and
child status collection under true NaCC.

For the next debugging iteration, prefer minimal true-NaCC commands such as:

```sh
/bin/sh -lc 'cd /usr/lib/lmbench/scripts && ./gnu-os --time-stamp'
/bin/sh -lc 'cd /usr/lib/lmbench/scripts && CC_FOR_BUILD=false ./gnu-os'
/bin/sh -lc 'tmp=$(mktemp -d /tmp/cgXXXXXX); echo "int x;" > $tmp/dummy.c; cc -c -o $tmp/dummy.o $tmp/dummy.c; echo rc=$?'
```

This is likely a better next target than running the whole lmbench wrapper.

## Child Wait / SIGCHLD Reduction

Follow-up batch:

- tag: `lmbench_nacc_child_wait_reduce_01_20260601_130134`
- VM log:
  `logs/lmbench_nacc_child_wait_reduce_01_20260601_130134_01_20260601_130134_vm_20260601_131446.log`
- QEMU log:
  `logs/lmbench_nacc_child_wait_reduce_01_20260601_130134_01_20260601_130134_qemu_20260601_131446.log`
- guest run directory:
  `/root/lmbench_nacc_runs/child_wait_reduce_20260601_050508`

This run reduced the `scripts/os`/`gnu-os` failure into generic process,
shell, child-wait, and container-teardown cases. The image was still
`nacc-lmbench:jammy`; each case was compared under default Docker and true
NaCC Docker.

### Child-Wait Results

| Case | Default Docker | True NaCC |
| --- | --- | --- |
| direct `/bin/true` | rc124, no semantic output; likely a Docker/no-output teardown artifact in this probe | rc0, empty output |
| direct `/bin/echo exec_echo_done` | rc0, printed `exec_echo_done` | rc124, printed `exec_echo_done` |
| shell builtin only | rc0, printed both builtin markers | rc124, printed both builtin markers |
| shell runs `/bin/true; echo done` | rc0, `true_rc=0`, `done` | rc124, empty output |
| shell runs `/bin/uname -m; echo done` | rc0, `riscv64`, `done` | rc124, empty output |
| shell with `trap ... CHLD; /bin/true` | rc0, `TRAP_CHLD`, `true_rc=0`, `done` | rc124, empty output |
| shell background `/bin/true & wait` | rc0, `wait_rc=0`, `done` | rc124, empty output |
| shell background `/bin/true & wait` with `CHLD` trap | rc0, `TRAP_CHLD`, `wait_rc=0`, `done` | rc124, empty output |
| nested `/bin/sh -c ...` | rc0, nested output and `sh_rc=0` | rc124, empty output |
| one `cc -c` child | rc0, `cc_rc=0`, `done` | rc139, empty output |
| shell runs `./gnu-os --time-stamp` | rc0, `2004-08-18`, `gnu_rc=0`, `done` | rc139, empty output |
| direct `gnu-os --time-stamp` | rc0, `2004-08-18` | rc124, `Segmentation fault` and `2004-08-18` |

The direct `/bin/true` default-Docker rc124 should be treated as probe noise
until reproduced separately: it had no semantic output, while the default
Docker shell-child cases all completed normally. The more important contrast is
that true NaCC can run an empty direct `/bin/true`, but output-producing direct
commands and even builtin-only shell commands often print their expected output
and still time out in Docker teardown.

### QEMU Signal Evidence

The QEMU log did not contain `Kernel panic`, `Oops`, `Fatal exception`, or
`BUG:` markers.

It did contain:

- 11 `SIGCHLD` `setup_rt_frame` attempts;
- 9 `handle_signal ... ret=-14` results;
- 9 matching `[NACC][private-copy-to-user-denied]` records;
- 2 `handle_signal ... ret=0` results.

Representative shell failure:

```text
handle_signal pid=3991 comm=sh cid=6b742f85a4a4 sig=17 ...
setup_rt_frame pid=3991 comm=sh cid=6b742f85a4a4 sig=17 ... frame=0000003fcffe9ff0
[NACC][private-copy-to-user-denied] pid=3991 comm=sh cid=6b742f85a4a4 user_va=3fcffe9ff0 ... bytes=48 copied=0 err=-4
handle_signal setup_done pid=3991 comm=sh cid=6b742f85a4a4 sig=17 ret=-14 ...
```

Representative `gnu-os` failure:

```text
handle_signal pid=6034 comm=gnu-os cid=603935b5d2d3 sig=17 ...
setup_rt_frame pid=6034 comm=gnu-os cid=603935b5d2d3 sig=17 ... frame=0000003fd678ffc0
[NACC][private-copy-to-user-denied] pid=6034 comm=gnu-os cid=603935b5d2d3 user_va=3fd678ffc0 ... bytes=48 copied=0 err=-4
handle_signal setup_done pid=6034 comm=gnu-os cid=603935b5d2d3 sig=17 ret=-14 ...
```

### Updated Interpretation

The full lmbench wrapper is now clearly too large as the next debugging target.
The reduced failure is no longer lmbench-specific:

- true NaCC has a generic `SIGCHLD` signal-frame delivery problem for private
  user stacks;
- output-producing containers can finish their command body and still time out
  during Docker/container teardown;
- shell external-command cases tend to produce empty logs with rc124, consistent
  with child completion / signal delivery getting stuck before the shell can
  print post-child status;
- `cc_one` and `gnu_ts_shell` turn into rc139, so compiler/config-script
  workloads still add a crash path on top of the signal-frame/teardown issue.

The next useful experiment is an image-level matrix, not another lmbench run:
compare `busybox`, `ubuntu:22.04`, and `nacc-lmbench:jammy` for direct
`/bin/echo`, direct `/bin/true`, shell-builtin `echo`, and shell-child
`/bin/true; echo done` under default Docker and true NaCC. This should tell us
whether the teardown problem is specific to the Ubuntu/Jammy userspace image or
is a general true-NaCC Docker lifecycle issue.

## Docker Image Matrix

Follow-up batch:

- tag: `nacc_docker_image_matrix_01_20260601_131651`
- VM log:
  `logs/nacc_docker_image_matrix_01_20260601_131651_01_20260601_131651_vm_20260601_132946.log`
- QEMU log:
  `logs/nacc_docker_image_matrix_01_20260601_131651_01_20260601_131651_qemu_20260601_132946.log`
- guest run directory:
  `/root/lmbench_nacc_runs/image_matrix_20260601_052021`

This run checked whether the timeout/teardown behavior was specific to the
lmbench Jammy image. It used four minimal commands on `busybox`,
`ubuntu:22.04`, and `nacc-lmbench:jammy` under both default Docker and true
NaCC Docker:

- direct `/bin/true`
- direct `/bin/echo image_echo_done`
- `/bin/sh -lc 'echo builtin_done'`
- `/bin/sh -lc '/bin/true; echo true_rc=$?; echo done'`

### Image Matrix Results

| Image | Mode | `/bin/true` | `/bin/echo` | shell builtin | shell external `/bin/true` |
| --- | --- | --- | --- | --- | --- |
| `busybox` | default Docker | rc0 | rc0, output | rc0, output | rc0, output |
| `ubuntu:22.04` | default Docker | rc0 | rc0, output | rc0, output | rc0, output |
| `nacc-lmbench:jammy` | default Docker | rc0 | rc0, output | rc0, output | rc0, output |
| `busybox` | true NaCC | rc0 | rc124, output already printed | rc124, output already printed | rc124, empty output |
| `ubuntu:22.04` | true NaCC | rc0 | rc124, output already printed | rc124, output already printed | rc124, printed `true_rc=0` and `done` |
| `nacc-lmbench:jammy` | true NaCC | rc0 | rc124, output already printed | rc124, output already printed | rc124, empty output |

The earlier default-Docker `nacc-lmbench /bin/true` rc124 did not reproduce in
this matrix; treat that earlier value as probe noise.

### Matrix Signal Evidence

The matrix QEMU log did not contain `Kernel panic`, `Oops`, `Fatal exception`,
or `BUG:` markers.

It contained:

- 12 `SIGCHLD` `setup_rt_frame` attempts;
- 10 successful `handle_signal ... ret=0` results;
- 2 failed `handle_signal ... ret=-14` results;
- 2 matching `[NACC][private-copy-to-user-denied]` records.

So the image matrix confirms two separate but related facts:

- the output/timeout behavior is not lmbench-image-specific; it reproduces on
  `busybox`, `ubuntu:22.04`, and `nacc-lmbench:jammy`;
- `SIGCHLD` frame denial still appears, but not every rc124 corresponds to a
  failed signal frame in the QEMU log.

### Updated Interpretation

The core problem now looks like a true-NaCC Docker lifecycle/teardown issue
with a signal-frame failure component:

- no-output direct `/bin/true` exits cleanly under true NaCC across all three
  images;
- output-producing direct commands and shell builtin-only commands can complete
  their command body, print output, and still leave the host-side `docker run`
  stuck until the outer timeout kills it;
- shell-child cases vary by image: Ubuntu printed the child status and then
  timed out, while BusyBox and the lmbench Jammy image produced empty logs;
- the `SIGCHLD` private-stack signal-frame bug remains real, but the rc124
  timeout is broader than only `setup_rt_frame ret=-14`.

The next reduction should remove `--rm` and inspect container state after the
foreground `docker run` times out. That will distinguish:

- command process still alive inside the container;
- command process exited, but Docker attach/wait is stuck;
- command process exited, but Docker removal/cleanup is stuck.

## Non-`--rm` Docker State Probe

Follow-up batch:

- tag: `nacc_docker_no_rm_state_01_20260601_133206`
- VM log:
  `logs/nacc_docker_no_rm_state_01_20260601_133206_01_20260601_133206_vm_20260601_134115.log`
- QEMU log:
  `logs/nacc_docker_no_rm_state_01_20260601_133206_01_20260601_133206_qemu_20260601_134115.log`
- guest run directory:
  `/root/lmbench_nacc_runs/no_rm_state_20260601_053533`

This run removed `--rm` and gave each container a fixed name. After the
foreground `docker run` returned or timed out, it ran:

- `docker ps -a`
- `docker inspect`
- `docker logs`
- `docker wait`
- `docker rm -f`

The goal was to decide whether rc124 meant the container process was still
alive, Docker removal was stuck, or the foreground `docker run`/attach path was
stuck after the container had already exited.

### Non-`--rm` Results

| Mode | Image | Case | foreground `docker run` | `docker inspect` | follow-up Docker commands |
| --- | --- | --- | --- | --- | --- |
| default Docker | `busybox` | `exec_echo` | rc124, output printed | `exited`, `exit=0` | `logs=0`, `wait=0`, `rm=0` |
| default Docker | `busybox` | `sh_builtin` | rc0, output printed | `exited`, `exit=0` | `logs=0`, `wait=0`, `rm=0` |
| default Docker | `busybox` | `sh_external_true` | rc0, output printed | `exited`, `exit=0` | `logs=0`, `wait=0`, `rm=0` |
| default Docker | `ubuntu:22.04` | `exec_echo` | rc0, output printed | `exited`, `exit=0` | `logs=0`, `wait=0`, `rm=0` |
| default Docker | `ubuntu:22.04` | `sh_builtin` | rc0, output printed | `exited`, `exit=0` | `logs=0`, `wait=0`, `rm=0` |
| default Docker | `ubuntu:22.04` | `sh_external_true` | rc0, output printed | `exited`, `exit=0` | `logs=0`, `wait=0`, `rm=0` |
| true NaCC | `busybox` | `exec_echo` | rc124, output printed | `exited`, `exit=0` | `logs=0`, `wait=0`, `rm=0` |
| true NaCC | `busybox` | `sh_builtin` | rc124, output printed | `exited`, `exit=0` | `logs=0`, `wait=0`, `rm=0` |
| true NaCC | `busybox` | `sh_external_true` | rc124, output printed | `exited`, `exit=0` | `logs=0`, `wait=0`, `rm=0` |
| true NaCC | `ubuntu:22.04` | `exec_echo` | rc124, output printed | `exited`, `exit=0` | `logs=0`, `wait=0`, `rm=0` |
| true NaCC | `ubuntu:22.04` | `sh_builtin` | rc124, output printed | `exited`, `exit=0` | `logs=0`, `wait=0`, `rm=0` |
| true NaCC | `ubuntu:22.04` | `sh_external_true` | rc124, empty foreground output | `exited`, `exit=139` | `logs=0`, `wait=0`, `rm=0` |

The default-Docker `busybox exec_echo` rc124 shows that this exact non-`--rm`
probe can also hit a foreground Docker-client hang even without true NaCC.
However, true NaCC makes the behavior systematic for output-producing and
shell cases.

### State-Probe Signal Evidence

The QEMU log did not contain `Kernel panic`, `Oops`, `Fatal exception`, or
`BUG:` markers.

It contained:

- 6 `SIGCHLD` `setup_rt_frame` attempts;
- 5 successful `handle_signal ... ret=0` results;
- 1 failed `handle_signal ... ret=-14` result;
- 1 matching `[NACC][private-copy-to-user-denied]` record.

### Updated Interpretation

This state probe narrows the rc124 meaning:

- most true-NaCC rc124 cases are not because the container command is still
  alive;
- they are not because `docker rm -f` cannot remove the container;
- they are not because `docker logs` or `docker wait` cannot observe the exited
  container afterward;
- the foreground `docker run`/attach path can remain stuck after the container
  has already reached `State.Status=exited` and `ExitCode=0`.

The current most likely split is:

- lifecycle/attach problem: foreground `docker run` does not return after
  command completion, especially under true NaCC;
- signal-frame problem: `SIGCHLD` setup can still fail on private user stacks,
  but this is not required for every foreground timeout;
- crash problem: some shell-child cases, such as true-NaCC
  `ubuntu:22.04 /bin/sh -lc '/bin/true; echo ...'`, can still make the
  container process exit with `139`.

For the next small step, prefer diagnosing the Docker/runc/attach boundary for
one minimal case:

```sh
docker run --name nacc_attach_probe --runtime runc \
  --security-opt seccomp=unconfined --ulimit core=0 \
  busybox /bin/echo image_echo_done
```

Run it without `--rm`, observe the foreground hang, and in parallel inspect
`containerd-shim-runc-v2`, `runc`, and Docker daemon state. The container state
will likely already be `exited=0`, so the question becomes why the foreground
client does not receive/finish the attach/wait completion.

## Attach Probe and Timeout Calibration

Follow-up attach probe:

- tag: `nacc_attach_probe_01_20260601_134343`
- VM log:
  `logs/nacc_attach_probe_01_20260601_134343_01_20260601_134343_vm_20260601_134815.log`
- QEMU log:
  `logs/nacc_attach_probe_01_20260601_134343_01_20260601_134343_qemu_20260601_134815.log`
- guest run directory:
  `/root/lmbench_nacc_runs/attach_probe_20260601_054716`

This probe ran one true-NaCC foreground command in the background:

```sh
docker run --name nacc_attach_probe_<ts> --runtime runc \
  --security-opt seccomp=unconfined --ulimit core=0 \
  busybox /bin/echo image_echo_done
```

It did not reproduce a permanent foreground hang. At the first snapshot, the
client was alive and the container was already running. By the second snapshot,
the client had returned with rc0:

```text
t04: client_alive=yes, container running=true, run_log contains image_echo_done
t12: client_alive=no, client_rc_file=0, container exited exit=0
t22: client_alive=no, client_rc_file=0, container exited exit=0
```

The QEMU log for this attach probe had no panic/Oops markers and no
`private-copy-to-user-denied` / signal-frame failures.

This changed the interpretation of the earlier 15-20 second rc124 results:
some of them were probably timeout-window artifacts, not permanent hangs.

### Long Timeout Matrix

Follow-up batch:

- tag: `nacc_long_timeout_matrix_01_20260601_134911`
- VM log:
  `logs/nacc_long_timeout_matrix_01_20260601_134911_01_20260601_134911_vm_20260601_135728.log`
- QEMU log:
  `logs/nacc_long_timeout_matrix_01_20260601_134911_01_20260601_134911_qemu_20260601_135728.log`
- guest run directory:
  `/root/lmbench_nacc_runs/long_timeout_matrix_20260601_055249`

This reran the minimal image matrix with a 90 second per-case timeout.

| Mode | Image | Case | rc | Duration |
| --- | --- | --- | --- | --- |
| default Docker | `busybox` | `exec_echo` | 0 | 19s |
| default Docker | `busybox` | `sh_builtin` | 0 | 16s |
| default Docker | `busybox` | `sh_external_true` | 0 | 15s |
| default Docker | `ubuntu:22.04` | `exec_echo` | 0 | 15s |
| default Docker | `ubuntu:22.04` | `sh_builtin` | 0 | 15s |
| default Docker | `ubuntu:22.04` | `sh_external_true` | 0 | 15s |
| true NaCC | `busybox` | `exec_echo` | 0 | 20s |
| true NaCC | `busybox` | `sh_builtin` | 0 | 20s |
| true NaCC | `busybox` | `sh_external_true` | 0 | 28s |
| true NaCC | `ubuntu:22.04` | `exec_echo` | 0 | 21s |
| true NaCC | `ubuntu:22.04` | `sh_builtin` | 0 | 35s |
| true NaCC | `ubuntu:22.04` | `sh_external_true` | 139 | 26s |

The long-timeout QEMU log did not contain `Kernel panic`, `Oops`,
`Fatal exception`, or `BUG:` markers. It contained one
`private-copy-to-user-denied` / `SIGCHLD setup_rt_frame ret=-14` pair.

### Corrected Interpretation

The previous "foreground Docker attach is stuck" interpretation was too strong.
The corrected view is:

- many minimal true-NaCC Docker commands complete successfully if the timeout is
  at least about 60-90 seconds;
- the current 15-20 second per-case timeout is too short for true-NaCC Docker
  lifecycle measurements and can misclassify slow success as rc124;
- default Docker on this RISC-V VM is also slow enough that 15 seconds can be
  marginal for small foreground `docker run` commands;
- true NaCC still adds noticeable overhead: the minimal BusyBox shell-child case
  took 28s, and Ubuntu shell builtin took 35s;
- real failures remain:
  - true-NaCC `ubuntu:22.04 /bin/sh -lc '/bin/true; echo ...'` returned rc139;
  - full lmbench/config-script paths still hit `SIGCHLD` frame failures and
    `rc139` cases;
  - `SIGCHLD` signal frame delivery to private stacks is still a confirmed bug,
    but it is not the explanation for every short-timeout rc124.

For future benchmark probes, use per-case timeouts of at least 90 seconds for
minimal Docker cases and longer for lmbench/LTP cases. Treat rc124 from a
shorter timeout as "inconclusive" unless the container state and Docker client
state were captured.

## Shell Option Reduction

Follow-up batch:

- tag: `nacc_sh_option_reduce_01_20260601_135919`
- VM log:
  `logs/nacc_sh_option_reduce_01_20260601_135919_01_20260601_135919_vm_20260601_140618.log`
- QEMU log:
  `logs/nacc_sh_option_reduce_01_20260601_135919_01_20260601_135919_qemu_20260601_140618.log`
- guest run directory:
  `/root/lmbench_nacc_runs/sh_option_reduce_20260601_060250`

This run tested whether the remaining true-NaCC Ubuntu shell-child rc139 was
caused by using `/bin/sh -lc` rather than a non-login shell.

| Mode | Command | rc | Duration | Output |
| --- | --- | --- | --- | --- |
| default Docker | `/bin/sh -c '/bin/true; echo ...'` | 0 | 20s | `true_rc=0`, `done` |
| default Docker | `/bin/sh -lc '/bin/true; echo ...'` | 0 | 16s | `true_rc=0`, `done` |
| default Docker | `/bin/bash -c '/bin/true; echo ...'` | 0 | 14s | `true_rc=0`, `done` |
| default Docker | `/bin/bash -lc '/bin/true; echo ...'` | 0 | 16s | `true_rc=0`, `done` |
| true NaCC | `/bin/sh -c '/bin/true; echo ...'` | 0 | 24s | `true_rc=0`, `done` |
| true NaCC | `/bin/sh -lc '/bin/true; echo ...'` | 139 | 27s | empty |
| true NaCC | `/bin/bash -c '/bin/true; echo ...'` | 0 | 31s | `true_rc=0`, `done` |
| true NaCC | `/bin/bash -lc '/bin/true; echo ...'` | 0 | 44s | `true_rc=0`, `done` |

The QEMU log did not contain `Kernel panic`, `Oops`, `Fatal exception`, or
`BUG:` markers. It contained one failed `SIGCHLD` frame:

```text
handle_signal pid=1981 comm=sh cid=471a0ad25472 sig=17 ...
setup_rt_frame pid=1981 comm=sh cid=471a0ad25472 sig=17 ... frame=0000003fe3f88e40
[NACC][private-copy-to-user-denied] pid=1981 comm=sh cid=471a0ad25472 user_va=3fe3f88e40 ... err=-4
handle_signal setup_done pid=1981 comm=sh cid=471a0ad25472 sig=17 ret=-14 ...
```

### Updated Interpretation

The remaining minimal rc139 is now very narrow:

- true-NaCC Ubuntu `/bin/sh -c` works;
- true-NaCC Ubuntu `/bin/bash -c` works;
- true-NaCC Ubuntu `/bin/bash -lc` works, although slowly;
- true-NaCC Ubuntu `/bin/sh -lc` fails with rc139 and an empty log;
- the failure aligns with a `SIGCHLD` signal frame setup denial on `comm=sh`.

This means future benchmark harnesses should avoid `/bin/sh -lc` unless the
login-shell behavior is explicitly under test. Prefer `/bin/sh -c` for small
Docker command wrappers. The signal-frame bug still matters for full
compatibility, but the minimal working path for benchmark smoke tests is now
clearer.

## Corrected `/bin/sh -c` lmbench Mini Matrix

Follow-up batch:

- tag: `nacc_lmbench_shc_valid_01_20260601_143111`
- VM log:
  `logs/nacc_lmbench_shc_valid_01_20260601_143111_vm_20260601_145722.log`
- QEMU log:
  `logs/nacc_lmbench_shc_valid_01_20260601_143111_qemu_20260601_145722.log`
- guest run directory:
  `/root/lmbench_nacc_runs/lmbench_shc_valid_20260601_063446`

This batch corrected the previous invalid binary path. The `nacc-lmbench:jammy`
image stores lmbench binaries directly under `/usr/lib/lmbench/bin`, not under
`/usr/lib/lmbench/bin/riscv64-linux-gnu`.

All direct lmbench binaries in this mini matrix completed under true NaCC when
invoked through `/bin/sh -c`:

| Case | default Docker | true NaCC |
| --- | --- | --- |
| `lat_syscall null` | rc0, `6.2913 us` | rc0, `13354.6264 us` |
| `lat_syscall read` | rc0 | rc0, `16693.8247 us` |
| `lat_syscall write` | rc0, `7.5201 us` | rc0, `15274.3803 us` |
| `lat_pipe` | rc0, `649.0775 us` | rc0, `66718.2632 us` |
| `bw_pipe` | rc0, `46.78 MB/sec` | rc0, `1.57 MB/sec` |
| `bw_mem 1m rd` | rc0, `1.05 14867.88` | rc0, `1.05 902.95` |
| `lat_proc fork` | rc0, `10235.0000 us` | rc0, `1250822.0000 us` |
| `scripts/os` | rc0, old GNU config diagnostic | rc0, three `Segmentation fault` lines |

The important correction is that direct lmbench binary execution is usable as a
benchmark smoke under true NaCC, but it is very slow. The remaining abnormal
behavior is concentrated in shell/script paths, especially scripts using
pipelines, command substitution, and child-process reaping.

The QEMU log for this matrix did not show a kernel panic, `Oops`, fatal
exception, or `BUG:`. It did show signal-frame failures during `scripts/os`:

```text
handle_signal pid=5058 comm=os cid=def578c1b34a sig=17 ...
setup_rt_frame pid=5058 comm=os cid=def578c1b34a sig=17 ...
[NACC][private-copy-to-user-denied] pid=5058 comm=os cid=def578c1b34a user_va=3ffecb5fb0 ... err=-4
handle_signal setup_done pid=5058 comm=os cid=def578c1b34a sig=17 ret=-14 ...
```

The failing code path is:

- `linux/arch/riscv/kernel/signal.c:428` `handle_signal()`;
- `linux/arch/riscv/kernel/signal.c:350` `setup_rt_frame()`;
- `setup_rt_frame()` writes the signal frame with `copy_siginfo_to_user()`,
  `__put_user()`, `setup_sigcontext()`, and `__copy_to_user()`;
- NaCC private copy handling reports the denial from
  `linux/arch/riscv/mm/nacc.c:596` in `nacc_private_data_copy_to_user()`;
- `setup_rt_frame()` returns `-EFAULT`, and `handle_signal()` passes that into
  `signal_setup_done()`.

So this lmbench line is not a kernel-panic failure. It is a failed user signal
frame delivery to a private user stack after `SIGCHLD`.

## `scripts/os` Shell Trace Reduction

Follow-up batch:

- tag: `nacc_lmbench_os_trace_01_20260601_145951`
- VM log:
  `logs/nacc_lmbench_os_trace_01_20260601_145951_vm_20260601_151038.log`
- QEMU log:
  `logs/nacc_lmbench_os_trace_01_20260601_145951_qemu_20260601_151038.log`
- guest run directory:
  `/root/lmbench_nacc_runs/scripts_os_trace_20260601_070327`

This batch ran `scripts/os` and `scripts/gnu-os` with `/bin/sh -x`.

Results:

| Case | default Docker | true NaCC |
| --- | --- | --- |
| script/source inspection | rc0 | rc139 |
| `/bin/sh -x ./os` | rc0, old config diagnostic | rc0, three `Segmentation fault` lines |
| `/bin/sh -x ./gnu-os --time-stamp` | rc0 | rc0, one `Segmentation fault` line |
| `CC_FOR_BUILD=false /bin/sh -x ./gnu-os` | rc1, expected old config failure | rc1, expected old config failure, much slower |

The `os` script is small. It runs:

```sh
MACHINE=`uname -m | sed -e 's/ //g' | sed -e 's?/?-?g'`
SYSTEM=`uname -s | sed -e 's/ //g' | sed -e 's?/?-?g'`
OS=`${SCRIPTSDIR}/gnu-os | sed 's/unknown-//'`
```

Under true NaCC, `sh -x ./os` printed `Segmentation fault` at these three
pipeline/command-substitution points, while continuing to rc0:

```text
+ uname -m
+ sed -e s/ //g
+ sed -e s?/?-?g
Segmentation fault
+ uname -s
+ sed -e s/ //g
+ sed -e s?/?-?g
Segmentation fault
+ ../scripts/gnu-os
+ sed s/unknown-//
Segmentation fault
```

`gnu-os --time-stamp` narrowed the issue further. Even this simple assignment
inside `gnu-os`:

```sh
me=`echo "$0" | sed -e 's,.*/,,'`
```

printed a `Segmentation fault` under true NaCC, while still returning rc0 and
printing `2004-08-18`.

This shows that the abnormality is not specific to lmbench measurement binaries
or to GNU config's lack of RISC-V recognition. It is tied to shell
pipeline/command-substitution child handling.

## Minimal Shell Pipeline Reproducer

Follow-up batch:

- tag: `nacc_shell_pipeline_reduce_01_20260601_151139`
- VM log:
  `logs/nacc_shell_pipeline_reduce_01_20260601_151139_vm_20260601_151929.log`
- QEMU log:
  `logs/nacc_shell_pipeline_reduce_01_20260601_151139_qemu_20260601_151929.log`
- guest run directory:
  `/root/lmbench_nacc_runs/shell_pipeline_reduce_20260601_071509`
- image: `ubuntu:22.04`

This batch removed lmbench entirely and used ordinary Ubuntu shell commands.

| Case | default Docker | true NaCC |
| --- | --- | --- |
| `/bin/true; echo after_true` | rc0 | rc0 |
| `echo foo \| sed s/foo/bar/` | rc0 | rc139 |
| `x=$(echo foo \| sed s/foo/bar/); echo x=$x` | rc0 | rc0, printed `Segmentation fault`, then `x=bar` |
| `x=$(uname -m \| sed ... \| sed ...); echo x=$x` | rc0 | rc0 in this run |
| `x=$(echo ./gnu-os \| sed -e 's,.*/,,'); echo x=$x` | rc0 | rc0 in this run |

The smallest hard failure found in this batch is:

```sh
/bin/sh -c 'set -x; echo foo | sed s/foo/bar/'
```

under true NaCC Docker. It returned rc139 and produced only:

```text
+ echo foo
+ sed s/foo/bar/
```

The smallest soft failure found in this batch is:

```sh
/bin/sh -c 'set -x; x=$(echo foo | sed s/foo/bar/); echo x=$x'
```

under true NaCC Docker. It returned rc0 but printed:

```text
+ echo foo
+ sed s/foo/bar/
Segmentation fault
+ x=bar
+ echo x=bar
x=bar
```

The QEMU log had no kernel panic, `Oops`, fatal exception, or `BUG:` markers. It
contained two failed `SIGCHLD` frame setup events:

```text
handle_signal pid=1546 comm=sh cid=1f3876a0b4ba sig=17 ...
setup_rt_frame pid=1546 comm=sh cid=1f3876a0b4ba sig=17 ... frame=0000003fc832bf80
[NACC][private-copy-to-user-denied] pid=1546 comm=sh cid=1f3876a0b4ba user_va=3fc832bf80 ... err=-4
handle_signal setup_done pid=1546 comm=sh cid=1f3876a0b4ba sig=17 ret=-14 ...

handle_signal pid=2026 comm=sh cid=4a47dbabf889 sig=17 ...
setup_rt_frame pid=2026 comm=sh cid=4a47dbabf889 sig=17 ... frame=0000003ff342ef00
[NACC][private-copy-to-user-denied] pid=2026 comm=sh cid=4a47dbabf889 user_va=3ff342ef00 ... err=-4
handle_signal setup_done pid=2026 comm=sh cid=4a47dbabf889 sig=17 ret=-14 ...
```

### Updated Interpretation

The current lmbench issue is now reduced to a general shell pipeline/command
substitution compatibility bug under true NaCC Docker:

- direct lmbench binaries are broadly runnable, though very slow;
- a simple child process (`/bin/true`) works;
- shell pipelines and command substitutions can trigger `SIGCHLD`;
- delivering that `SIGCHLD` requires the RISC-V signal code to write an
  `rt_sigframe` to the shell's user stack;
- NaCC sometimes denies that private-stack user copy with `err=-4`;
- Linux then returns `-EFAULT` from `setup_rt_frame()`, and user space observes
  either rc139 or a printed `Segmentation fault` while the shell may continue.

This is the same class as the earlier full `lmbench-run`, `scripts/os`, and
`/bin/sh -lc` failures, but the minimal reproducer is no longer lmbench-specific.

The next debugging target should be the NaCC private copy-to-user handling for
signal-frame writes to private user stacks, not the lmbench wrapper itself.

### Function-Level Location

For the current lmbench / shell-pipeline issue, there is no kernel panic
location to report: the checked QEMU logs for the reduced reproducer contain no
`Kernel panic`, `Oops`, fatal exception, or `BUG:` marker. The visible failure
is a user-space shell `SIGSEGV`/rc139 caused by a failed signal-frame setup.

The failing chain is:

1. `linux/arch/riscv/kernel/signal.c:428` `handle_signal()` receives `SIGCHLD`
   for `/bin/sh`.
2. `linux/arch/riscv/kernel/signal.c:350` `setup_rt_frame()` chooses a frame on
   the shell user stack and starts writing `struct rt_sigframe`.
3. The frame writes include:
   - `copy_siginfo_to_user(&frame->info, &ksig->info)` at line 368;
   - several `__put_user()` / `__save_altstack()` / `setup_sigcontext()` calls;
   - `__copy_to_user(&frame->uc.uc_sigmask, set, sizeof(*set))` at line 375.
4. Generic `__copy_to_user()` eventually reaches the RISC-V hook
   `linux/arch/riscv/include/asm/uaccess.h:390` `raw_copy_to_user()`.
5. When `nacc_private_data_uaccess_active()` is true, `raw_copy_to_user()` calls
   `nacc_private_data_copy_to_user()` in `linux/arch/riscv/mm/nacc.c:526`.
6. `nacc_private_data_copy_to_user()` issues
   `SBI_EXT_NACC_UACCESS_PRIVATE_COPY_TO_USER` at lines 564-566.
7. OpenSBI dispatches that ecall through
   `opensbi/lib/sbi/sbi_ecall_nacc.c:141-148`.
8. The OpenSBI handler
   `opensbi/lib/sbi/sbi_trap_ldst.c:757`
   `nacc_private_data_uaccess_private_copy_to_user()` calls
   `nacc_private_data_resolve_private_user_pa()` at line 787.

The reduced QEMU log shows this OpenSBI destination resolution failing:

```text
[NACC][uaccess-copy-to-user-diag] ... event=dst_resolve rc=-4 ... user_va=0x3fc832bf80 ... dst_pa=0x0 ...
[NACC][private-copy-to-user-denied] pid=1546 comm=sh ... user_va=3fc832bf80 ... err=-4
[Linux]: handle_signal setup_done pid=1546 comm=sh ... sig=17 ret=-14 ...
```

This can be narrowed further than function level. The logged `user_va` equals
the `frame` address printed by `setup_rt_frame()`, and
`struct rt_sigframe` starts with `struct siginfo info`. The failed copy is also
`bytes=48`, matching the first `copy_to_user()` inside
`linux/kernel/signal.c:3384` `copy_siginfo_to_user()`, which copies
`sizeof(struct kernel_siginfo)` before clearing the remaining siginfo expansion
space. Therefore the first failing statement is very likely:

```c
err |= copy_siginfo_to_user(&frame->info, &ksig->info);
```

from `linux/arch/riscv/kernel/signal.c:368`, specifically its internal
`copy_to_user(to, from, sizeof(struct kernel_siginfo))` at
`linux/kernel/signal.c:3387`.

`rc=-4` is `SBI_ERR_DENIED`, so this is not the not-supported/prefault fallback
case. In the current OpenSBI code this can come from
`nacc_private_data_resolve_private_user_leaf()` rejecting a leaf that is not
`NACC_RESIDENT_LEAF_VALID_USER`, or from
`nacc_private_data_resolve_private_user_pa()` rejecting a leaf that is not
user-writable (`!(leaf.pte & PTE_W)`). The diagnostic reports `dst_pa=0x0`
because destination PA resolution failed before a writable destination physical
address was produced.

One caveat: this workspace currently does not contain the unstripped NaCC
`vmlinux` or `System.map`, so the logged `caller_pc` value cannot be resolved
with `addr2line` yet. The function-level source path above is identified from
the instrumented log messages and the uaccess call chain in the checked source.

### Destination Leaf Diagnostic: No-Write Private Stack Page

Follow-up diagnostic batch:

- tag: `nacc_copy_to_user_dst_detail_20260601_154538_01_20260601_154538`
- VM log:
  `logs/nacc_copy_to_user_dst_detail_20260601_154538_01_20260601_154538_vm_20260601_155411.log`
- QEMU log:
  `logs/nacc_copy_to_user_dst_detail_20260601_154538_01_20260601_154538_qemu_20260601_155411.log`
- command:

```sh
docker run --rm --runtime runc --security-opt seccomp=unconfined ubuntu:22.04 \
  /bin/sh -c 'set -x; echo foo | sed s/foo/bar/'
```

This run used a narrow temporary OpenSBI diagnostic on the
`SBI_EXT_NACC_UACCESS_PRIVATE_COPY_TO_USER` destination-denied path. The batch
ended as `auto-timeout` because the VM later panicked during coredump handling,
but the first bad event was captured.

Key first-bad signal-frame sequence:

```text
[Linux]: handle_signal pid=927 comm=sh cid=fcef37b77def sig=17 ...
[Linux]: setup_rt_frame pid=927 comm=sh ... frame=0000003fd35b3eb0 frame_size=1088
[NACC][copy-to-user-dst-denied-detail] seq=1 rc=-4 reason=no_write pid=39f user_va=3fd35b3eb0 kernel_va=ffffffc60071bdb0 bytes=30 caller_pc=ffffffff80029c00 leaf_found=1 root_pfn=105544 kind=2 tag=2 pte=400000462db4d3 pfn=118b6d page_pa=118b6d000 fault_pa=118b6deb0 level=0 flags=d3 vrwxu=11001 ...
[NACC][private-copy-to-user-denied] pid=927 comm=sh ... user_va=3fd35b3eb0 ... bytes=48 copied=0 err=-4
[Linux]: handle_signal setup_done pid=927 comm=sh ... sig=17 ret=-14 ...
```

Interpretation:

- `user_va=3fd35b3eb0` equals the `setup_rt_frame()` frame address, so this is
  still the first signal-frame write.
- The diagnostic prints `bytes=30` in hex, i.e. 48 decimal, matching the first
  `copy_to_user()` for `sizeof(struct kernel_siginfo)`.
- `leaf_found=1`: OpenSBI resolved the destination VA to a leaf.
- `tag=2`: `NACC_PFN_TAG_PRIVATE_DATA`.
- `kind=2`: `NACC_RESIDENT_LEAF_VALID_USER`.
- `flags=d3` / `vrwxu=11001`: PTE has V, R, and U, but does not have W.
- Therefore the precise destination rejection reason is `no_write`.

This narrows the bug substantially: the failing shell signal frame lands on an
existing private user stack page that is currently write-protected, plausibly a
COW/write-protect state caused by the pipeline's fork/child handling. Current
Linux-side `nacc_private_data_copy_to_user()` only triggers
`nacc_private_data_fault_in_writeable()` on `SBI_ERR_NOT_SUPPORTED`; this case
returns `SBI_ERR_DENIED`, so the COW/write-fault retry path is not reached and
`setup_rt_frame()` fails with `-EFAULT`.

The later panic in the same run is secondary:

```text
[NACC][strict-sumoff-first-deny] access=load reason=sum_off_kernel_high_private_data pc=0xffffffff80a2bba0 ra=0xffffffff80426950 stval=0xffffffd6a087a000 ...
Oops - load access fault [#1]
epc : __memcpy+0x3c/0xf8
ra  : copy_page_from_iter_atomic+0x446/0x8b2
...
dump_user_range
elf_core_dump
do_coredump
...
Kernel panic - not syncing: Fatal exception in interrupt
```

That path occurs after the shell signal-frame failure causes a fatal user-space
fault and the kernel tries to generate a core dump. It is important, but it is
not the root cause of the pipeline failure. The root cause is the denied
signal-frame `copy_to_user()` to a private, valid-user, no-write stack page.

Likely next repair direction: make the private `copy_to_user` path handle the
private-valid-user-but-no-write destination as a write-fault/COW case. A narrow
way to do that would be for OpenSBI to distinguish this no-write private-user
case from real denials, or to return a code that causes the existing Linux
`nacc_private_data_fault_in_writeable()` + retry path to run exactly once.

## 2026-06-01 Bulk Copy-to-User COW Retry Repair

Repair attempt:

- OpenSBI `SBI_EXT_NACC_UACCESS_PRIVATE_COPY_TO_USER` now resolves the
  destination with `nacc_private_data_resolve_private_user_leaf()` so it can
  inspect the destination leaf PTE before requiring a writable PA.
- If the destination is a valid private user leaf but lacks `PTE_W`, OpenSBI
  returns `SBI_EDENIED_LOCKED`. This mirrors the existing scalar `put_user`
  behavior for private COW/write-protected leaves.
- Linux `nacc_private_data_copy_to_user()` now treats both
  `SBI_ERR_NOT_SUPPORTED` and `SBI_ERR_DENIED_LOCKED` as one-shot
  `nacc_private_data_fault_in_writeable()` + retry cases.

Build status:

- `make opensbi`: passed.
- `make linux-update`: passed after reverting an unrelated local
  `linux/mm/mremap.c` edit back to the current Linux commit state.
- Final image was regenerated successfully.

Validation batch:

- tag: `nacc_copy_to_user_cow_retry_20260601_173703_01_20260601_173703`
- VM log:
  `logs/nacc_copy_to_user_cow_retry_20260601_173703_01_20260601_173703_vm_20260601_174113.log`
- QEMU log:
  `logs/nacc_copy_to_user_cow_retry_20260601_173703_01_20260601_173703_qemu_20260601_174113.log`
- command:

```sh
docker run --rm --runtime runc --security-opt seccomp=unconfined ubuntu:22.04 \
  /bin/sh -c 'set -x; echo foo | sed s/foo/bar/'
```

Observed VM output:

```text
+ echo foo
+ sed s/foo/bar/
bar
[NaCC][ssh-auto-exit] code=0
```

Key QEMU log points:

```text
[Linux]: setup_rt_frame prepared pid=927 comm=sh ... sig=17 ...
[Linux]: handle_signal setup_done pid=927 comm=sh ... sig=17 ret=0 ...
```

No matches were found for the prior failure signatures
`private-copy-to-user-denied`, `private-copy-to-user-prefault-failed`,
`copy-to-user-dst-denied-detail`, `Kernel panic`, `Oops`, `BUG:`, or
`Segmentation fault` in this validation run.

Conclusion: the minimal `/bin/sh` pipeline signal-frame reproducer is fixed by
the COW/write-fault retry repair. This does not yet prove the full lmbench
wrapper is clean; it only closes the specific first failure where signal-frame
`copy_to_user()` hit a private valid-user no-write stack page.
