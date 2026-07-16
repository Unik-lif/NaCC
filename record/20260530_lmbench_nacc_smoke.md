# lmbench True-NaCC Smoke

Date: 2026-05-30

## Goal

Try a smaller benchmark before continuing with full LTP. The immediate target
was a minimal lmbench smoke under the current true NaCC container path:

- Docker runtime: NaCC-patched `runc`
- Docker seccomp: `--security-opt seccomp=unconfined`
- lmbench binary: bind-mounted from the RISC-V guest into `ubuntu:22.04`
- first benchmark: `lat_syscall null`

This avoids the full lmbench script harness and tests one direct lmbench binary
as the container workload.

## Artifacts

- Batch tag:
  `lmbench_nacc_smoke_01_20260530_144646`
- Auto command:
  `logs/test_runner/lmbench_nacc_smoke_01_20260530_144646_auto_cmd.txt`
- VM log:
  `logs/lmbench_nacc_smoke_01_20260530_144646_vm_20260530_145443.log`
- QEMU log:
  `logs/lmbench_nacc_smoke_01_20260530_144646_qemu_20260530_145443.log`

The batch completed with:

```text
run=1 status=ok
```

No `Kernel panic`, `Oops`, or `reject Linux-origin` signature was found in the
captured QEMU log.

## Setup

The guest installed Ubuntu's packaged lmbench:

```text
lmbench 3.0-a9+debian.1-6
lmbench-doc 3.0-a9+debian.1-6
```

This mutates the guest filesystem image by adding the `lmbench` and
`lmbench-doc` packages.

The guest reported:

```text
Linux Ubuntu-riscv64 6.12.0-00063-gf401367654bd-dirty #1 SMP Wed May 27 23:09:48 CST 2026 riscv64
Docker version 28.5.0
runc version 1.3.2
```

The installed binary used for the smoke was:

```text
/usr/lib/lmbench/bin/lat_syscall
```

The container invocation was equivalent to:

```sh
docker run --rm --runtime runc --security-opt seccomp=unconfined \
  -v /usr/lib/lmbench:/lmbench:ro \
  -e LD_LIBRARY_PATH=/lmbench/bin \
  ubuntu:22.04 /lmbench/bin/lat_syscall null
```

## Result

Native guest baseline for the same binary:

```text
Simple syscall: 4.6874 microseconds
```

True NaCC container result:

```text
Simple syscall: 13081.8667 microseconds
```

The NaCC result is very slow, but the important first result is functional:
the benchmark binary started, ran to completion, and exited with `rc=0` under
the true NaCC registration path.

## NaCC Evidence

The QEMU log shows Docker/runc reaching NaCC registration:

```text
[Linux] register a new NACC process.
[SBI]: cid: cd101149e5b pid: 4bb
[Linux]: GO BACK TO RUNC.
```

The benchmark process itself ran under that CID:

```text
comm=lat_syscall cid=cd101149e5b
```

Unregister activity was also observed near the end:

```text
[Linux]: nacc unregister pid=1281 cid=cd101149e5b
[Linux]: nacc unregister pid=1211 cid=cd101149e5b
```

## Interpretation

This is the first confirmed small benchmark that completes under true NaCC
container execution after the LTP probe exposed an exec/page-table blocker.

The result supports shifting the near-term benchmark plan away from full LTP
and toward small direct benchmark binaries:

- direct lmbench binaries can run without the full lmbench script harness;
- `lat_syscall null` is a usable first smoke;
- the overhead is large and should be measured carefully only after we have a
  stable small-suite runner;
- full lmbench scripts should be introduced gradually, because they may add
  shell, fork, exec, and file-management paths that resemble the LTP blocker.

## Next Steps

1. Add a small lmbench subset runner rather than launching the full suite:
   - `lat_syscall null`
   - `lat_syscall read`
   - `lat_syscall write`
   - maybe one memory bandwidth test such as `bw_mem`

2. Run the same subset in three modes:
   - direct guest native
   - ordinary Docker without NaCC registration, if needed as a container
     baseline
   - true NaCC Docker with `seccomp=unconfined`

3. Keep LTP as a targeted compatibility probe, not the primary near-term
   benchmark.
