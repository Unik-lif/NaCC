# lmbench `bw_mem` Invocation Closeout

Date: 2026-06-03

## Context

The active `TASK_20260603_115529_lmbench_bw_mem` investigated why prior
`lmbench` runs around `bw_mem 1m rd` produced unusable output. The fresh
test-runner detailed run showed:

- guest direct `bw_mem 1m rd`: rc0 with a numeric row, for example
  `1.05 15363.75`;
- default Docker direct exec: rc0 with only the Docker logpipe warning;
- true NaCC direct exec: rc0 with 0-byte captured output;
- fresh QEMU logs did not reproduce the older signal-frame
  `private-copy-to-user-denied` / `ret=-14` lead.

That evidence made the case suspicious as a measurement, but did not prove a
NaCC source bug.

## Image Provenance

`nacc-lmbench:jammy` is not a public registry image. It was built locally inside
the RISC-V VM by the earlier lmbench task from this effective Dockerfile:

```dockerfile
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive LANG=C LC_ALL=C
RUN apt-get update \
 && apt-get install -y --no-install-recommends lmbench lmbench-doc bc net-tools procps hostname iproute2 perl libc6 libtirpc3 \
 && rm -rf /var/lib/apt/lists/*
```

The image stores direct lmbench binaries under `/usr/lib/lmbench/bin`.

## Manual Reproduction

The human manually reproduced the behavior inside the RISC-V VM.

Basic checks:

- `docker run --rm nacc-lmbench:jammy /bin/echo docker_stdout_ok` printed the
  marker and exited rc0, while also printing the Docker warning
  `Failed to write to log, write logpipe: file already closed`.
- `docker run --rm nacc-lmbench:jammy ls -l /usr/lib/lmbench/bin/bw_mem`
  confirmed the `bw_mem` binary exists in the image.

Default Docker with a shell wrapper completed and printed a numeric row:

```sh
docker run --rm \
  -e LANG=C -e LC_ALL=C -e ENOUGH=1000 -e TIMING_O=0 -e LOOP_O=0 \
  nacc-lmbench:jammy \
  /bin/sh -lc 'echo before_bw_mem; /usr/lib/lmbench/bin/bw_mem 1m rd; echo inner_rc=$?; echo after_bw_mem'
```

Observed output included:

```text
before_bw_mem
1.05 15592.21
inner_rc=0
after_bw_mem
docker rc=0
```

True NaCC with the same shell wrapper also completed and printed a numeric row:

```sh
docker run --rm \
  --runtime runc \
  --security-opt seccomp=unconfined \
  --ulimit core=0 \
  -e LANG=C -e LC_ALL=C -e ENOUGH=1000 -e TIMING_O=0 -e LOOP_O=0 \
  nacc-lmbench:jammy \
  /bin/sh -lc 'echo before_bw_mem; /usr/lib/lmbench/bin/bw_mem 1m rd; echo inner_rc=$?; echo after_bw_mem'
```

Observed output included:

```text
before_bw_mem
1.05 7482.19
inner_rc=0
after_bw_mem
true nacc docker rc=0
```

True NaCC direct exec still exited rc0 without the numeric row:

```sh
docker run --rm \
  --runtime runc \
  --security-opt seccomp=unconfined \
  --ulimit core=0 \
  -e LANG=C -e LC_ALL=C -e ENOUGH=1000 -e TIMING_O=0 -e LOOP_O=0 \
  nacc-lmbench:jammy /usr/lib/lmbench/bin/bw_mem 1m rd
```

Adding Docker `--init` made the true NaCC direct command print a numeric row:

```sh
docker run --rm \
  --init \
  --runtime runc \
  --security-opt seccomp=unconfined \
  --ulimit core=0 \
  -e LANG=C -e LC_ALL=C -e ENOUGH=1000 -e TIMING_O=0 -e LOOP_O=0 \
  nacc-lmbench:jammy /usr/lib/lmbench/bin/bw_mem 1m rd
```

Observed output included:

```text
1.05 7429.18
```

The human also reproduced the direct-exec no-row behavior without the NaCC
security options, so the empty direct-exec output is not NaCC-specific.

## Conclusion

The prior `bw_mem` oddity is best classified as an invocation/output-capture
problem, not as a proven NaCC source bug and not as evidence that `bw_mem` fails
or stalls under NaCC.

The key boundary is:

- Docker direct exec, where `bw_mem` is the container PID 1, can exit rc0 while
  not producing a captured numeric row in this environment.
- Running through `/bin/sh -lc` or adding Docker `--init` makes the same
  benchmark produce the expected numeric row.
- Because the direct-exec no-row behavior also appears without NaCC, it should
  not be treated as a NaCC performance/pathology signal.

## Follow-Up Guidance

Do not use the old direct-exec form as a valid `bw_mem` measurement:

```sh
docker run ... nacc-lmbench:jammy /usr/lib/lmbench/bin/bw_mem 1m rd
```

For future `bw_mem` performance comparisons, use the same non-PID1 invocation
shape across guest/default-Docker/true-NaCC paths. Preferred shape:

```sh
docker run --rm \
  --init \
  -e LANG=C -e LC_ALL=C -e ENOUGH=1000 -e TIMING_O=0 -e LOOP_O=0 \
  nacc-lmbench:jammy /usr/lib/lmbench/bin/bw_mem 1m rd
```

For true NaCC, add the NaCC runtime/security options to the same shape:

```sh
docker run --rm \
  --init \
  --runtime runc \
  --security-opt seccomp=unconfined \
  --ulimit core=0 \
  -e LANG=C -e LC_ALL=C -e ENOUGH=1000 -e TIMING_O=0 -e LOOP_O=0 \
  nacc-lmbench:jammy /usr/lib/lmbench/bin/bw_mem 1m rd
```

Using `/bin/sh -lc 'cd /usr/lib/lmbench/bin && ./bw_mem 1m rd'` is also valid
for smoke/debug comparisons, but `--init` is the cleaner measurement shape
because it changes the benchmark command less.
