# Clean runc-origin and dockero Baseline

Date: 2026-05-29

## Goal

Create a cleaner native Docker baseline inside the NaCC RISC-V Ubuntu guest by
removing the NaCC-patched `runc` from the container runtime path.

The immediate motivation is the LTP syscall baseline:

- The default native Docker LTP `runtest/syscalls` run completed `1506` entries.
- It returned `rc=0` for `898` entries and non-zero for `608` entries.
- `rc=2` appeared for `269` entries, which may include ordinary LTP
  setup/broken cases, Docker policy effects, or runtime/environment problems.

Before interpreting those failures, we need to know whether the Docker runtime
path is using a clean upstream `runc` or the local NaCC-patched `runc`.

## Current Default runc State

The guest default `runc` is not clean upstream:

- Binary path: `/usr/local/sbin/runc`
- Version: `runc version 1.3.2`
- Commit string: `v1.3.2-0-gaeabe4e7-dirty`
- SHA256:
  `7f7caabb464ddf40a2638e60f0666e5f05cbf6d572ec22f9903850e0b3372b5d`
- Marker strings found in the binary:
  - `NACC_MANIFEST_PATH`
  - `nacc register syscall failed`
  - `naccLoadManifestIdentity`
  - `naccLoadManifestLayout`

This means the existing default Docker service is not a fully clean native
runtime baseline, even if a specific container launch avoids the intended NaCC
startup flow.

Probe artifacts:

- VM log:
  `logs/runc_current_state_probe_01_20260529_132950_vm_20260529_133307.log`
- QEMU log:
  `logs/runc_current_state_probe_01_20260529_132950_qemu_20260529_133307.log`

## Implemented Clean Runtime Path

Host-side helper added:

- `scripts/setup_runc_origin_dockero_guest.sh`

The helper is intended to run inside the RISC-V guest. It performs these steps:

1. Uses `/root/riscv-docker/runc` as the existing source repository.
2. Creates a detached clean worktree at `/root/riscv-docker/runc-origin`.
3. Builds upstream `runc` from the same upstream commit.
4. Installs it as `/usr/local/sbin/runc-origin`.
5. Verifies the source and binary do not contain the NaCC marker strings.
6. Creates a separate Docker daemon service, `dockero.service`, using:
   - socket: `/run/dockero.sock`
   - data root: `/var/lib/dockero`
   - exec root: `/run/dockero`
   - default runtime: `runc-origin`
   - runtime binary: `/usr/local/sbin/runc-origin`
7. Creates `/usr/local/bin/dockero`, a small CLI wrapper around:
   `docker -H unix:///run/dockero.sock`.

`dockero` intentionally shares the existing `containerd` service but uses a
separate Docker daemon socket, pidfile, data root, exec root, and default
runtime. It also disables bridge/iptables management to avoid colliding with
the normal Docker daemon.

## Setup Result

The setup batch completed successfully.

Batch artifacts:

- VM log:
  `logs/runc_origin_dockero_setup_01_20260529_133720_vm_20260529_134528.log`
- QEMU log:
  `logs/runc_origin_dockero_setup_01_20260529_133720_qemu_20260529_134528.log`

Clean worktree details:

- Source repository: `/root/riscv-docker/runc`
- Source HEAD:
  `aeabe4e711d903ef0ea86a4155da0f9e00eabd29`
- Existing source describe before worktree:
  `v1.3.2-dirty`
- Dirty file in patched source:
  `libcontainer/standard_init_linux.go`
- Clean worktree: `/root/riscv-docker/runc-origin`
- Clean worktree describe: `v1.3.2`

Installed clean runtime:

- Binary path: `/usr/local/sbin/runc-origin`
- Version: `runc version 1.3.2`
- Commit string: `v1.3.2-0-gaeabe4e7`
- OCI spec: `1.2.1`
- Go: `go1.23.9`
- libseccomp: `2.5.3`
- SHA256:
  `f5a95d20c59ea942abb54f3d9114e370dcc48b6d9b37329155e49e3e23eee0d0`
- NaCC marker check: clean

`dockero info` reported:

```text
Runtimes: runc-origin io.containerd.runc.v2 runc
Default Runtime: runc-origin
```

`ubuntu:22.04` was loaded from the normal Docker image store into the separate
`dockero` image store.

Smoke test:

```text
dockero run --rm ubuntu:22.04 sh -c 'echo dockero-smoke-ok; uname -m'
dockero-smoke-ok
riscv64
```

This confirms that `ubuntu:22.04` can run through the clean `runc-origin`
runtime path inside the RISC-V guest.

## LTP Probe Through dockero

After parameterizing `scripts/ltp_docker_syscalls_runner.sh` with
`LTP_DOCKER_CLI`, a small LTP syscall probe was run through `dockero`:

```text
LTP_DOCKER_CLI=/usr/local/bin/dockero \
LTP_CASE_TIMEOUT_SECONDS=120 \
/root/nacc_ltp/ltp_docker_syscalls_runner.sh probe
```

Probe artifacts:

- VM log:
  `logs/ltp_dockero_syscalls_probe_01_20260529_135000_01_20260529_134856_vm_20260529_135636.log`
- QEMU log:
  `logs/ltp_dockero_syscalls_probe_01_20260529_135000_01_20260529_134856_qemu_20260529_135636.log`

Runner configuration:

- `docker_cli=/usr/local/bin/dockero`
- image: `ubuntu:22.04`
- LTP tree: `/root/ltp`
- selected entries: `2`
- syscall executables linked: `1520`
- per-case timeout: `120s`
- guest run directory:
  `/root/ltp_docker_runs/syscalls_probe_20260529_055610`

Probe result:

```text
getpid01    rc=0    elapsed=2s
seccomp01   rc=2    elapsed=0s    broken=1

RESULT total=2 rc0=1 nonzero=1
LTP_FIELDS passed=100 failed=0 broken=1 skipped=0 warnings=0
RC code=0 count=1
RC code=2 count=1
```

This confirms that the LTP runner can execute through the clean `dockero`
runtime path. The remaining `seccomp01 rc=2` in this tiny probe is not enough
evidence to implicate the NaCC-patched `runc`; it is still consistent with
ordinary default-Docker seccomp/policy behavior or LTP setup assumptions.

## Interpretation

This is a cleaner runtime-layer baseline than the previous default Docker run,
because the container create/init path no longer uses the NaCC-patched `runc`
binary.

It is not a fully "no NaCC" baseline. The VM still uses the current NaCC guest
environment, including the NaCC-enabled kernel/OpenSBI image and any kernel-side
hooks already present in this VM. Therefore:

- `dockero` isolates the runtime-level effect of the patched `runc`.
- It does not isolate kernel/OpenSBI-level NaCC effects.
- A fully clean native baseline would require a stock kernel/OpenSBI VM or an
  explicit build/runtime mode where NaCC kernel and firmware hooks are absent.

## Recommended Next Steps

1. Keep default Docker and `dockero` results as separate baselines:
   - default Docker: current project runtime behavior;
   - `dockero`: clean upstream `runc` runtime-layer baseline.
2. Use the completed full `dockero` LTP baseline as the runtime-layer
   comparison artifact:
   `record/20260529_ltp_dockero_syscalls_full_origin_runc_baseline.md`.
3. Do not treat the NaCC-patched `runc` binary as the primary explanation for
   the default-Docker `rc=2` population. The full `dockero` run produced the
   same `rc=2` count: `269`.
4. Next, classify the `rc=2` cases by LTP error reason and Docker policy class,
   or run the same runner in a fully stock kernel/OpenSBI RISC-V VM if a
   no-NaCC baseline is required.
