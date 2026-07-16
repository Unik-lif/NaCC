# LTP on NaCC RISC-V VM: Native Build and Docker Smoke

Date: 2026-05-29

## Goal

Evaluate whether upstream LTP can be built inside the NaCC RISC-V Ubuntu guest and then executed both directly in the guest and inside an `ubuntu:22.04` Docker container without rebuilding inside the container.

## Setup

- Repository: upstream `linux-test-project/ltp`
- LTP checkout: `e52eb4b`
- Build location in guest: `/root/ltp`
- Intended install prefix: `/opt/ltp`
- Docker runtime image: `ubuntu:22.04`
- Batch command file: `config/debug-batch.ltp_native_build_smoke.txt`
- Main VM log: `logs/ltp_native_build_smoke_nosubmodule_01_20260528_233211_vm_20260529_023527.log`
- Main QEMU log: `logs/ltp_native_build_smoke_nosubmodule_01_20260528_233211_qemu_20260529_023527.log`

Network note: the guest had stale proxy variables pointing to `192.168.104.171:7890`. `apt` worked only after unsetting `http_proxy`, `https_proxy`, `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and `all_proxy`, and forcing apt proxy options to `false`.

Clone note: cloning with submodules failed on the `kirk/ltx` submodule due GitHub/network instability. The successful build attempt used the main LTP repository without `--recurse-submodules`.

## LTP Size Counters

Counters collected from the RISC-V guest after the timed build:

- `runtest/*` non-comment entries: `4141`
- `runtest/syscalls` non-comment entries: `1506`
- Executable files built under `testcases/kernel/syscalls`: `1460`
- Executable files built under all `testcases`: `2333`
- `/opt/ltp`: missing, because `make install` was not reached

Interpretation: "3000+" is true for all `runtest/*` entries. The syscall-only suite is closer to `1500`, which is consistent with earlier observations of "1000+" tests.

## Full Build Result

The batch ran:

```sh
make autotools
./configure --prefix=/opt/ltp
make -j1
make install
```

`make -j1` compiled for 10800 seconds and then hit the SSH auto-command timeout:

```text
[NaCC][ssh-auto-timeout] remote command exceeded 10800s
```

The timeout happened after syscall and container testcases had already built, while the build was in:

```text
testcases/kernel/controllers/memcg/memcontrol01
```

No hard compile error was observed before the timeout. The important result is that a full one-shot LTP build is too slow for the current single-core RISC-V VM timeout, not that LTP cannot build.

## Build-Tree Smoke Tests

Because `make install` did not run, smoke tests used the build tree directly with:

```sh
LTPROOT=/root/ltp
PATH=/root/ltp/testcases/bin:$PATH
LD_LIBRARY_PATH=/root/ltp/lib:/root/ltp/lib64:${LD_LIBRARY_PATH:-}
```

Results:

- Native guest `getpid01`: passed `100`, failed `0`, broken `0`
- Docker default seccomp `getpid01` with `/root/ltp` bind-mounted read-only: passed `100`, failed `0`, broken `0`
- Native guest `seccomp01`: passed `18`, failed `0`, broken `0`
- Docker default seccomp `seccomp01`: broken, rc `2`, failed at `prctl(SECCOMP_MODE_STRICT)` with `EINVAL`
- Docker `--security-opt seccomp=unconfined` `seccomp01`: partial progress, rc `6`, failed later at `prctl(SECCOMP_MODE_FILTER)` with `EACCES`
- Docker default seccomp plus `--cap-add SYS_ADMIN` `seccomp01`: still broken, rc `2`
- Docker unconfined plus `--cap-add SYS_ADMIN` `seccomp01`: hung the VM/SSH path during this ad hoc check, so no conclusion was drawn from this variant

Smoke summary log with return codes: `logs/ltp_post_timeout_buildtree_smoke_20260529_023655.log`

The Docker `getpid01` run printed a harmless-looking Docker/logpipe warning:

```text
Failed to write to log, write logpipe: file already closed
```

The LTP summary still reported a clean pass.

## Cleanup

After the ad hoc seccomp capability check made the VM SSH path unresponsive, the retained QEMU owner was cleaned up:

- Cleanup log: `logs/cleanup_stale_qemu_owner_20260529_024639_ltp.log`
- Result: QEMU owner for `NaCC.qcow2` was killed and the image owner became free.

## Conclusions

1. Building LTP inside the NaCC RISC-V Ubuntu guest is feasible, but the full `make -j1 && make install` path exceeds a 10800-second remote command window.
2. The build progressed past the syscall suite and container tests, reaching controller/memcg tests before timeout.
3. The practical workflow should compile once in the guest and run from the build tree or from a targeted install, rather than rebuilding inside Docker.
4. A normal Docker `ubuntu:22.04` container with default seccomp can run ordinary build-tree LTP binaries such as `getpid01`.
5. Seccomp-specific LTP tests are strongly affected by Docker's own seccomp/capability policy. These should be separated from ordinary syscall tests when evaluating NaCC.
6. `--security-opt seccomp=unconfined` should not be used as the default native Docker baseline. It is better treated as a separate labeled mode for tests that intentionally manipulate seccomp, namespaces, or controller state.

## Recommended Next Steps

1. Reuse the persisted `/root/ltp` build tree in the guest rootfs instead of starting from a fresh clone/build.
2. Add a small targeted batch that runs selected syscall smoke tests from the build tree in:
   - native guest mode
   - Docker default seccomp mode
   - optionally Docker unconfined/privileged mode only for explicitly policy-sensitive tests
3. For `/opt/ltp` validation, try a targeted install rather than global `make install`, for example install only the libraries, runtest metadata, and `testcases/kernel/syscalls`.
4. Treat test counts explicitly:
   - all `runtest/*`: about `4141`
   - syscall-only `runtest/syscalls`: about `1506`
5. Do not mix ordinary compatibility results with Docker policy failures from tests like `seccomp01`.
