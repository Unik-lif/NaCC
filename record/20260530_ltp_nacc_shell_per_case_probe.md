# LTP Syscalls Through NaCC-Patched runc: Per-Container Probe

Date: 2026-05-30

## Goal

Start validating upstream LTP `runtest/syscalls` in a NaCC container path, after
the native RISC-V Docker, clean `runc-origin`/`dockero`, and direct guest
baselines from 2026-05-29.

The immediate question is not whether all LTP failures are NaCC bugs. It is:

- Can we run LTP syscall entries through the NaCC-patched container path?
- What runner shape avoids LTP harness artifacts?
- What early pass/fail distribution do we see before launching a long full run?

## Existing Baselines

The relevant completed baselines are:

- Native RISC-V Docker, default policy:
  `record/20260529_ltp_docker_syscalls_full_default_baseline.md`
  - `1506` entries
  - `rc=0`: `898`
  - non-zero: `608`
  - `rc=2`: `269`
  - `rc=127`: `45`

- Clean `runc-origin` through `dockero`, default policy:
  `record/20260529_ltp_dockero_syscalls_full_origin_runc_baseline.md`
  - `1506` entries
  - `rc=0`: `896`
  - non-zero: `610`
  - `rc=2`: `269`
  - `rc=127`: `45`

- Direct guest, no Docker:
  `record/20260529_ltp_native_syscalls_full_guest_baseline.md`
  - `1506` entries
  - `rc=0`: `1181`
  - non-zero: `325`
  - `rc=2`: `9`
  - `rc=127`: `13`

Interpretation from these baselines still stands: the large Docker `rc=2`
population is mostly Docker/container-environment behavior, not the local
NaCC-patched `runc` binary itself.

## Current NaCC ABI Reality

The current kernel entry point is:

- `linux/arch/riscv/kernel/sys_riscv.c`
  - `SYSCALL_DEFINE1(nacc_register, unsigned long, cid)`

It marks the current task as NaCC-preparation state, stores the container ID,
and issues:

- `sbi_ecall(SBI_EXT_NACC, SBI_EXT_NACC_REGISTER, cid, pid, ...)`

The current OpenSBI side is:

- `opensbi/lib/sbi/sm/sm.c`
  - `sm_nacc_register(uintptr_t cid, uintptr_t pid)`

It records the CID/PID mapping and ensures thread context. This path currently
does not consume a manifest memory-layout object from Linux/OpenSBI.

Therefore, in this experiment, "NaCC LTP" means running through the currently
installed NaCC-patched `runc`/kernel/OpenSBI registration path. It does not yet
mean manifest-enforced LTP coverage.

## Runner Added

New runner:

- `scripts/ltp_nacc_container_init_syscalls_runner.sh`

The runner executes one Docker container per selected `runtest/syscalls` entry.
It bind-mounts the already-built guest LTP tree at `/root/ltp`, so it does not
rebuild LTP inside each container.

Important defaults:

- `LTPROOT=/root/ltp`
- `RUN_ROOT=/root/ltp_nacc_runs`
- `LTP_DOCKER_IMAGE=ubuntu:22.04`
- `NACC_DOCKER_SECURITY_MODE=default`
- `NACC_LTP_INIT_MODE=shell`
- `LTP_CASE_TIMEOUT_SECONDS=120`

The runner now syncs `summary.tsv` before printing the final aggregate report,
to reduce risk of losing the final rows when the VM is shut down immediately
after a run.

## Direct PID-1 Mode Failed as a Harness Artifact

First probe tried to run the LTP testcase executable directly as container PID
1. That is not a usable runner shape for LTP.

Artifacts:

- VM log:
  `logs/ltp_nacc_init_probe2_default_01_20260530_122911_vm_20260530_123503.log`
- QEMU log:
  `logs/ltp_nacc_init_probe2_default_01_20260530_122911_qemu_20260530_123503.log`

Result:

- `getpid01`: `rc=3`
- `seccomp01`: `rc=3`

Observed LTP output includes:

- `TFAIL: Main test process might have exit!`
- `TBROK: Test killed! (timeout?)`

Conclusion: running the testcase itself as container PID 1 breaks LTP harness
expectations. These `rc=3` results should not be interpreted as kernel or NaCC
semantic failures.

## Shell PID-1 Mode Works

The runner default was changed to `NACC_LTP_INIT_MODE=shell`.

In this mode, container PID 1 is:

```text
bash -lc "$cmd; rc=$?; exit $rc"
```

The LTP testcase runs as a child of PID 1. This avoids the LTP PID-1 harness
timeout while still exercising the container start path. If NaCC registration
is active on the shell process, child coverage relies on the existing fork
inheritance path:

- `linux/kernel/fork.c`
  - `nacc_register_forked_child_pid(nacc_nr)`

Shell-mode probe artifacts:

- VM log:
  `logs/ltp_nacc_init_probe3_shell_01_20260530_123711_vm_20260530_124300.log`
- QEMU log:
  `logs/ltp_nacc_init_probe3_shell_01_20260530_123711_qemu_20260530_124300.log`

Result:

- Total: `2`
- `rc=0`: `1`
- non-zero: `1`
- `getpid01`: `rc=0`
- `seccomp01`: `rc=2`

`seccomp01` broke with `prctl(SECCOMP_MODE_STRICT) error: EINVAL (22)`, which
matches the earlier Docker/container-environment pattern rather than a runner
failure.

## Sample50 Result

Then the first `50` `runtest/syscalls` entries were run in shell-init mode,
default Docker policy. This is still useful as a Docker/LTP runner sanity check,
but later registration smokes showed it should not be treated as a true NaCC
coverage sample: Docker's default seccomp profile blocks the custom
`nacc_register` syscall issued by the NaCC-patched `runc`.

Artifacts:

- VM log:
  `logs/ltp_nacc_init_sample50_shell_01_20260530_124340_vm_20260530_130336.log`
- QEMU log:
  `logs/ltp_nacc_init_sample50_shell_01_20260530_124340_qemu_20260530_130336.log`
- Guest run directory:
  `/root/ltp_nacc_runs/syscalls_sample_20260530_044829`

Aggregate result from the runner's final report:

- Total: `50`
- `rc=0`: `26`
- non-zero: `24`
- LTP sub-results:
  - `passed=328`
  - `failed=20`
  - `broken=13`
  - `skipped=20`
  - `warnings=2`

Return-code distribution:

- `rc=0`: `26`
- `rc=1`: `3`
- `rc=2`: `13`
- `rc=5`: `1`
- `rc=32`: `6`
- `rc=33`: `1`

Non-zero entries:

```text
access04 rc=2
acct01 rc=32
acct02 rc=32
add_key01 rc=33
add_key02 rc=1
add_key03 rc=2
add_key04 rc=2
add_key05 rc=32
adjtimex01 rc=1
adjtimex02 rc=5
arch_prctl01 rc=32
bind02 rc=1
bind06 rc=2
bpf_map01 rc=2
bpf_prog01 rc=2
bpf_prog02 rc=2
bpf_prog03 rc=2
bpf_prog04 rc=2
bpf_prog05 rc=2
bpf_prog06 rc=2
bpf_prog07 rc=2
cacheflush01 rc=32
cachestat01 rc=2
cachestat02 rc=32
```

This distribution is plausible for default Docker policy: early entries already
include keyring, BPF, arch-specific, and feature/skip-sensitive tests.

Important correction: because this run used `NACC_DOCKER_SECURITY_MODE=default`,
it is a default-Docker runner sample, not a confirmed NaCC-container sample.

## NaCC Registration Evidence

A direct syscall sanity check proved that the guest kernel/OpenSBI registration
path is live:

- VM log:
  `logs/ltp_nacc_collect2_sample50_01_20260530_130937_vm_20260530_131324.log`
- QEMU log:
  `logs/ltp_nacc_collect2_sample50_01_20260530_130937_qemu_20260530_131324.log`

The direct check called syscall `256` and got:

```text
syscall256 ret=0 errno=0
```

The logs then showed:

```text
[Linux] register a new NACC process.
[Linux]: container id is 1234.
[SBI]: cid: 1234 pid: 364
[Linux]: GO BACK TO RUNC.
```

Caveat from the direct syscall check: it proves the kernel/OpenSBI
`nacc_register` path, but not whether Docker/runc can reach it under Docker's
runtime policy.

Two Docker registration smokes then clarified the policy requirement:

- Default Docker policy:
  - VM log:
    `logs/ltp_nacc_docker_register_smoke2_01_20260530_133024_vm_20260530_133424.log`
  - QEMU log:
    `logs/ltp_nacc_docker_register_smoke2_01_20260530_133024_qemu_20260530_133424.log`
  - `docker run --rm --runtime runc ubuntu:22.04 true` succeeded.
  - No fresh `[Linux] register a new NACC process` was observed.
  - Interpretation: Docker default seccomp blocks syscall `256` before it
    reaches the kernel.

- Unconfined seccomp:
  - VM log:
    `logs/ltp_nacc_docker_register_unconfined_smoke_01_20260530_134322_vm_20260530_134724.log`
  - QEMU log:
    `logs/ltp_nacc_docker_register_unconfined_smoke_01_20260530_134322_qemu_20260530_134724.log`
  - Command:
    `docker run --rm --runtime runc --security-opt seccomp=unconfined ubuntu:22.04 true`
  - Logs showed `[Linux] register a new NACC process`,
    `[SBI]: cid: ... pid: ...`, `GO BACK TO RUNC`, secure page-table activity,
    and unregister/reclaim activity.
  - Interpretation: true current NaCC container coverage requires
    `NACC_DOCKER_SECURITY_MODE=unconfined`.

## True NaCC Unconfined Probe

A two-case shell-init LTP probe was launched with unconfined seccomp:

- `NACC_DOCKER_SECURITY_MODE=unconfined`
- `NACC_LTP_INIT_MODE=shell`
- VM log:
  `logs/ltp_nacc_probe_unconfined_shell_01_20260530_134839_vm_20260530_140708.log`
- QEMU log:
  `logs/ltp_nacc_probe_unconfined_shell_01_20260530_134839_qemu_20260530_140708.log`

It did not complete even the first case:

```text
START idx=1/2 name=getpid01 exe=getpid01
```

There is no completed `END` line and no aggregate LTP summary for this true
NaCC run. The batch hit the outer timeout after the VM had already panicked.

The QEMU log shows registration followed by a kernel panic in the exec path:

```text
[Linux] register a new NACC process.
...
do_execveat_common pid=2568 comm=getpid01 nacc_flag=10 filename=/bin/sh
[SBI] reject Linux-origin Secure PTP store trap:
  virt=0xffffffd73ffe9ff8 phys=0x1bffe9ff8 val=0x0
Oops - store (or AMO) access fault
epc : move_page_tables+0xa24/0xdf4
Kernel panic - not syncing: Fatal exception in interrupt
```

The visible stack is:

```text
move_page_tables
relocate_vma_down
setup_arg_pages
load_elf_binary
bprm_execve
do_execveat_common
__riscv_sys_execve
do_trap_ecall_u
```

Working interpretation: in the true NaCC path, shell-init LTP reaches an exec
sequence where a NaCC-active mm has secure page-table pages, and the normal
`move_page_tables()` path performs a Linux-origin store to a secure PTP slot.
This is a blocker before any meaningful full NaCC LTP pass-rate can be
collected.

## Interpretation

The main result is now sharper:

- LTP can be driven through Docker in a per-entry container runner, provided
  the LTP testcase is not used directly as PID 1.
- Default Docker policy can produce runner samples, but it does not exercise
  the current NaCC registration path because default seccomp blocks syscall
  `256`.
- Unconfined seccomp does exercise the current NaCC registration path.
- The first true NaCC LTP probe panics before completing `getpid01`, so there is
  currently no true NaCC LTP pass-rate number.

The `sample50` numbers should not be compared directly against the 2026-05-29
full Docker baseline as a final pass-rate claim, because:

- it is only the first `50` entries;
- those entries are not representative of the full suite;
- default Docker policy naturally breaks or skips many privileged tests;
- most importantly, default seccomp means it is not true NaCC coverage.

Launching a long full true-NaCC LTP run is not useful until the exec/move-page
tables blocker is addressed or explicitly bypassed.

## Next Steps

1. Do not use default-seccomp Docker runs as NaCC evidence. They are useful only
   as Docker/LTP runner baselines.

2. For true NaCC LTP coverage, use:
   - `NACC_LTP_INIT_MODE=shell`
   - `NACC_DOCKER_SECURITY_MODE=unconfined`
   - `LTP_CASE_TIMEOUT_SECONDS=120`
   - runner: `scripts/ltp_nacc_container_init_syscalls_runner.sh`

3. Before launching a full `1506`-entry true-NaCC run, resolve or temporarily
   bypass the observed exec-path blocker:
   - panic site: `move_page_tables+0xa24/0xdf4`
   - path: `setup_arg_pages()` / `relocate_vma_down()` during exec
   - symptom: Linux-origin store to secure page-table page rejected by OpenSBI

4. Once true-NaCC LTP runs complete, compare against:
   - native Docker default: `898/1506`
   - clean `runc-origin`/`dockero`: `896/1506`
   - direct guest native: `1181/1506`

5. Classify any new regressions relative to native Docker/dockero before
   assigning them to NaCC. The expected buckets are Docker policy, missing
   helper/build dependency, timeout/cleanup artifact, unsupported feature,
   genuine syscall semantic difference, and NaCC-specific regression.
