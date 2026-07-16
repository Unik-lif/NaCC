# Workload 1 SUM-On Strict-Deny Readout

Date: 2026-05-20

Primary task packet:
`docs/workflow/tasks/active/TASK_20260520_141343_all_workloads_sum_on.md`

Related background note:
`record/20260520_sum_on_uaccess_interface_notes.md`

This note is a compact record for future code changes. It records the concrete
workload-1 SUM-on PRIVATE_DATA strict-deny answer and the boundary between
observed evidence, diagnostic instrumentation, and future interface design.

## Bottom Line

Workload 1 first hits SUM-on PRIVATE_DATA strict deny during
`sys_openat path=file_path`, in the kernel filename-copy path symbolized to
`do_strncpy_from_user` / `strncpy_from_user`.

The strict run did not print `kernel_read_done`; the VM auto command exited
`[NaCC][ssh-auto-exit] code=127` after SSH readiness and after the auto command
started. This is a valid strict-deny diagnostic failure signal, not an SSH
readiness or timeout failure.

This result answers the immediate stop-point question only. It does not define
the final explicit uaccess/syscall-buffer authorization model.

## Baseline Evidence

The earlier workload-1 baseline completed successfully under fallback/emulation:

- VM result: `kernel_read_done`
- Exit marker: `[NaCC][ssh-auto-exit] code=0`
- PRIVATE_DATA stats: `load=273 store=1249 total=1522`
- SUM split: `sum_on=1522 sum_off=0`
- Raw uaccess attribution: `uaccess_active_hits=0`
- Primary QEMU log:
  `logs/TASK_20260520_141343_sumon_w1_01_20260520_174526_qemu_20260520_174902.log`

Interpretation: this proved workload 1 exercises the SUM-on PRIVATE_DATA
surface, but it did not prove strict deny because OpenSBI still serviced the
protected accesses through fallback/emulation.

## Diagnostic Patch Shape

No existing SUM-on PRIVATE_DATA strict-deny selector was found in the current
OpenSBI mediation path. A narrow diagnostic patch was added in:

`opensbi/lib/sbi/sbi_trap_ldst.c`

The new helper is:

`nacc_private_data_strict_sumon_deny()`

Current behavior of the diagnostic patch after the 2026-05-21 correction:

- Applies only after PRIVATE_DATA PA resolution.
- Applies only to traps from S-mode with saved `mstatus.SUM=1`.
- Prints first-deny attribution, then panics in OpenSBI before M-mode
  fallback/emulation can read or write the protected page.
- Is wired into PRIVATE_DATA load, normal/AMO store, and CBO-zero handling.
- Prints one `[NACC][strict-sumon-first-deny]` attribution line.
- Prints `[NACC][strict-sumon-panic]` with the same key attribution fields as
  the fatal stop marker.
- Leaves Linux helper code, Agent code, workload commands, and broader uaccess
  or TX interfaces unchanged.

Important boundary: syscall/path/uaccess/TX fields are diagnostic attribution
only. They are not policy authority.

The patch was left uncommitted. Future work should decide whether to keep the
panic as a gated diagnostic, convert it into a real selector, commit it, or
remove it.

## Strict Run Evidence

Build:

`make opensbi`

Result: exit code 0.

Strict workload-1 command:

```sh
config/debug-batch.sh --session-name TASK_20260520_141343_sumon_w1_strict --tag-prefix TASK_20260520_141343_sumon_w1_strict --ssh-ready-timeout 420 --ssh-auto-timeout 600 --wait-after-auto 720 --cmd "docker run --security-opt seccomp=unconfined --rm busybox sh -c 'printf alpha >/dev/null; echo kernel_read_done'"
```

Primary strict logs:

- QEMU:
  `logs/TASK_20260520_141343_sumon_w1_strict_01_20260520_181720_qemu_20260520_182058.log`
- VM:
  `logs/TASK_20260520_141343_sumon_w1_strict_01_20260520_181720_vm_20260520_182058.log`

VM lines 11-14 show authenticated SSH readiness, the canonical auto command,
and `[NaCC][ssh-auto-exit] code=127`. There is no `kernel_read_done` in the
strict VM log.

QEMU lines 1852-1858 are the key excerpt. Line 1856 is the first strict deny:

```text
[NACC][strict-sumon-first-deny] access=load reason=sum_on_private_data pc=0xffffffff804d2370 ra=0xffffffff804d22fa trap_va=0x3fe77d7000 pa=0x11f1e5000 pfn=0x11f1e5 width=8 mstatus=0xa00040822 sum=1 pid=803 comm=unavailable task=0xffffffd683d93300 syscall=56 path=file_path uaccess_active=0 uaccess_direction=unknown uaccess_caller=0x0 tx_active=0 tx_api=unknown tx_direction=unknown
```

Adjacent context:

- Linux syscall context: `pid=803 comm=sh`
- User syscall: `sys_openat`
- PRIVATE_DATA path classification: `path=file_path`
- Denied access: load, width 8, `trap_va=0x3fe77d7000`,
  `pa=0x11f1e5000`, `pfn=0x11f1e5`
- Saved SUM: `sum=1`
- Raw uaccess/TX attribution: inactive or unknown

Symbolization used by log analysis:

```sh
riscv64-linux-gnu-addr2line -e riscv-linux/vmlinux -fip 0xffffffff804d2370 0xffffffff804d2372 0xffffffff804d22fa
```

Result:

- `0xffffffff804d2370` / `0xffffffff804d2372` map to
  `do_strncpy_from_user` at `linux/lib/strncpy_from_user.c:41`, inlined by
  `strncpy_from_user`.
- `0xffffffff804d22fa` maps to `strncpy_from_user` around line 120.

## Interpretation Boundary

Observed:

- SSH readiness succeeded.
- The workload auto command started.
- `kernel_read_done` was not printed.
- VM auto command exited 127.
- The first strict SUM-on deny is a PRIVATE_DATA load at
  `sys_openat path=file_path`.
- The kernel PC/RA symbolize to `do_strncpy_from_user` /
  `strncpy_from_user`.
- No kernel Oops or panic string appears in the original 2026-05-20 strict
  QEMU log because that version redirected the trap back to Linux.
- Strict aggregate stats report no mediated traps, consistent with stopping
  before the old fallback/emulation stats path.

Inferred:

- The diagnostic strict-deny patch answered the immediate stop-point question:
  workload 1 first concretely stops on the filename-copy/private-data path for
  `sys_openat`.
- The earlier visible `sys_brk path=mapping_update` context is not the first
  strict-deny stop point in this run.
- The final shell `127` is best classified as a workload-level consequence of
  strict deny after auto-run, not as a harness transport failure.

Not proven:

- The final authorization model for SUM-on PRIVATE_DATA access.
- Whether `do_strncpy_from_user` should be patched directly.
- Whether syscall/path metadata should ever be policy authority.
- Whether workloads 2-8 converge under the same shape.

## Future Modification Guidance

Do not treat this as authorization for a one-off fix in
`do_strncpy_from_user`. Treat it as evidence for a broader string-read or
syscall-filename access family that needs explicit NaCC semantics.

The next design should replace or constrain implicit OpenSBI fallback with an
explicit authorization path. Likely access families to reason about include:

- string read from user, represented here by `sys_openat path=file_path`
- bulk copy from user
- bulk copy to user
- clear or zero to user
- scalar get/put user access
- atomic or futex-style user operations

Useful diagnostic fields to preserve in future runs:

- access type and width
- MEPC/PC and RA
- trap VA, PA, and PFN
- saved `mstatus` and SUM
- syscall number/name and path category
- raw uaccess active/direction/caller
- TX active/API/direction
- pid/task/cid if available

Before broadening to workloads 2-8, decide the intended explicit semantics for
at least the workload-1 `sys_openat` filename-copy case and decide the
diagnostic patch disposition.

## 2026-05-21 Panic Correction

The first strict-deny run showed that redirect-only SUM-on denial is too weak
for diagnostics: `strncpy_from_user()` uses recoverable uaccess machinery, so
Linux converted the denied PRIVATE_DATA load into `-EFAULT`, and the shell
eventually exited 127 instead of exposing a hard first-bad point.

The OpenSBI diagnostic was corrected to panic directly inside
`nacc_private_data_strict_sumon_deny()` after printing attribution. This keeps
the important first-site evidence and prevents Linux uaccess exception-table
fixup from hiding the violation as an ordinary user-pointer fault.

Expected future artifact shape:

- QEMU log should contain `[NACC][strict-sumon-first-deny]`.
- QEMU log should then contain `[NACC][strict-sumon-panic]`.
- The first panic should still point to the same class unless earlier evidence
  changes it: `sys_openat path=file_path`, PC in `do_strncpy_from_user` /
  `strncpy_from_user`, SUM-on PRIVATE_DATA load.
- VM/harness may timeout or fail to complete after the panic; that is expected
  diagnostic behavior.
