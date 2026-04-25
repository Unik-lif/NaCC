# Human Progress Report

- Task ID: TASK_20260423_170823_manifest_register
- Task Packet: `docs/workflow/tasks/active/TASK_20260423_170823_manifest_register.md`
- Created: 2026-04-23 17:08:23 +0800
- Purpose: cumulative human-readable updates appended by coder, reviewer, and log_analyzer
- Append Rule: add a new timestamped section for each new turn; do not rewrite older entries
- Reading Hint: newest updates are appended at the end of this file

## 2026-04-23 17:37:12 +0800 Coder Update

- Changed files:
  - `linux/arch/riscv/kernel/sys_riscv.c`
  - `scripts/install_runc_manifest_register_in_vm.sh`
  - `scripts/patches/runc_manifest_register.patch`
- Why this was needed:
  - the packet needed manifest identity to attach to the real guest container/CID registration boundary instead of remaining a standalone VM-side generation artifact
  - the host worktree does not contain the guest `runc` tree, so the in-VM `runc` edit had to be preserved as a repo-tracked patch/helper rather than an undocumented guest-only change
- What changed in code:
  - `linux/arch/riscv/kernel/sys_riscv.c` now lets syscall `256` accept an optional `manifest_path + sha256 + size` payload from `runc`, copies that payload from userspace, stores it in a small Linux-side CID registry, and logs it while keeping the existing CID-only SBI registration path unchanged
  - `scripts/patches/runc_manifest_register.patch` captures the exact guest `runc` edit against `/root/riscv-docker/runc/libcontainer/standard_init_linux.go`
  - `scripts/install_runc_manifest_register_in_vm.sh` stages that patch into the guest, applies it idempotently, exports `/usr/local/go/bin` into `PATH` for the non-interactive shell, and runs `make && make install`
- What I intentionally left unchanged:
  - no host-side manifest generation path was revived
  - no OpenSBI transport was added for the full manifest payload in this slice
  - no startup audit/enforcement behavior changed
  - no Linux/OpenSBI rebuild or VM reboot was taken over in coder just to force an end-to-end proof on the live VM
- Cheap bounded sanity checks run:
  - `bash -n scripts/install_runc_manifest_register_in_vm.sh`
  - `git diff --check -- linux/arch/riscv/kernel/sys_riscv.c scripts/install_runc_manifest_register_in_vm.sh scripts/patches/runc_manifest_register.patch`
  - single-object Linux compile:
    - `make ARCH=riscv -C /home/link/NaCC/linux O=/home/link/NaCC/riscv-linux CROSS_COMPILE=/home/link/NaCC/riscv-tools/bin/riscv64-unknown-linux-gnu- arch/riscv/kernel/sys_riscv.o`
- Bounded guest-side execution evidence:
  - readiness gate log: `logs/coder/TASK_20260423_170823_manifest_register_vm_ready_20260423_172608.log`
  - guest `runc` patch/build/install log: `logs/coder/TASK_20260423_170823_manifest_register_runc_build_20260423_173008.log`
  - guest manifest-generation log: `logs/coder/TASK_20260423_170823_manifest_register_generate_20260423_173345.log`
  - host-copied guest manifest artifact: `logs/coder/TASK_20260423_170823_manifest_register_manifest_20260423_173406.json`
  - patched-`runc` smoke log: `logs/coder/TASK_20260423_170823_manifest_register_runc_smoke_20260423_173540.log`
- What the smoke proved and what it did not:
  - the guest `runc` patch applies reproducibly, builds, installs, and the installed `/usr/local/sbin/runc` contains the sentinel string `NACC_MANIFEST_PATH`
  - a real `busybox echo test` container launch still succeeds when the guest-local manifest path is passed through `-e NACC_MANIFEST_PATH=/tmp/nacc_manifest_ls.json` and a bind-mounted manifest file
  - it did not produce the new `nacc manifest register ...` kernel log yet, because the currently running VM has not been rebooted into a kernel that contains the new `linux/arch/riscv/kernel/sys_riscv.c` change
- What is intentionally deferred to reviewer / test_runner:
  - review of whether keeping the Linux->OpenSBI leg CID-only is still within packet scope
  - heavy activation proof that requires rebuilding the changed Linux component into the booted VM image and rerunning the real container launch on that new kernel
- Remaining watchpoints:
  - the repo-tracked guest patch was generated against the live guest `runc` baseline, which already carried the older `SYS_NACC_REGISTER` hook
  - the current coder smoke should be read as `patched runc installed and baseline container still works`, not as authoritative proof that the new Linux-side manifest registry path is active in the running VM yet

## 2026-04-23 18:08:38 +0800 Coder Update

- Changed files this turn:
  - `docs/workflow/tasks/active/TASK_20260423_170823_manifest_register.md`
  - `docs/workflow/tasks/reports/active/TASK_20260423_170823_manifest_register_human_report.md`
- Why this was needed:
  - the packet was already in `needs_review`, so this turn was limited to confirming the existing bounded implementation still passes cheap sanity and leaving a fresh reviewer handoff instead of widening into downstream proof work
- What changed in code:
  - no implementation files changed in this turn
  - rechecked the existing bounded route in `linux/arch/riscv/kernel/sys_riscv.c`, `scripts/install_runc_manifest_register_in_vm.sh`, and `scripts/patches/runc_manifest_register.patch`; the prior coder implementation remains the active route for review
- What I intentionally left unchanged:
  - no new Linux/OpenSBI transport work was added
  - no guest `runc` behavior was changed beyond the already-landed patch
  - no heavy kernel/image rebuild, VM reboot, or full T1 activation proof was attempted in coder
- Cheap bounded sanity checks run in this turn:
  - `bash -n scripts/install_runc_manifest_register_in_vm.sh`
  - `git -C linux diff --check -- arch/riscv/kernel/sys_riscv.c`
  - `make ARCH=riscv -C /home/link/NaCC/linux O=/home/link/NaCC/riscv-linux CROSS_COMPILE=/home/link/NaCC/riscv-tools/bin/riscv64-unknown-linux-gnu- arch/riscv/kernel/sys_riscv.o`
- What is intentionally deferred to reviewer / test_runner:
  - reviewer still owns the fidelity/risk read on whether the Linux-side manifest registry and CID-only Linux->OpenSBI leg stay within packet scope
  - test_runner still owns the heavy rebuild/reboot-backed proof that the running VM emits the new `nacc manifest register ...` evidence on a real container launch

## 2026-04-23 18:12:35 +0800 Reviewer Update

- Review verdict:
  - `approve-with-conditions`
  - `can proceed to test = yes`
- What I checked directly:
  - re-read the task packet and `docs/workflow/CURRENT_STATE.md`
  - reviewed `linux/arch/riscv/kernel/sys_riscv.c`, `scripts/patches/runc_manifest_register.patch`, `scripts/install_runc_manifest_register_in_vm.sh`, and `scripts/generate_manifest_in_vm.sh`
  - inspected `logs/coder/TASK_20260423_170823_manifest_register_vm_ready_20260423_172608.log`, `logs/coder/TASK_20260423_170823_manifest_register_generate_20260423_173345.log`, `logs/coder/TASK_20260423_170823_manifest_register_runc_build_20260423_173008.log`, and `logs/coder/TASK_20260423_170823_manifest_register_runc_smoke_20260423_173540.log`
  - reran `bash -n scripts/install_runc_manifest_register_in_vm.sh`, `git -C linux diff --check -- arch/riscv/kernel/sys_riscv.c`, and `make ARCH=riscv -C /home/link/NaCC/linux O=/home/link/NaCC/riscv-linux CROSS_COMPILE=/home/link/NaCC/riscv-tools/bin/riscv64-unknown-linux-gnu- arch/riscv/kernel/sys_riscv.o`
- Most important findings:
  - no blocking spec-fidelity drift: the patch keeps manifest authority guest-local, adds only bounded `path + sha256 + size` transport at the existing `runc -> Linux` registration boundary, and does not reopen host authority, PR4 audit, PR5 enforcement, or the Linux->OpenSBI ABI
  - the repo-tracked guest patch/helper satisfies the packet's reproducibility requirement even though the host worktree does not contain `runc`
  - the saved `docker run` smoke is not the final proof because the live VM kernel predates the Linux-side syscall change; test_runner must prove the `nacc manifest register ...` line on a rebuilt boot
  - both `runc` and Linux intentionally fall back to CID-only registration when the manifest payload is missing or invalid, so test must assert the manifest-specific Linux evidence explicitly
- Plain-English code explanation:
  - `runc` now reads `NACC_MANIFEST_PATH`, hashes that guest-local manifest file, and passes the file path, SHA-256, and size into syscall `256`
  - Linux copies and logs/stores those fields by CID after the existing SBI registration succeeds, but it does not change startup policy
- What the human should watch next:
  - make sure test_runner boots artifacts that actually contain the changed `linux/arch/riscv/kernel/sys_riscv.c`, then reruns the real busybox container path and captures the Linux-side manifest-registration evidence
  - if that evidence is still missing, the first blocker should come back instead of widening the design

## 2026-04-23 18:33:34 +0800 Log Analyzer Update

- Verdict:
  - `failed`
  - first bad point is guest patch applicability, not rebuild or VM readiness
- Dominant signal:
  - the run follows a clean `rebuild -> fresh boot -> authenticated SSH readiness` pattern and then stops immediately when `scripts/install_runc_manifest_register_in_vm.sh` reaches `/root/riscv-docker/runc` and `git apply` fails on `libcontainer/standard_init_linux.go:1`
- Key evidence:
  - `logs/test_runner/TASK_20260423_170823_manifest_register_t1_20260423_182141.log` shows `readiness_gate=passed`, then `guest_action=scripts/install_runc_manifest_register_in_vm.sh`, then `guest_pwd=/root/riscv-docker/runc`, then `error: patch failed: libcontainer/standard_init_linux.go:1`, `patch does not apply`, and `guest patch does not apply cleanly`
  - `logs/test_runner/TASK_20260423_170823_manifest_register_t1_fail_20260423_182141.log` preserves the same failure sequence with no later manifest-generation or container-launch activity
  - `logs/TASK_20260423_170823_manifest_register_t1_vm_20260423_183018.log` shows normal authenticated SSH readiness only
  - `logs/TASK_20260423_170823_manifest_register_t1_qemu_20260423_183018.log` shows normal boot to the serial login prompt and no earlier runtime stop tied to this failure
  - comparison only: `logs/coder/TASK_20260423_170823_manifest_register_runc_build_20260423_173008.log` previously showed the same helper reporting `patch already applied` and successfully rebuilding/installing `runc`
- What this means for the next decision:
  - the next owner should be `coder`
  - the repair target is narrow: make the repo-tracked guest `runc` patch/helper reproducible against the fresh rebuilt VM baseline at `/root/riscv-docker/runc/libcontainer/standard_init_linux.go`
  - this handoff does not justify widening into Linux/OpenSBI ABI or startup-policy work because the run never reached manifest generation or the container launch
- Evidence / Inference Boundary:
  - evidence: the failing run directly shows a file-specific `git apply` stop after readiness succeeded
  - evidence: the VM and QEMU pane logs do not show an earlier boot/readiness regression that explains the stop
  - inference: the most likely cause is guest `runc` baseline drift or patch-context mismatch in `libcontainer/standard_init_linux.go`
  - inference: the logs do not by themselves prove why the guest file differs or whether the patch needs regeneration versus a more robust apply/detect path
- Remaining uncertainty:
  - whether the fresh VM reset the guest `runc` tree to a cleaner baseline than the earlier coder VM, or whether another guest-side change altered `libcontainer/standard_init_linux.go` enough to invalidate the saved patch

## 2026-04-23 18:48:26 +0800 Coder Update

- Changed files this turn:
  - `scripts/install_runc_manifest_register_in_vm.sh`
  - `scripts/patches/runc_manifest_register.patch`
  - `docs/workflow/tasks/active/TASK_20260423_170823_manifest_register.md`
  - `docs/workflow/tasks/reports/active/TASK_20260423_170823_manifest_register_human_report.md`
- Why this was needed:
  - the test-runner stop was not a Linux/OpenSBI or VM-readiness regression; the repo-tracked guest `runc` patch no longer matched the fresh VM baseline and blocked the turn before manifest generation or container launch
  - direct guest evidence showed that `git show HEAD:libcontainer/standard_init_linux.go` in `/root/riscv-docker/runc` is a pristine upstream file without the older CID-only `SYS_NACC_REGISTER` hook, so the saved patch had to be rebased from the stale dirty-baseline diff to the real guest repo `HEAD`
- What changed in code:
  - `scripts/patches/runc_manifest_register.patch` is now the full upstream-to-target diff for `/root/riscv-docker/runc/libcontainer/standard_init_linux.go`, so it can forward-apply on a fresh guest repo checkout instead of assuming a preexisting CID-only hook
  - `scripts/install_runc_manifest_register_in_vm.sh` now detects an already-manifest-aware `standard_init_linux.go` via semantic markers before it falls back to `git apply`, and it prints a bounded guest diff excerpt if the file still does not match either path
  - the packet was updated for reviewer handoff with the new bounded evidence and the corrected guest-baseline explanation
- What I intentionally left unchanged:
  - `linux/arch/riscv/kernel/sys_riscv.c` and the bounded `runc -> Linux` manifest transport stayed unchanged in this turn
  - no Linux/OpenSBI ABI work, startup-policy work, heavy rebuild, VM reboot, or real container proof rerun was taken over in coder
- Cheap bounded sanity checks run this turn:
  - `bash -n scripts/install_runc_manifest_register_in_vm.sh`
  - `git diff --check -- scripts/install_runc_manifest_register_in_vm.sh scripts/patches/runc_manifest_register.patch`
  - guest pristine-baseline apply check log:
    - `logs/coder/TASK_20260423_170823_manifest_register_runc_pristine_apply_check_20260423_184617.log`
    - this shows the rebased saved patch passes `git apply --check` against a temp tree populated from `git show HEAD:libcontainer/standard_init_linux.go` inside the guest `runc` repo
  - guest helper rerun log:
    - `logs/coder/TASK_20260423_170823_manifest_register_runc_helper_repro_20260423_184530.log`
    - this shows the helper no longer stops at `git apply`; on the already-patched live guest tree it reports `patch already applied (semantic match)`, then rebuilds and reinstalls `runc`
- What is intentionally deferred to reviewer / test_runner:
  - reviewer should confirm the refreshed patch/helper repair still fits packet scope and is sufficient to hand back to `test_runner`
  - test_runner still owns the next rebuilt-kernel T1 rerun that must capture the Linux-side `nacc manifest register ...` evidence on a real guest container launch

## 2026-04-23 18:50:17 +0800 Reviewer Update

- Review verdict:
  - `approve-with-conditions`
  - `can proceed to test = yes`
- What I checked directly:
  - re-read the task packet and current handoff requirements
  - reviewed `scripts/patches/runc_manifest_register.patch` and `scripts/install_runc_manifest_register_in_vm.sh`
  - inspected `logs/coder/TASK_20260423_170823_manifest_register_runc_pristine_apply_check_20260423_184617.log`, `logs/coder/TASK_20260423_170823_manifest_register_runc_helper_repro_20260423_184530.log`, and `logs/test_runner/TASK_20260423_170823_manifest_register_t1_fail_20260423_182141.log`
  - reran `bash -n scripts/install_runc_manifest_register_in_vm.sh`
- Most important findings:
  - no blocking spec-fidelity drift: rebasing the saved patch to the guest repo's pristine `HEAD` restores the same bounded guest-side registration route instead of widening the design
  - the helper's semantic `already applied` path is narrow and specific enough to serve as an idempotence guard, not a new control path
  - the refreshed evidence repairs guest reproducibility only; the packet still needs a rebuilt-kernel run that proves Linux emits the manifest-specific registration evidence on a real guest container launch
  - a successful container exit remains insufficient proof because the route can still fall back to CID-only registration when manifest payload handling fails
- Plain-English code explanation:
  - the repo-tracked `runc` patch now matches the file shape that fresh VMs actually boot with, and the install helper now knows how to recognize that the manifest-aware hook is already present before rebuilding `runc`
- What the human should watch next:
  - make sure the next `test_runner` turn uses the existing `T1` plan and explicitly checks for Linux-side `nacc manifest register ...` evidence after the real busybox launch
  - if the helper fails again or the container runs without manifest-specific Linux evidence, route back the first blocker rather than widening the architecture in-place

## 2026-04-23 19:16:12 +0800 Log Analyzer Update

- Verdict:
  - `acceptable`
  - the packet's bounded manifest-registration proof is present; the runner stopped on an evidence-capture false negative, not on a missing runtime handoff
- Dominant signal:
  - the real guest launch registers manifest identity once on the rebuilt kernel, then continues through noisy fault/debug churn before still writing `test` and exiting cleanly
- Key evidence:
  - `logs/TASK_20260423_170823_manifest_register_t1_20260423_185636_qemu_20260423_191149.log` contains `[Linux]: nacc manifest register cid=a03c074c561a pid=947 path=/tmp/nacc_manifest_ls.json size=2809 sha256=b420226b5e26ba30789d5b38601713ff1b60198da3ea8293262b21cfff15d4d8`
  - `logs/test_runner/TASK_20260423_170823_manifest_register_manifest_20260423_185636.json` matches that exact digest and byte count (`sha256=b420226b5e26ba30789d5b38601713ff1b60198da3ea8293262b21cfff15d4d8`, `2809` bytes)
  - `logs/test_runner/TASK_20260423_170823_manifest_register_t1_20260423_185636.log` shows container output `test` and `guest_action_result=container_launch rc=0` before the runner declares `manifest_register_evidence=absent`
  - `logs/test_runner/TASK_20260423_170823_manifest_register_guest_dmesg_20260423_185636.log` starts at timestamp `246.041767`, which is later than the manifest-register event timestamp `242.502226`, so the searched artifact had already lost the proof line
  - the same guest/QEMU evidence later shows `sys_write`, `sys_exit_group`, and `reason=exit_mmap` for the confidential `/bin/echo` path under the same CID
- What this means:
  - the bounded `runc -> Linux` manifest-to-CID association path is proved for this packet
  - the runner's blocked outcome should not be read as CID-only fallback in this run
  - the remaining concern is workflow/evidence capture quality, not the implementation slice itself
- Residual uncertainty:
  - later logs still show `PRIVATE_DATA` lookup misses and repeated `SEGV_ACCERR`-tagged fault retries during `/bin/echo`; this looks suspicious as background runtime noise, but this run still reaches write and exit cleanup, so the noise is not decisive against the packet's proof target
- Evidence / Inference Boundary:
  - evidence: the manifest-register line is directly present in the QEMU pane log and matches the copied manifest artifact
  - evidence: the guest `dmesg` artifact begins after that event, so its absence there is real for that file
  - inference: the most likely reason is log-retention loss from heavy debug churn before the late `dmesg` capture, not a missing runtime registration
  - inference: a separate harness follow-on may be worthwhile if the project wants this proof to survive future high-volume debug logging without relying on manual QEMU-log inspection
- Recommended next owner:
  - `human`
- Recommended next step:
  - accept or close the packet based on the QEMU-pane proof, and only open a follow-on if you want the runner to treat QEMU pane logs or earlier `dmesg` capture as first-class manifest evidence in future turns

## 2026-04-23 22:49:19 +0800 Log Analyzer Update

- Workflow decision:
  - the human accepted the current bounded manifest-registration result as correct and asked to hand off downward to `planner`
- What changed in packet state:
  - this packet remains `done` on its technical goal
  - the next owner is now `planner`, not `human`
  - the `Next Handoff` block now asks planner to treat this packet as accepted reference material and seed the next condensed packet rather than reopening the completed transport slice
- Planner focus I wrote into the packet:
  - primary next slice: build on the proved `runc -> Linux` manifest identity handoff and define a minimal audit-only / observation packet for consuming that identity closer to the startup trust path
  - secondary optional slice: if workflow robustness still matters, treat runner evidence-capture hardening as a separate small packet instead of the main semantic follow-on
- Why this handoff is narrow:
  - this turn does not change the technical verdict from the previous log analysis
  - it only converts the now-accepted proof into a concrete downstream planning request so the next machine session does not drift back into transport rework
