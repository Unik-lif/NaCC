# Human Progress Report

- Task ID: TASK_20260423_231217_manifest_more
- Task Packet: `docs/workflow/tasks/active/TASK_20260423_231217_manifest_more.md`
- Created: 2026-04-23 23:12:17 +0800
- Purpose: cumulative human-readable updates appended by coder, reviewer, and log_analyzer
- Append Rule: add a new timestamped section for each new turn; do not rewrite older entries
- Reading Hint: newest updates are appended at the end of this file

## 2026-04-23 23:47:41 +0800 — coder

What changed:
- `linux/arch/riscv/kernel/sys_riscv.c` now extends the existing `nacc_register` syscall payload beyond manifest identity so Linux can also accept a fixed manifest-layout array from userspace. The new layout record is intentionally small: startup role (`entry` / optional `interp`), program-header index, page-aligned relative offset, page-aligned size, and raw flags. Linux stores that per CID with the existing manifest identity and, at the existing startup-coordinate handoff points (`nacc_invoke`, `nacc_exec`, `nacc_invoke_child`), emits those registered layout records through the already-landed `SBI_EXT_NACC_STARTUP_AUDIT_RANGE` path after Linux has reported runtime bases.
- `scripts/patches/runc_manifest_register.patch` now keeps `runc` as the manifest parser. The guest patch still loads manifest identity from `NACC_MANIFEST_PATH`, but it now also parses the current manifest JSON directly in `runc`, accepts only the current startup scope (`entry` plus optional `interp`), translates each `PT_LOAD` into the fixed page-aligned layout record shape, and passes that array in the existing `SYS_NACC_REGISTER` syscall.
- `scripts/install_runc_manifest_register_in_vm.sh` was updated only enough to recognize the new manifest-layout-aware guest file shape when deciding whether the repo-tracked `runc` patch is already applied.

Why this was needed:
- The packet asked for the first working end-to-end loop where `manifest.json` is analyzed before OpenSBI and a reduced monitor-oriented layout reaches OpenSBI without pushing raw JSON parsing into OpenSBI.
- The smallest route in the current tree was to reuse the already accepted `runc -> Linux` registration boundary and the already-landed Linux/OpenSBI startup-coordinate plus startup-range ABI, instead of inventing a second transport or a new OpenSBI parser.

Files carrying the change:
- `linux/arch/riscv/kernel/sys_riscv.c`
- `scripts/patches/runc_manifest_register.patch`
- `scripts/install_runc_manifest_register_in_vm.sh`

Key assumption made explicit:
- For this bounded slice, object identity inside the transported layout is reduced to the current startup-role IDs (`entry` / optional `interp`). I did not invent a richer per-object identity format because the accepted manifest generator currently emits only those startup roles and the packet did not require a broader schema here.

What I intentionally left unchanged:
- I did not add any raw JSON parsing to OpenSBI.
- I did not add a new OpenSBI-specific layout ABI; Linux reuses the existing `SBI_EXT_NACC_STARTUP_AUDIT_RANGE` carrier after runtime bases are known.
- I did not replace or remove the older fixed `/etc/nacc/startup_table.bin` path; this runtime-registered path is additive.
- I did not run heavy rebuilt-image / VM / QEMU proof locally, per packet scope.

Cheap sanity checks run:
- `bash -n scripts/install_runc_manifest_register_in_vm.sh`
- `git -C linux diff --check -- arch/riscv/kernel/sys_riscv.c`
- `git apply --stat --summary scripts/patches/runc_manifest_register.patch`
- `make ARCH=riscv -C /home/link/NaCC/linux O=/home/link/NaCC/riscv-linux CROSS_COMPILE=/home/link/NaCC/riscv-tools/bin/riscv64-unknown-linux-gnu- arch/riscv/kernel/sys_riscv.o`

Deferred to reviewer / test_runner:
- Rebuild the touched Linux image path and boot a fresh VM.
- Apply/install the repo-tracked guest `runc` patch in the VM.
- Launch a real guest container with a guest-local `manifest.json` that matches the actual startup ELF.
- Capture Linux/OpenSBI evidence of both manifest registration and the new manifest-layout dispatch into OpenSBI.

## 2026-04-23 23:52:04 +0800 — reviewer

Review verdict:
- approve-with-conditions

What I checked directly:
- Read the task packet first, then re-read `docs/workflow/CURRENT_STATE.md` and the accepted manifest-registration packet to confirm the intended control model before reviewing code.
- Reviewed the touched Linux path in `linux/arch/riscv/kernel/sys_riscv.c`, the guest `runc` patch in `scripts/patches/runc_manifest_register.patch`, the guest install helper in `scripts/install_runc_manifest_register_in_vm.sh`, and the existing startup-coordinate / startup-range consumers in `linux/arch/riscv/mm/nacc.c` and `opensbi/lib/sbi/sm/region.c`.
- Reran cheap reviewer-owned checks: `bash -n scripts/install_runc_manifest_register_in_vm.sh`, `git -C linux diff --check -- arch/riscv/kernel/sys_riscv.c`, `git apply --stat --summary scripts/patches/runc_manifest_register.patch`, and the single-object Linux build for `arch/riscv/kernel/sys_riscv.o`.

Most important findings:
- No blocking spec-fidelity drift: manifest parsing still happens in guest `runc`, Linux is still only the join point that adds runtime coordinates and forwards reduced layout facts, and OpenSBI still consumes a fixed startup-oriented view instead of raw JSON.
- Reusing the existing startup-coordinate plus `SBI_EXT_NACC_STARTUP_AUDIT_RANGE` path is acceptable for this packet. It is less invasive than inventing a parallel layout ABI, and it still gives OpenSBI an interpreted manifest-derived layout view.
- The main review-visible risks are operational: Linux keeps registrations in a fixed 32-slot per-CID table with no retire path yet, kernel-side layout validation is deliberately shallow because this is still audit-only transport, and the code can still fall back to identity-only / CID-only registration on bad manifest payloads.

Plain-English code explanation:
- The new path has `runc` read the current guest-local manifest, reduce the `entry` / optional `interp` `PT_LOAD` information into a small fixed record list, hand that list into Linux at the existing registration syscall, and then have Linux replay those records to OpenSBI only after Linux has already reported the runtime base coordinates. OpenSBI then logs the resulting interpreted startup ranges with its existing audit machinery.

What the human should watch next:
- The next `T1` run must prove both sides of the new path for the same CID: Linux `manifest layout dispatch ... source=register` evidence and OpenSBI `manifest startup audit ...` evidence.
- Treat container exit `0` as irrelevant unless those manifest-specific logs are present.
- Keep the proof on a fresh boot and preserve the QEMU/console pane log, not just a late guest `dmesg` snapshot, because early manifest-dispatch lines can scroll out under current debug volume.

## 2026-04-24 00:26:55 +0800 — log_analyzer

Run verdict:
- failed at the first guest install boundary

Dominant signal:
- the fresh-boot VM path itself looks acceptable up to readiness, then the run stops immediately in `scripts/install_runc_manifest_register_in_vm.sh` because the repo-tracked layout-aware `runc` patch does not apply to guest `libcontainer/standard_init_linux.go`

Key evidence:
- `logs/test_runner/TASK_20260423_231217_manifest_more_rerun3_20260424_001853.log` shows `vm_ready=1 auto_exit=1`, then `error: patch failed: libcontainer/standard_init_linux.go:1`, `error: libcontainer/standard_init_linux.go: patch does not apply`, and `error: guest patch does not apply cleanly`
- the same log preserves a guest diff excerpt that already contains the older manifest-identity-only additions: `crypto/sha256`, `func naccLoadManifestIdentity`, and `unix.Syscall6(... manifestSize, 0, 0)`
- saved primary/QEMU/VM artifacts for this turn contain no `manifest layout` or `startup audit` hits, so the run never reached Linux/OpenSBI manifest-layout evidence

What this means for the next decision:
- route the packet to `coder`, not `planner` or `human`
- the next repair should stay on the repo-tracked guest patch/install path and make it converge from the older identity-only guest `runc` state to the newer layout-aware state
- do not treat this turn as evidence of a Linux/OpenSBI runtime failure, because the run stopped before manifest generation or container launch

What remains uncertain:
- the logs prove the guest file is on the older identity-only shape, but they do not prove why; stale guest state versus another guest-tree divergence is still inference
- the repo helper mismatch is the best-fit cause from the saved evidence plus repo state, but it still needs coder confirmation in the actual fix

## 2026-04-24 00:36:18 +0800 — coder

What changed:
- `scripts/install_runc_manifest_register_in_vm.sh` now has a second semantic detector for the exact older manifest-identity-only `libcontainer/standard_init_linux.go` shape seen in the saved `T1` failure (`naccLoadManifestIdentity`, `io.Copy(...)`, and `unix.Syscall6(... manifestSize, 0, 0)` without `naccLoadManifestLayout`).
- When that legacy shape is present, the guest helper no longer stops at `git apply`. Instead it materializes `HEAD:libcontainer/standard_init_linux.go` into a temp directory, applies the existing repo-tracked full patch there, verifies the resulting file now contains the layout-aware markers, and copies that reconstructed file back into the guest worktree before the existing `gofmt`, `make`, and `make install` steps.
- The clean-tree path and the already-applied semantic-match path were left in place, so the helper still supports a pristine guest tree and an already-upgraded guest tree with the same repo-tracked patch artifact.

Why this was needed:
- The decisive `T1` rerun failed before manifest generation or container launch because the guest `runc` worktree already carried the older identity-only hook shape, so the repo-tracked full layout-aware patch no longer applied directly to that dirty file.
- The packet explicitly asked for a repair to the repo-tracked guest patch/install flow, not a Linux/OpenSBI redesign. Reconstructing the desired guest file from Git `HEAD` plus the existing full patch keeps the control model unchanged and fixes only the applicability boundary that actually failed.

Files carrying the change:
- `scripts/install_runc_manifest_register_in_vm.sh`

Key assumption made explicit:
- This repair assumes `/root/riscv-docker/runc` still has the pristine upstream `HEAD:libcontainer/standard_init_linux.go` available in Git history and that the recorded older identity-only hook is a worktree edit on top of that `HEAD`. I wrote that assumption back into the packet's `Key Assumptions` section rather than leaving it implicit in the installer logic.

What I intentionally left unchanged:
- I did not change `scripts/patches/runc_manifest_register.patch`; it remains the single repo-tracked source of truth for the desired layout-aware guest `runc` file shape.
- I did not change Linux or OpenSBI code, their ABI, or any manifest-layout semantics.
- I did not add a second patch format, a new guest-side parser path, or any heavy local VM proof loop.

Cheap sanity checks run:
- `bash -n scripts/install_runc_manifest_register_in_vm.sh`
- A bounded log-derived detector check against `logs/test_runner/TASK_20260423_231217_manifest_more_rerun3_20260424_001853.log` confirmed the new legacy matcher does recognize the exact saved older identity-only guest shape (`LEGACY_SHAPE_MATCHED`).
- A bounded temp-repo model check confirmed the chosen upgrade method works as intended at the mechanism level: rebuild a file from `git show HEAD:file`, apply the full patch there, and replace the dirty worktree file (`HEAD_RECONSTRUCTION_OK`).

Deferred to reviewer / test_runner:
- Reviewer should confirm the new guest-side HEAD-reconstruction route is an acceptable packet-scoped repair and that the recorded assumption about guest `HEAD` is explicit enough.
- Test runner should do the real guest proof on a fresh boot and look specifically for Linux `nacc manifest layout ... source=register` and OpenSBI `manifest startup audit ...` evidence after guest `runc` install succeeds.

## 2026-04-24 00:40:33 +0800 — reviewer

Review verdict:
- approve-with-conditions

What I checked directly:
- Read the task packet first, then re-read `docs/workflow/CURRENT_STATE.md`, the repaired `scripts/install_runc_manifest_register_in_vm.sh`, the repo patch artifact `scripts/patches/runc_manifest_register.patch`, and the saved failing runner log `logs/test_runner/TASK_20260423_231217_manifest_more_rerun3_20260424_001853.log`.
- Reran bounded reviewer-owned checks: `bash -n scripts/install_runc_manifest_register_in_vm.sh` and `git apply --stat --summary scripts/patches/runc_manifest_register.patch`.
- Matched the saved failure log directly against the new legacy-detector strings to verify the repair is targeting the recorded identity-only guest state rather than inventing a broader merge path.

Most important findings:
- No blocking spec-fidelity drift: this is still a script-only repair to the guest install boundary, and it leaves the already accepted `runc -> Linux -> OpenSBI` manifest-layout route unchanged.
- The repair stays minimally invasive: it keeps the full repo patch as the only source of truth for the desired guest file, reconstructs from guest Git `HEAD`, and verifies the resulting file has the layout-aware markers before copying it back.
- The main remaining risk is bounded and operational: the legacy detector is signature-based, so the fresh-boot rerun should treat any third guest file shape as a new blocker instead of broadening the installer logic again.

Plain-English code explanation:
- If guest `runc` is already on the older identity-only hook, the installer now rebuilds `libcontainer/standard_init_linux.go` from guest Git `HEAD` plus the same full repo patch, then builds and installs `runc`. It no longer assumes the full layout-aware patch can apply directly to that older dirty file.

What the human should watch next:
- The next `T1` rerun should record which installer branch fired: `patch applied`, `patch already applied (semantic match)`, or `upgraded legacy identity-only patch via HEAD reconstruction`.
- A pass still requires manifest-specific Linux `nacc manifest layout ... source=register` / `manifest layout dispatch ...` evidence and OpenSBI `manifest startup audit ...` evidence for the same run; container exit alone is still not sufficient.
- If the installer fails again, save the new diff excerpt and treat it as a new guest-file-shape mismatch until proved otherwise, not as a Linux/OpenSBI runtime regression.

## 2026-04-24 01:11:56 +0800 — log_analyzer

Run verdict:
- failed at the HEAD-reconstruction verification gate inside the guest `runc` installer

Dominant signal:
- `rerun5` boots and reaches authenticated SSH cleanly, then `scripts/install_runc_manifest_register_in_vm.sh` exits on `error: reconstructed guest runc file does not match expected layout-aware shape` before any `runc` build/install or manifest-transport activity

Key evidence:
- primary log `logs/test_runner/TASK_20260423_231217_manifest_more_rerun5_20260424_010151.log` shows `vm_ready=1 auto_exit=1`, then the installer error, then `guest_action_result=scripts/install_runc_manifest_register_in_vm.sh rc=1`
- the same log records `linux_manifest_evidence=0`, `opensbi_manifest_evidence=0`, and `stop_reason=install_runc_failed`
- repo code makes that error string specific to `upgrade_guest_runc_manifest_patch_from_head()` after `HEAD + patch` reconstruction fails the helper's layout-aware semantic check, before copy-back, `gofmt`, `make`, or `make install`
- the fail snapshot still names a manifest-artifact path, but `logs/test_runner/TASK_20260423_231217_manifest_more_manifest_20260424_010151.json` is absent, and quick scans of guest dmesg plus QEMU/VM pane logs show no `manifest layout`, `startup audit`, `nacc manifest`, or container-launch evidence

What this means for the next decision:
- hand back to `coder`
- keep the repair inside `scripts/install_runc_manifest_register_in_vm.sh` or the repo-tracked guest patch/install path
- do not interpret this run as a Linux/OpenSBI manifest-transport regression, because the guest installer never reached manifest generation or container launch

What remains uncertain:
- the decisive boundary is clear, but the exact mismatch inside the reconstructed guest file is still unknown because the helper logs only the semantic-check failure, not the failed markers or reconstructed diff
- likely causes are guest `HEAD` drift or a third `standard_init_linux.go` shape outside the helper's current assumptions, but that is inference until the installer logs the mismatch directly

## 2026-04-24 01:22:59 +0800 — coder

What changed:
- `scripts/install_runc_manifest_register_in_vm.sh` now treats the layout-aware guest `runc` file shape as a structural marker set instead of requiring the exact whitespace-sensitive const line `naccManifestEnv = "NACC_MANIFEST_PATH"`.
- The helper now logs `installer_path=...` for each decision branch (`already_applied_reverse_check`, `semantic_match`, `legacy_head_reconstruction`, `clean_apply`, `apply_failed`) so the next rerun shows which install path actually fired.
- If `upgrade_guest_runc_manifest_patch_from_head()` still fails after reconstructing `HEAD + patch`, the helper now logs guest `HEAD` commit/blob ids, per-marker presence for `reconstructed`, `head`, and `worktree`, plus bounded `diff -u` excerpts against both `HEAD` and the live worktree before stopping.

Why this was needed:
- A bounded local check against `scripts/patches/runc_manifest_register.patch` showed the old semantic probe could false-negative on the layout-aware file purely because the full Go const block aligns `NACC_MANIFEST_PATH` differently than the older single-space matcher expected.
- That made the rerun5 gate likely a helper-probe problem rather than proof that `HEAD + patch` produced a semantically different file, so the smallest packet-faithful repair was to fix the probe and improve the diagnostics before asking `test_runner` to repeat the fresh-boot path.

Files carrying the change:
- `scripts/install_runc_manifest_register_in_vm.sh`
- `docs/workflow/tasks/active/TASK_20260423_231217_manifest_more.md`
- `docs/workflow/tasks/reports/active/TASK_20260423_231217_manifest_more_human_report.md`

What I intentionally left unchanged:
- I did not change `scripts/patches/runc_manifest_register.patch`; it remains the single source of truth for the desired layout-aware guest file.
- I did not change Linux or OpenSBI code, their ABI, or any manifest transport / startup-audit behavior.
- I did not run the heavy rebuilt-image or VM proof loop; that still belongs to reviewer / test_runner for this slice.

Cheap sanity checks run:
- `bash -n scripts/install_runc_manifest_register_in_vm.sh`
- A bounded marker-alignment check against the repo patch confirmed the new structural probe matches the saved layout-aware artifact (`PATCH_MARKERS_OK`).

Deferred to reviewer / test_runner:
- Reviewer should confirm the script-only repair is still packet-scoped and that the new diagnostics are precise enough if a third guest-tree shape still appears.
- Test runner should rerun the fresh-boot `T1` path and check either that the installer now passes beyond the old reconstruction gate or that the new marker/diff logging captures the exact remaining guest-tree mismatch.

## 2026-04-24 01:29:34 +0800 — reviewer

Review verdict:
- approve-with-conditions

What I checked directly:
- Read the task packet first, then re-read `docs/workflow/CURRENT_STATE.md`, the current `scripts/install_runc_manifest_register_in_vm.sh`, the repo patch artifact `scripts/patches/runc_manifest_register.patch`, and the saved `rerun3` / `rerun5` runner logs.
- Reran bounded reviewer-owned checks: `bash -n scripts/install_runc_manifest_register_in_vm.sh` and `git apply --stat --summary scripts/patches/runc_manifest_register.patch`.
- Verified two specific claims from artifacts instead of taking the coder summary on faith: the repo patch really does use aligned const-block spacing for `NACC_MANIFEST_PATH`, and the saved legacy failure still matches the intended identity-only marker set without any `naccLoadManifestLayout` marker.

Most important findings:
- No blocking spec-fidelity drift. The repair stays entirely inside the guest `runc` installer path and does not change the accepted `runc -> Linux -> OpenSBI` control model or transport semantics.
- The new layout-aware semantic probe is materially better scoped than the old one. It removes the known false-negative on the aligned const block by matching a small structural marker set that is present in the repo-tracked full patch, not by inventing a second guest patch or a broader merge path.
- The new breadcrumbs and bounded reconstruction diagnostics are useful and still packet-faithful. If the guest tree presents a third shape again, the next rerun should now show the exact installer branch, guest `HEAD` ids, marker presence, and short diffs instead of stopping on an opaque semantic-check failure.
- Residual risk is still bounded to guest-tree-shape assumptions, not to Linux/OpenSBI transport. A pass still requires manifest-specific Linux `source=register` / dispatch evidence and OpenSBI `manifest startup audit ...` evidence from the same run.

Plain-English code explanation:
- The installer now decides whether the guest already has the layout-aware `runc` hook by checking for a handful of stable code markers instead of one spacing-sensitive const line. If reconstructing `HEAD + patch` still fails later, it prints which path it took and enough short marker/diff output to show exactly how the guest file differs.

What the human should watch next:
- The next fresh-boot `T1` rerun should record the exact `installer_path=...` line.
- If guest install succeeds, do not accept container exit alone; require Linux manifest-layout evidence and OpenSBI startup-audit evidence from the same run.
- If guest install fails again, preserve the new marker-state and diff excerpts as the decisive boundary and hand that back to `coder` without reframing it as a Linux/OpenSBI regression.

## 2026-04-24 02:19:09 +0800 — log_analyzer

Run verdict:
- acceptable for the packet proof target

Dominant signal:
- `rerun9` is a real end-to-end success for this slice. The guest installer succeeds, manifest generation/export succeeds, the confidential container prints `test` and exits `0`, and the preserved QEMU pane log contains the full Linux `source=register` manifest-layout transport plus the matching four OpenSBI `manifest startup audit match` lines for the same CID.

Key evidence:
- `logs/test_runner/TASK_20260423_231217_manifest_more_rerun9_20260424_015438.log` shows `vm_ready=1 auto_exit=1`, `installer_path=legacy_head_reconstruction`, successful manifest generation/copy-out, `docker run ... busybox echo test`, printed output `test`, and container `rc=0`.
- `logs/TASK_20260423_231217_manifest_more_rerun9_20260424_015438_qemu_20260424_020658.log` contains the Linux proof lines the runner summary missed:
  - `nacc manifest register cid=55f3a460174e ... size=2809 sha256=548bb061ed0e81669c9bd3dc97ad43fe35d7a5d04f89c08d49e60ce6cd49c0ef layout_records=4`
  - four Linux `nacc manifest layout ...` records
  - `manifest layout dispatch source=register ... path=/tmp/nacc_manifest_ls.json records=4`
  - four matching OpenSBI `manifest startup audit match ...` lines for `entry phdr=3`, `entry phdr=4`, `interp phdr=1`, and `interp phdr=2`
- `logs/test_runner/TASK_20260423_231217_manifest_more_manifest_20260424_015438.json` hashes to `548bb061ed0e81669c9bd3dc97ad43fe35d7a5d04f89c08d49e60ce6cd49c0ef` and is `2809` bytes, exactly matching the Linux registration line.
- `logs/test_runner/TASK_20260423_231217_manifest_more_guest_dmesg_20260424_015438.log` begins only at timestamp `639.116640`, while the decisive Linux manifest lines in the QEMU pane occur at `635.003410` through `636.491483`.

What this means for the next decision:
- next hop should be `human`, not `coder` or `planner`
- this packet's semantic goal is already proved; the runner summary was a false negative caused by the late guest `dmesg` artifact boundary
- if workflow robustness still matters, split runner evidence-capture hardening into a separate task instead of rerunning or reopening this packet

What remains uncertain:
- the only remaining uncertainty is operational: whether the runner should preserve earlier Linux evidence more reliably in future runs
- this turn does not show a Linux/OpenSBI transport gap
