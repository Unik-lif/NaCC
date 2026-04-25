# Task Packet

- Task ID: TASK_20260423_170823_manifest_register
- Created: 2026-04-23 17:08:23 +0800
- Priority: P0
- Lane: A
- Packet Type: execution
- Owner Role: planner
- Status: done
- Goal: Establish a bounded in-VM manifest-to-CID registration path on a real guest container launch, so a guest-generated or guest-local `manifest.json` is attached to the live container registration flow instead of existing only as a standalone SSH proof artifact.
- Critical Intent: Keep the accepted VM-first manifest semantics and move one step closer to the real trust path by attaching manifest identity at the same in-guest `runc` registration boundary where the container CID is already handed into the system. This slice is transport/association only. It must not reopen host-side manifest generation, and it must not silently widen into PR4 audit or PR5 enforcement.
- Preferred Shape: Reuse the accepted guest-side manifest generation route from `docs/workflow/tasks/active/TASK_20260423_115900_fix_manifest.md`, then add the smallest in-guest `runc` handoff near `/root/riscv-docker/runc/libcontainer/standard_init_linux.go` at the existing final registration syscall path. First choice is to have `runc` consume a caller-provided guest-local manifest path, compute a bounded manifest-identity payload for that file (default: path + SHA-256 + size), and extend the existing registration syscall path only enough to log/store that payload next to CID. Prefer a repo-tracked orchestration/helper or repo-tracked patch artifact that can be copied into the guest over ad hoc one-off guest edits with no preserved diff. Validation should use the repo-owned readiness gate `make vm VM_AUTO_CMD='...'` and a real guest container launch, not a host-only dry run.
- Disallowed Shape: Do not go back to host-generated manifest authority. Do not reopen the archived PR4C4 host-closure staging route as the primary next slice. Do not parse the full manifest schema in multiple places this turn if a bounded manifest-identity handoff is enough. Do not change startup leaf-tag decisions, `nacc.manifest_mode`, or startup audit/enforcement behavior. Do not assume the host worktree contains `riscv-docker/runc`. Do not treat SCP copy-out as a new trust stage. Do not leave the only meaningful code change stranded inside the guest with no repo-tracked helper, patch, or preserved diff.
- Allowed Freedom: Coder may add a small repo-side helper, guest apply-script, or repo-tracked patch file to make the in-guest `runc` edit reproducible. Coder may extend the existing Linux/OpenSBI registration syscall path with bounded manifest metadata fields if needed, as long as the new data is logging-only / registration-only and does not yet affect startup policy. For the T1 proof, coder may choose a bounded test manifest location inside the guest and a small real container workload, as long as the manifest is generated and consumed inside the guest and the container launch is real.
- Scope: the in-guest `runc` registration hook, the smallest Linux/OpenSBI plumbing needed to accept bounded manifest identity metadata alongside CID, repo-side orchestration/proof helpers, and a runner-reproducible T1 proof that a real guest container launch registers manifest identity from inside the VM. Full manifest parsing inside Linux/OpenSBI, startup-table regeneration, PR4 audit revalidation, and PR5 enforcement are out of scope.
- Constraints:
  - Treat `docs/workflow/tasks/active/TASK_20260423_115900_fix_manifest.md` as accepted context, not as an open proof target.
  - Use the repo-owned readiness gate `VM_SSH_READY_TIMEOUT_SECONDS=180 make vm VM_AUTO_CMD='...'` before any guest SSH orchestration.
  - Treat host-side copy-out of guest artifacts as evidence export only, not as a second semantic stage.
  - Keep the next proof aligned to a real guest container launch; prefer the ordinary passing baseline command family over synthetic non-container exec unless a concrete blocker forces earlier stop.
  - If the in-guest `runc` tree or build/install path diverges from the human-provided note, stop at the first concrete blocker and preserve it instead of improvising a different runtime architecture.
  - If the existing registration syscall cannot cheaply carry the chosen bounded manifest-identity payload, stop and record that ABI blocker before widening to full manifest parsing or larger ad hoc transport.
- Open Semantic Questions:
  - Is the smallest useful handoff payload `manifest_path + sha256 + size`, or does the current registration ABI make a different bounded payload materially cheaper? Default route: `manifest_path + sha256 + size`; do not silently widen beyond that without a concrete blocker.
  - For T1, where should the manifest live at container-start time: a disposable guest-local test path passed into the launch flow, or a bundle-local path derived from the container rootfs? Default route: use the smallest disposable guest-local path that `runc` can consume reproducibly; record any reason the real bundle path is required.
- Human Concern: The repaired VM-first generator proved guest-local ELF/interpreter resolution, but the project still lacks a real container-lifecycle handoff that associates a manifest with the CID/startup path. The next slice should close that gap without reopening the old host-side validation drift or prematurely widening into full audit/enforcement.
- Key Assumptions:
  - The VM-first manifest generation proof in `docs/workflow/tasks/active/TASK_20260423_115900_fix_manifest.md` is accepted and should not be re-litigated.
  - The ordinary container baseline still works on the current tree, so the next failure should be treated as a manifest-registration-path issue until evidence shows otherwise.
  - The candidate in-guest hook point `/root/riscv-docker/runc/libcontainer/standard_init_linux.go` and the guest-side `make && make install` activation step come from the current packet's human workflow notes; they are treated as working assumptions for the next coder turn, not reverified facts from this planning turn.
  - A bounded manifest-identity handoff is enough for this slice; full manifest semantic consumption may remain a later packet.
  - For this slice, the full `manifest_path + sha256 + size` payload is captured and stored at the `runc -> Linux` syscall boundary. The existing Linux->OpenSBI leg remains CID-only because widening that scalar SBI handoff to carry a full path string would require a new transport mechanism that is outside this packet's least-invasive scope.
- Evidence / Inference Boundary:
  - Evidence from `docs/workflow/tasks/active/TASK_20260423_115900_fix_manifest.md`: guest-side manifest generation is now proved with the repo-owned SSH readiness gate, guest-local ELF/interpreter resolution, and matching host/guest manifest hash export.
  - Evidence from `docs/workflow/CURRENT_STATE.md`: the intended broader phase is still Phase 2 minimal manifest-driven startup sealing, and the archived manifest MVP packet should not be resumed as the live source of truth.
  - Evidence from the current packet's follow-on workflow notes: if manifest consumption moves into `runc`, the first place to inspect is `/root/riscv-docker/runc/libcontainer/standard_init_linux.go` near the final registration syscall path, and activation likely requires in-guest `make && make install`.
  - Relevance note: `docs/workflow/NEXT_STEPS.md` still carries the generic pending item to seed a fresh condensed Phase 2 / PR4 follow-on packet. This packet is the concrete runtime-aligned continuation for that broad item; the background file is not being normalized in this turn.
  - Inference in this planner turn: the smallest next runtime-aligned slice is to attach bounded manifest identity at the existing in-guest CID registration boundary before reviving broader PR4 audit or PR5 enforcement work.
  - Not claimed as fact: that the current registration ABI already has room for the preferred payload, or that the guest `runc` tree exactly matches the remembered path. Those are next-turn coder execution facts.
  - Directly observed in this coder turn: the guest `runc` tree exists at `/root/riscv-docker/runc`, and the guest build/install path `make && make install` works once the non-interactive helper exports `/usr/local/go/bin` into `PATH`.
  - Directly observed in this coder turn: `git show HEAD:libcontainer/standard_init_linux.go` inside the guest `runc` repo is a pristine upstream baseline without the older CID-only `SYS_NACC_REGISTER` hook; the failing repo-tracked patch had instead been generated against a previously dirty working tree, which explains the fresh-VM `patch failed: libcontainer/standard_init_linux.go:1` stop.
  - Directly observed in this coder turn: the installed guest `/usr/local/sbin/runc` contains the sentinel string `NACC_MANIFEST_PATH`, and a real `busybox echo test` container launch still succeeds when the manifest path is passed through `-e NACC_MANIFEST_PATH=...` plus a bind-mounted guest-local manifest file.
  - Directly observed in this coder turn: no in-guest kernel log for `nacc manifest register ...` appeared from the live VM smoke because the running VM was not rebooted into a kernel containing the new `linux/arch/riscv/kernel/sys_riscv.c` change. Activating that Linux-side log/store path requires the heavy kernel/image rebuild plus reboot that this coder turn intentionally deferred to reviewer/test_runner.
- Reconciliation Required: no
- Post-Run Analysis Required: yes
- Human Checkpoint Required: no
- Definition Of Done: a real guest container launch reaches the existing registration handoff and logs/stores bounded manifest identity (at minimum manifest path, digest, and size, or a cheaper equivalent justified from the current ABI) alongside CID from inside the guest runtime. The manifest used in that proof is guest-generated or guest-local under the accepted VM-first flow. Any required repo-side helper or patch artifact exists in the host workspace so the guest-side `runc` change is reproducible. No startup audit/enforcement behavior changes are introduced.
- Related State:
  - `docs/workflow/CURRENT_STATE.md`
  - `docs/workflow/NEXT_STEPS.md`
- Related Ticket / Plan:
  - `docs/workflow/tasks/active/TASK_20260423_115900_fix_manifest.md`
  - `docs/workflow/tasks/completed/TASK_20260421_004333_manifest_mvp.md`
- Branch / Worktree: `main`
- Validation Tier: `T1`

## Reference Values

- Priority: `P0` / `P1` / `P2` / `P3`
- Lane: `A` / `B` / `C`
- Packet Type: `execution` / `planning` / `analysis`
- Owner Role: `human` / `planner` / `coder` / `reviewer` / `test_runner` / `log_analyzer`
- Status: `draft` / `in_progress` / `needs_review` / `changes_requested` / `needs_test` / `needs_analysis` / `test_failed` / `blocked` / `done`
- Validation Tier: `T0` / `T1` / `T2` / `T3`
- Reconciliation Required: `yes` / `no`
- Post-Run Analysis Required: `yes` / `no`
- Human Checkpoint Required: `yes` / `no`

## Required Artifacts

- Patch or commit: repo-side helper(s) and any Linux/OpenSBI patch needed for the bounded handoff. If guest `runc` is edited, preserve the exact change as a repo-tracked patch file or scripted apply helper, and name the in-guest touched file path explicitly in the packet result.
- Minimal compile result: `bash -n` or `python3 -m py_compile` for repo helper changes as applicable; if Linux/OpenSBI is touched, rebuild only the changed components; if guest `runc` is touched, preserve the in-guest `make && make install` log.
- Test command or batch plan: bring the guest to authenticated SSH readiness via `VM_SSH_READY_TIMEOUT_SECONDS=180 make vm VM_AUTO_CMD='true'`; apply the repo-tracked `runc` change in the guest and rebuild/install `runc`; generate or stage a guest-local manifest for the bounded container payload; run a real bounded container command (prefer the existing busybox smoke family); and capture evidence that CID registration now includes the bounded manifest-identity payload. If the runtime handoff never reaches the new log/store point, stop at the first blocker.
- Primary log path: `logs/test_runner/TASK_20260423_170823_manifest_register_t1_<timestamp>.log`
- Log path if validation fails: `logs/test_runner/TASK_20260423_170823_manifest_register_*_fail_<timestamp>.log`

## Latest Summary

- The current active packet `TASK_20260423_115900_fix_manifest` proved the VM-first manifest-generation path and should now be treated as accepted closeout evidence rather than an active proof target.
- The next gap is runtime association, not generation: manifest identity is still not attached to the live guest container/CID registration path.
- This packet deliberately does not revive the archived host-closure PR4 validation route as the default next slice. Runtime alignment wins over reopening that route history.
- The chosen next step is the smallest runtime-aligned slice: bounded manifest-identity handoff at the in-guest `runc` registration boundary, with no startup audit or enforcement change.
- Coder implemented the bounded Linux-side handoff route: `linux/arch/riscv/kernel/sys_riscv.c` now accepts optional manifest path + SHA-256 + size on syscall `256`, stores/logs that payload per CID in a small Linux-side registry, and keeps the existing Linux->OpenSBI CID registration unchanged.
- Coder added repo-tracked guest reproducibility artifacts: `scripts/install_runc_manifest_register_in_vm.sh` plus `scripts/patches/runc_manifest_register.patch`, which apply the manifest-path-aware `runc` change to `/root/riscv-docker/runc/libcontainer/standard_init_linux.go` and rebuild/install `runc` inside the VM.
- Coder preserved bounded execution evidence: the repo-owned readiness gate log is `logs/coder/TASK_20260423_170823_manifest_register_vm_ready_20260423_172608.log`; the guest `runc` build/install log is `logs/coder/TASK_20260423_170823_manifest_register_runc_build_20260423_173008.log`; the guest manifest-generation log is `logs/coder/TASK_20260423_170823_manifest_register_generate_20260423_173345.log`; the host-copied manifest artifact is `logs/coder/TASK_20260423_170823_manifest_register_manifest_20260423_173406.json`; and the patched-`runc` container smoke log is `logs/coder/TASK_20260423_170823_manifest_register_runc_smoke_20260423_173540.log`.
- Coder stopped before a full end-to-end manifest-registration proof because the running VM still uses a pre-change kernel. Demonstrating the new Linux-side `nacc manifest register ...` log/store path now requires the heavy kernel/image rebuild plus reboot that the packet workflow assigns downstream rather than silently taking over in coder.
- 2026-04-23 coder refresh reran bounded sanity on the landed route: `bash -n scripts/install_runc_manifest_register_in_vm.sh`, `git -C linux diff --check -- arch/riscv/kernel/sys_riscv.c`, and the single-object `sys_riscv.o` build all passed. No additional implementation change was needed, so the packet remains reviewer-ready with the heavy rebuild/reboot proof still deferred downstream.
- 2026-04-23 reviewer accepted the bounded route for T1 handoff: no blocking fidelity drift was found in the Linux-side store/log design or the repo-tracked guest `runc` helper, keeping the Linux->OpenSBI leg CID-only is acceptable for this packet, and the remaining gap is runner-owned rebuild/reboot activation of the new Linux-side `nacc manifest register ...` evidence.
- 2026-04-23 test_runner rebuilt the changed image path with `make linux-update` and `make agent-update`, booted a fresh debug VM, and passed the `VM_AUTO_CMD='true'` SSH readiness gate on the rebuilt image. The run then stopped at the first decisive blocker because `scripts/install_runc_manifest_register_in_vm.sh` reported `patch failed: libcontainer/standard_init_linux.go:1` and `guest patch does not apply cleanly` inside `/root/riscv-docker/runc`, so manifest generation and the real container launch were not run in this T1 turn. Primary runner log: `logs/test_runner/TASK_20260423_170823_manifest_register_t1_20260423_182141.log`; captured pane logs: `logs/TASK_20260423_170823_manifest_register_t1_qemu_20260423_183018.log` and `logs/TASK_20260423_170823_manifest_register_t1_vm_20260423_183018.log`.
- 2026-04-23 log_analyzer classified that stop as a failed guest-`runc` patch applicability turn, not a rebuild/boot/readiness regression: the runner reached `guest_pwd=/root/riscv-docker/runc` after the SSH gate, then failed immediately on `git apply` for `/root/riscv-docker/runc/libcontainer/standard_init_linux.go`. The VM/QEMU pane logs only show normal boot/readiness, so the next repair stays on the repo-tracked guest patch/helper path.
- 2026-04-23 coder repaired that guest reproducibility gap without widening the route: `scripts/patches/runc_manifest_register.patch` is now rebased to the guest repo's pristine `HEAD:libcontainer/standard_init_linux.go` so it can forward-apply on a fresh VM, and `scripts/install_runc_manifest_register_in_vm.sh` now treats a manifest-aware file as `already applied` via semantic markers before it falls back to `git apply`. Fresh bounded evidence: `logs/coder/TASK_20260423_170823_manifest_register_runc_pristine_apply_check_20260423_184617.log` proves the saved patch passes `git apply --check` against the guest repo's pristine `HEAD` file shape, and `logs/coder/TASK_20260423_170823_manifest_register_runc_helper_repro_20260423_184530.log` proves the helper reruns successfully on an already-patched guest tree through build/install.
- 2026-04-23 reviewer rechecked the refreshed guest reproducibility repair and found no blocking fidelity drift: rebasing the saved patch to the guest repo's pristine `HEAD` restores the same bounded `runc -> Linux` manifest-registration route rather than widening it, and the helper's semantic `already applied` path is a narrow idempotence guard rather than a new control path. The packet is approved to return to `test_runner` for the rebuilt-kernel activation proof under the existing `T1` plan.
- 2026-04-23 test_runner reran the approved `T1` plan on the rebuilt image path: `make linux-update` and `make agent-update` both completed, a fresh debug VM passed the `VM_AUTO_CMD='true'` SSH readiness gate, `scripts/install_runc_manifest_register_in_vm.sh` completed, `scripts/generate_manifest_in_vm.sh -o /tmp/nacc_manifest_ls.json /usr/bin/ls` completed, the manifest artifact was copied out to `logs/test_runner/TASK_20260423_170823_manifest_register_manifest_20260423_185636.json`, and the real busybox container launch exited `0`. The runner then captured guest dmesg to `logs/test_runner/TASK_20260423_170823_manifest_register_guest_dmesg_20260423_185636.log`, but the artifact did not contain any `nacc manifest register` line, so this turn stopped at the missing Linux-side manifest evidence boundary and now routes to `log_analyzer`. Primary runner log: `logs/test_runner/TASK_20260423_170823_manifest_register_t1_20260423_185636.log`; pane logs: `logs/TASK_20260423_170823_manifest_register_t1_20260423_185636_qemu_20260423_191149.log` and `logs/TASK_20260423_170823_manifest_register_t1_20260423_185636_vm_20260423_191149.log`; failure snapshot: `logs/test_runner/TASK_20260423_170823_manifest_register_t1_fail_20260423_185636.log`.
- 2026-04-23 log_analyzer reduced the latest `T1` rerun and found that the rebuilt-kernel manifest-registration proof is actually present in the QEMU pane log, not absent from the run. `logs/TASK_20260423_170823_manifest_register_t1_20260423_185636_qemu_20260423_191149.log` contains `[Linux]: nacc manifest register cid=a03c074c561a pid=947 path=/tmp/nacc_manifest_ls.json size=2809 sha256=b420226b5e26ba30789d5b38601713ff1b60198da3ea8293262b21cfff15d4d8`, and the copied manifest artifact matches that exact digest and byte count. The runner's `missing_manifest_register_evidence` stop is therefore an evidence-capture false negative caused by relying on a late guest `dmesg` snapshot whose first preserved line is already at timestamp `246.041767`, after the manifest-register event at `242.502226`. The run still shows noisy `PRIVATE_DATA` / `SEGV_ACCERR` debug churn later in `/bin/echo`, but the same artifacts also show `test`, `sys_write`, `sys_exit_group`, and `exit_mmap`, so that residual noise does not negate the packet's bounded manifest-registration proof.
- 2026-04-23 human accepted the bounded transport proof as correct and asked to continue downward via `planner` rather than reopening this packet. The next machine step should therefore treat this packet as done reference material and seed the next condensed packet from the now-proved `runc -> Linux` manifest-identity handoff.

## Next Handoff

- Next owner: planner
- Trigger: the current packet is accepted as done on the strength of the QEMU-pane manifest-registration proof, and the human wants downstream work to continue without reopening this bounded transport slice.
- Exact artifact to read first: `docs/workflow/tasks/active/TASK_20260423_170823_manifest_register.md`, then `logs/TASK_20260423_170823_manifest_register_t1_20260423_185636_qemu_20260423_191149.log`, then `logs/test_runner/TASK_20260423_170823_manifest_register_manifest_20260423_185636.json`, then `docs/workflow/CURRENT_STATE.md`.
- Exact task for next owner: seed the next condensed packet that builds on this now-proved `runc -> Linux` manifest-identity handoff without re-litigating it. The primary route should advance from transport/association into minimal audit-only consumption of the Linux-side bounded manifest identity near the startup trust path. Keep the current packet closed as accepted evidence. If runner evidence-capture hardening is still desirable, spin it as a separate small workflow task rather than the main semantic next slice.
- Expected deliverable: a fresh planner packet with explicit `goal / scope / constraints / definition of done / validation tier`, anchored on the accepted proof that Linux now receives `manifest_path + sha256 + size` alongside CID during a real guest container launch.
- Stop condition: stop once the next active packet is written clearly enough that a fresh coder session can proceed without reconstructing this manifest-register turn from logs.
- If blocked: preserve the exact semantic ambiguity about the next audit-only consumption slice, rather than routing back into the completed transport packet by default.
- Do not do in this turn: do not send the next machine role back to coder on this same packet, do not reopen transport plumbing as the main task, and do not widen directly into enforcement unless a new explicit requirement overrides the current phase shape.

## Coder Result

- Implementation summary: Repaired only the repo-tracked guest `runc` reproducibility path that blocked the fresh-VM T1 run. `scripts/patches/runc_manifest_register.patch` is now the full upstream-to-target diff against the guest repo's pristine `HEAD:libcontainer/standard_init_linux.go`, including the existing CID registration hook plus the bounded manifest identity additions, and `scripts/install_runc_manifest_register_in_vm.sh` now detects the manifest-aware file shape semantically before falling back to `git apply`. The Linux-side manifest registration code in `linux/arch/riscv/kernel/sys_riscv.c` was left unchanged in this turn.
- Commit or patch: working-tree patch touching `scripts/install_runc_manifest_register_in_vm.sh` and `scripts/patches/runc_manifest_register.patch`
- Route chosen and why: Kept the same control model and repaired the broken guest reproducibility artifacts in place. Rebasing the saved patch onto the guest repo's pristine `HEAD` file shape is the smallest fix that restores forward-apply behavior on a fresh VM, and the semantic already-patched check is the smallest helper hardening that preserves idempotence after `gofmt`/prior local edits without inventing a new runtime hook.
- Escalations made: No semantic escalation. The blocker was execution-local and was resolved within the allowed helper/patch path after directly observing that the guest repo `HEAD` file is pristine upstream while the previous saved patch had been generated against a dirty CID-only working tree.
- Remaining risks: This turn proved only the repaired guest patch/build/install path, not the full rebuilt-kernel manifest-registration proof. The next heavy step is still a reviewer-approved `test_runner` rerun that boots the rebuilt kernel and captures the Linux-side `nacc manifest register ...` evidence on a real container launch.

## Review Result

- Approval status: approve-with-conditions
- Spec fidelity: acceptable; no blocking fidelity drift found in the refreshed repair. Rebasing `scripts/patches/runc_manifest_register.patch` to the guest repo's pristine `HEAD:libcontainer/standard_init_linux.go` restores the same bounded `runc -> Linux` manifest-registration route on a fresh VM rather than choosing a broader architecture, and `scripts/install_runc_manifest_register_in_vm.sh` adds only a narrow semantic `already applied` path to preserve idempotence when the guest file is already manifest-aware.
- Fidelity findings:
  - none blocking
  - condition for test handoff: the refreshed helper/patch evidence repairs guest reproducibility only; test_runner must still prove that the rebuilt kernel emits the Linux-side `nacc manifest register ...` evidence on a real guest container launch before this packet can close
- Risk review: acceptable for renewed `T1` handoff. The remaining risks are baseline-drift and proof-activation risks, not route-shape or control-model regressions.
- Risk findings:
  - the current refreshed evidence proves that the saved patch now matches the guest repo's pristine `HEAD` baseline and that the helper reruns on an already-patched tree, but it still does not activate the Linux-side log/store path on a rebuilt boot by itself
  - the helper's semantic `already applied` guard is intentionally specific to three manifest-aware markers in `libcontainer/standard_init_linux.go`; if the guest baseline drifts again, test_runner should treat helper failure or unexpected build behavior as the first blocker rather than editing in the VM ad hoc
  - both `runc` and Linux intentionally fall back to CID-only registration on missing or invalid manifest payload, so a successful container exit is still insufficient proof without the manifest-specific Linux evidence
- Can proceed to test: yes
- Key files reviewed:
  - `scripts/patches/runc_manifest_register.patch`
  - `scripts/install_runc_manifest_register_in_vm.sh`
  - `logs/coder/TASK_20260423_170823_manifest_register_runc_pristine_apply_check_20260423_184617.log`
  - `logs/coder/TASK_20260423_170823_manifest_register_runc_helper_repro_20260423_184530.log`
  - `logs/test_runner/TASK_20260423_170823_manifest_register_t1_fail_20260423_182141.log`
  - `docs/workflow/tasks/active/TASK_20260423_170823_manifest_register.md`
- Human-facing code explanation: the saved `runc` patch now matches the pristine guest `standard_init_linux.go` baseline that fresh VMs actually boot with, and the install helper now first detects whether the manifest-aware registration hook is already present before it applies the repo-tracked patch and rebuilds `runc` in the guest.
- Why this route still fits the packet: it only repairs the repo-tracked reproducibility mechanism around the same guest-side registration hook. It keeps manifest authority in the guest, preserves the bounded `path + sha256 + size` transport already accepted for this slice, and does not widen Linux/OpenSBI transport or startup-policy behavior.
- Requirements checked directly from code:
  - `scripts/patches/runc_manifest_register.patch` is now a full pristine-`HEAD`-to-target diff for `/root/riscv-docker/runc/libcontainer/standard_init_linux.go` and keeps the same bounded manifest-identity additions at the final `SYS_NACC_REGISTER` callsite
  - `scripts/install_runc_manifest_register_in_vm.sh` checks exact manifest-aware markers before `git apply`, which is narrow enough to support idempotence without inventing a new runtime path
  - `logs/coder/TASK_20260423_170823_manifest_register_runc_pristine_apply_check_20260423_184617.log` directly shows the saved patch passes `git apply --check` against the guest repo's pristine `HEAD` file shape
  - `logs/coder/TASK_20260423_170823_manifest_register_runc_helper_repro_20260423_184530.log` directly shows the helper no longer stops at `git apply` on an already-patched guest tree and continues through build/install
  - reviewer reran `bash -n scripts/install_runc_manifest_register_in_vm.sh` successfully
- Human-facing summary: reviewer found no blocking fidelity or refreshed code-risk issue in the repaired guest patch/helper path. The packet can return to `test_runner`, but the next run still has to prove the rebuilt kernel emits manifest-specific Linux registration evidence on a real guest container launch.

## Test Result

- Command run: `T1` packet batch plan with `make linux-update`, `make agent-update`, rebuilt-image debug boot gated by `VM_SSH_READY_TIMEOUT_SECONDS=180 make vm VM_AUTO_CMD='true'` inside `make debug`, then `scripts/install_runc_manifest_register_in_vm.sh`, `scripts/generate_manifest_in_vm.sh -o /tmp/nacc_manifest_ls.json /usr/bin/ls`, host copy-out of `/tmp/nacc_manifest_ls.json`, and the real guest container command `docker run --security-opt seccomp=unconfined --rm -e NACC_MANIFEST_PATH=/tmp/nacc_manifest_ls.json -v /tmp/nacc_manifest_ls.json:/tmp/nacc_manifest_ls.json:ro busybox echo test`
- Build actions: `make linux-update` completed; `make agent-update` completed; `final_image.bin` was regenerated on the rebuilt kernel/agent path before the fresh VM boot
- Outcome: blocked at the first decisive post-launch boundary: the rebuilt-image run completed readiness, guest `runc` install/build, guest manifest generation, manifest export, and the real busybox container launch (`rc=0`), but the captured guest dmesg artifact still lacked any `nacc manifest register` evidence
- Primary log path: `logs/test_runner/TASK_20260423_170823_manifest_register_t1_20260423_185636.log`
- Artifact / log path:
  - manifest artifact `logs/test_runner/TASK_20260423_170823_manifest_register_manifest_20260423_185636.json`
  - guest dmesg `logs/test_runner/TASK_20260423_170823_manifest_register_guest_dmesg_20260423_185636.log`
  - QEMU pane log `logs/TASK_20260423_170823_manifest_register_t1_20260423_185636_qemu_20260423_191149.log`
  - VM pane log `logs/TASK_20260423_170823_manifest_register_t1_20260423_185636_vm_20260423_191149.log`
  - failure snapshot `logs/test_runner/TASK_20260423_170823_manifest_register_t1_fail_20260423_185636.log`

## Analysis Result

- Verdict: `acceptable`
- Human-facing summary: the rebuilt-kernel `T1` run did reach the bounded manifest-registration path on a real guest container launch. The runner blocked on a false negative because it searched a late guest `dmesg` snapshot that no longer contained the earlier manifest-register line; the preserved QEMU pane log does contain it, and the copied manifest artifact matches the logged digest and size.
- Run classification: acceptable for this packet's proof target, with suspicious residual trap/debug noise after the proof point.
- Dominant event pattern: a single successful `nacc manifest register ...` event is emitted before the in-guest `runc:[2:INIT] -> /bin/echo` exec path, then the run falls into the usual verbose page-fault / `SEGV_ACCERR` / `PRIVATE_DATA` debug churn, but still reaches `sys_write`, `sys_exit_group`, and normal `exit_mmap` cleanup while the container prints `test` and exits `0`.
- Key evidence:
  - `logs/TASK_20260423_170823_manifest_register_t1_20260423_185636_qemu_20260423_191149.log` shows `[Linux]: nacc manifest register cid=a03c074c561a pid=947 path=/tmp/nacc_manifest_ls.json size=2809 sha256=b420226b5e26ba30789d5b38601713ff1b60198da3ea8293262b21cfff15d4d8`, immediately followed by `GO BACK TO RUNC.` and then `do_execveat_common pid=947 comm=runc:[2:INIT] ... filename=/bin/echo`.
  - `logs/test_runner/TASK_20260423_170823_manifest_register_manifest_20260423_185636.json` hashes to `b420226b5e26ba30789d5b38601713ff1b60198da3ea8293262b21cfff15d4d8` and is `2809` bytes, matching the logged manifest payload exactly.
  - `logs/test_runner/TASK_20260423_170823_manifest_register_t1_20260423_185636.log` shows the real guest container printed `test` and `guest_action_result=container_launch rc=0` before the runner declared `manifest_register_evidence=absent`.
  - `logs/test_runner/TASK_20260423_170823_manifest_register_guest_dmesg_20260423_185636.log` begins at timestamp `246.041767`, which is later than the manifest-register event at `242.502226`, so the specific proof line was already missing from that captured artifact.
  - The same guest/QEMU evidence also shows later post-proof progress rather than an immediate crash: `sys_write`, `sys_exit_group`, and `reason=exit_mmap` are present for the confidential `/bin/echo` process with the same CID.
- Likely cause:
  - The packet's runtime path succeeded, but the runner's evidence check was too narrow: it only grepped the late guest `dmesg` snapshot and did not consult the QEMU pane log that still held the earlier manifest-register line.
  - The missing line in `guest_dmesg` is most likely a log-retention issue caused by very heavy debug output between the proof point and the later capture, not a real CID-only fallback in this run.
- Confidence: `high`
- Evidence / Inference Boundary:
  - Evidence: the QEMU pane log contains the manifest-register line with CID, path, size, and SHA-256; the copied manifest artifact matches that size and SHA-256; the primary runner log shows `test` and container `rc=0`; the guest `dmesg` artifact starts several seconds later and therefore does not contain the earlier proof line.
  - Evidence: the post-proof logs also contain noisy `PRIVATE_DATA` lookup misses and repeated `SEGV_ACCERR`-tagged fault retries.
  - Inference: the runner's `missing_manifest_register_evidence` stop was a false negative caused by evidence capture strategy, not by failure of the manifest-registration path itself.
  - Inference: the later trap noise is a residual concern worth tracking, but this run does not show it preventing the packet's bounded manifest-registration proof because the process reaches write and exit cleanup.
- Recommended next owner: `planner`
- Recommended next step: treat this packet as accepted closeout evidence and write the next condensed packet for the semantic follow-on. The primary next slice should consume the now-available Linux-side manifest identity in an audit-only / observation mode near the startup-trust path without reopening the transport work. If workflow robustness still matters, leave runner evidence-capture hardening as a separate optional mini-packet.

## Open Questions

- None yet beyond the packet-level `Open Semantic Questions`; execution should convert any real ambiguity into a concrete blocker or resolved route.
