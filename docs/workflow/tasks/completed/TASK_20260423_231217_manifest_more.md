# Task Packet

- Task ID: TASK_20260423_231217_manifest_more
- Created: 2026-04-23 23:12:17 +0800
- Priority: P0
- Lane: A
- Packet Type: execution
- Owner Role: human
- Status: done
- Goal: Establish a first working path in which `manifest.json` is analyzed before OpenSBI and the resulting monitor-oriented memory-layout information, optionally paired with Linux-provided runtime base coordinates, is transported to the OpenSBI monitor so the monitor can expose or consume an interpreted view of the user application's memory arrangement.
- Critical Intent: This task is the first step toward replacing the former VMA-based monitor guidance with manifest-driven decisions about which user-application regions should be shared or protected privately, but this packet is only for getting manifest-derived layout information into OpenSBI through a simple end-to-end path.
- Preferred Shape: Reuse the accepted guest `runc -> Linux` manifest-registration path from `docs/workflow/tasks/completed/TASK_20260423_170823_manifest_register.md` as the default entry point. First choice is to have `runc` at the existing registration boundary read the current guest-local `manifest.json`, extract only the bounded startup-relevant facts already available now (at minimum object identity plus `PT_LOAD` segment metadata), let Linux add runtime coordinates such as object or segment load bases if needed, and forward a fixed monitor-oriented layout payload to OpenSBI through the smallest ABI / ECALL extension that fits. OpenSBI should log, store, or expose that simplified layout only; it should not become a raw JSON parser in this packet.
- Disallowed Shape: Do not push full `manifest.json` parsing into OpenSBI. Do not reopen the completed bounded manifest-registration packet as an unfinished transport problem. Do not return startup authority to Linux VMA metadata. Do not replace the former VMA-based protection mechanism yet. Do not widen into final manifest-schema design, PR5 enforcement, shared/private policy changes, attestation, or unrelated runner-hardening work. Do not leave the only meaningful change stranded as an untracked guest-only edit.
- Allowed Freedom: Default route is `runc` at the already accepted registration boundary, but coder may move the pre-OpenSBI analysis to another Linux-side producer if and only if the payload semantics stay the same and the `runc` path hits a concrete blocker. The monitor payload may be minimal and audit-only; current manifest `PT_LOAD` data plus Linux-reported runtime base coordinates are acceptable inputs for this slice.
- Scope: Focus on the path from existing `manifest.json` data to a simplified layout description delivered to the OpenSBI monitor, using the current manifest fields (especially ELF / `PT_LOAD`-related information) plus Linux-reported address bases as runtime coordinates if needed, so OpenSBI can discover the user application's memory layout at an initial level without having to parse the full manifest format itself.
- Constraints:
  - Do not treat this task as the full final manifest design.
  - Do not require a complicated new manifest format in this step.
  - Do not push full manifest parsing into OpenSBI if a simpler preprocessed form can be sent instead.
  - Prefer manifest analysis in `runc` or Linux-side code, with an ECALL-style interface used to inform OpenSBI of the needed layout information.
  - Linux-provided load bases or segment coordinates may be used in this step, but only as runtime coordinates, not as final startup security authority.
  - Do not replace the former VMA-based protection mechanism yet; this task is only about enabling manifest-derived transport and monitor-side visibility as a first step.
  - Use the current manifest content as-is or with only minimal additions if strictly necessary.
- Open Semantic Questions:
  - Default producer is `runc` at the accepted registration boundary; if that path is concretely blocked, may the same preprocessing move to another Linux-side producer without changing the monitor payload semantics?
  - What is the smallest fixed monitor payload that is still useful for this step: object identity plus `PT_LOAD` ranges and flags, or that set plus Linux-reported load-base coordinates?
- Human Concern: Keep the first loop simple and monitor-oriented. Avoid paying the complexity cost of raw `manifest.json` parsing inside OpenSBI when the current step only needs bounded layout facts that help the monitor understand the application memory arrangement.
- Key Assumptions:
  - The current manifest may not yet be rich enough for the final policy model, but it is rich enough to support this first transport slice.
  - The current manifest already contains enough basic information (for example ELF / `PT_LOAD`-related layout data) to support an initial OpenSBI-side understanding of user application memory arrangement.
  - Linux can provide runtime coordinates such as different segment base addresses without becoming the authority source for the final policy model.
  - A simple end-to-end loop is preferred over premature schema expansion.
  - OpenSBI should receive a reduced, monitor-oriented description rather than the raw full manifest when possible.
  - For this bounded slice, startup-object identity in the transported layout is reduced to the current manifest role IDs (`entry` / optional `interp`), because the accepted manifest generator currently emits only those startup roles and the packet does not require a richer per-object identity scheme yet.
  - For the guest-side legacy-upgrade path, `/root/riscv-docker/runc` still keeps the pristine upstream `HEAD:libcontainer/standard_init_linux.go` in Git history while the older manifest-identity-only hook exists only as a worktree edit; the installer rebuilds the desired file from that tracked `HEAD` plus the repo-tracked full patch instead of guessing a textual merge.
  - For the fresh-boot `T1` rerun, the guest `runc` file is expected to be either the clean upstream `HEAD` shape or the specific older manifest-identity-only worktree edit captured in `logs/test_runner/TASK_20260423_231217_manifest_more_rerun3_20260424_001853.log`; any third file shape should be treated as a new blocker rather than silently merged.
- Evidence / Inference Boundary:
  - Direct human intent: manifest analysis should likely happen in `runc` or Linux, not in OpenSBI; OpenSBI should receive the needed layout information through something like an ECALL path.
  - Direct human intent: OpenSBI should still be able to expose or hold an interpreted memory-layout view useful for later protection logic.
  - Direct human intent: even if the current manifest is semantically incomplete for the eventual target, its `PT_LOAD` information plus Linux-provided load bases are acceptable ingredients for this first step.
  - Auxiliary workflow evidence from `docs/workflow/tasks/completed/TASK_20260423_170823_manifest_register.md`: a real guest container launch already proves guest `runc -> Linux` transport of bounded manifest identity (`path + sha256 + size`), so this packet should extend consumption from that accepted boundary rather than reopen transport from scratch.
  - Auxiliary workflow evidence from `docs/workflow/CURRENT_STATE.md`: the current phase goal remains manifest-guided startup understanding with Linux runtime facts used as coordinates only, not security authority.
  - Inference from wording: "make the loop right" means achieving a working end-to-end path for the current `manifest.json`, not completing the eventual replacement of the VMA mechanism.
- Reconciliation Required: no
- Post-Run Analysis Required: no
- Human Checkpoint Required: no
- Definition Of Done:
  - There is a working end-to-end path by which the current `manifest.json` is analyzed before OpenSBI and the resulting layout information reaches the OpenSBI monitor.
  - OpenSBI receives enough manifest-derived information, potentially paired with Linux runtime base coordinates, to expose or hold an interpreted view of the user application's memory layout at an initial level.
  - The task stops at making this initial manifest-to-monitor loop work correctly; richer manifest semantics and actual replacement of the VMA-based decision path are deferred to later tasks.
- Related State:
  - `docs/workflow/CURRENT_STATE.md`
  - `docs/workflow/NEXT_STEPS.md`
- Related Ticket / Plan:
  - `docs/workflow/tasks/completed/TASK_20260423_170823_manifest_register.md`
  - `docs/workflow/tasks/completed/TASK_20260421_004333_manifest_mvp.md` (archived route history only; do not let it override this packet's fresh intent)
- Branch / Worktree: `main`
- Validation Tier: T1

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

- Patch or commit: repo-tracked changes for pre-OpenSBI manifest extraction plus Linux / OpenSBI transport, including any guest `runc` patch or install helper needed to keep the route reproducible
- Minimal compile result: bounded coder sanity only; if the only useful proof is a heavy `make linux-update` / `make opensbi` / QEMU or image rebuild, write `deferred to test_runner`
- Test command or batch plan: rebuild touched components, boot a fresh VM with the repo-owned readiness gate, apply or install the repo-tracked guest `runc` patch if needed, generate or use a guest-local `manifest.json`, launch a real guest container, and capture Linux/OpenSBI evidence that the simplified manifest-derived layout payload reaches OpenSBI
- Primary log path: `logs/test_runner/TASK_20260423_231217_manifest_more_<timestamp>.log`
- Log path if validation fails: `logs/test_runner/TASK_20260423_231217_manifest_more_fail_<timestamp>.log`

## Latest Summary

- Fresh packet seeded from human intent and auxiliary workflow context.
- Build on the accepted guest `runc -> Linux` manifest-registration proof instead of reopening transport from scratch.
- The next slice is to preprocess the current manifest into a bounded monitor-oriented layout payload, using current `PT_LOAD` facts plus Linux load-base coordinates if needed, and deliver that simplified payload to OpenSBI in a visibility-only loop.
- 2026-04-23 coder implemented the bounded runtime route without adding a new OpenSBI parser or a new layout-specific SBI ABI: the repo-tracked guest `runc` patch now parses the current manifest's `entry` / optional `interp` `PT_LOAD` set into a fixed layout-record array, Linux syscall `nacc_register` stores that layout per CID next to the already-accepted manifest identity, and the existing Linux startup-coordinate handoff now emits those registered layout records through the already-landed `SBI_EXT_NACC_STARTUP_AUDIT_RANGE` path so OpenSBI logs an interpreted manifest-derived layout view with Linux runtime bases.
- 2026-04-23 coder bounded sanity passed for the touched paths: `bash -n scripts/install_runc_manifest_register_in_vm.sh`, `git -C linux diff --check -- arch/riscv/kernel/sys_riscv.c`, `git apply --stat --summary scripts/patches/runc_manifest_register.patch`, and the single-object Linux build `make ARCH=riscv -C /home/link/NaCC/linux O=/home/link/NaCC/riscv-linux CROSS_COMPILE=/home/link/NaCC/riscv-tools/bin/riscv64-unknown-linux-gnu- arch/riscv/kernel/sys_riscv.o`. Heavy rebuilt-image / VM proof remains deferred to reviewer / test_runner per packet scope.
- 2026-04-23 reviewer accepted the route on spec fidelity and bounded risk for `T1`: the patch keeps manifest parsing in guest `runc`, keeps Linux as the runtime-coordinate join point, and reuses the existing startup-coordinate plus `SBI_EXT_NACC_STARTUP_AUDIT_RANGE` carrier instead of inventing a new OpenSBI parser or a more invasive ABI. The remaining review-visible risks are operational rather than architectural: Linux keeps the registered layout in a fixed 32-slot per-CID registry with no retire path yet, kernel-side layout validation is intentionally shallow because this slice is still audit-only transport, and test evidence must key off manifest-specific Linux/OpenSBI logs rather than container exit alone.
- 2026-04-24 test_runner rebuilt the dirty runtime artifacts once with `make linux-update` and `make agent-update` (preserved in `logs/test_runner/TASK_20260423_231217_manifest_more_20260424_000115.log`), then reran the fresh-boot `T1` path against that rebuilt image until the first decisive task-packet stop. The final decisive rerun reached authenticated SSH readiness on a fresh debug VM and entered `scripts/install_runc_manifest_register_in_vm.sh`, but stopped immediately at the guest `runc` patch applicability boundary: the guest `/root/riscv-docker/runc/libcontainer/standard_init_linux.go` still matched the older manifest-identity-only hook shape, so the repo-tracked layout-aware patch failed at line 1 and no manifest generation, matched container launch, Linux manifest-layout log, or OpenSBI startup-audit evidence was produced in this turn. Primary failure log: `logs/test_runner/TASK_20260423_231217_manifest_more_rerun3_20260424_001853.log`; failure snapshot: `logs/test_runner/TASK_20260423_231217_manifest_more_fail_20260424_001853.log`; preserved pane logs: `logs/TASK_20260423_231217_manifest_more_rerun3_20260424_001853_postfail_qemu_20260424_002254.log` and `logs/TASK_20260423_231217_manifest_more_rerun3_20260424_001853_postfail_vm_20260424_002254.log`.
- 2026-04-24 log_analyzer reduced the stop boundary to a pre-manifest-generation guest `runc` patch applicability failure. The decisive evidence is still in `logs/test_runner/TASK_20260423_231217_manifest_more_rerun3_20260424_001853.log`: the VM reached `vm_ready=1 auto_exit=1`, then `git apply` failed immediately on `libcontainer/standard_init_linux.go`, and the saved diff excerpt shows only the older manifest-identity-only symbols (`naccLoadManifestIdentity`, `crypto/sha256`, `unix.Syscall6(... manifestSize, 0, 0)`) rather than the newer layout-aware shape expected by the repo helper. No `manifest layout` or `startup audit` evidence appears in the saved primary/QEMU/VM artifacts for this turn, so the next repair should stay on the repo-tracked guest patch/install path rather than Linux/OpenSBI transport.
- 2026-04-24 coder repaired only the repo-tracked guest install convergence path. `scripts/install_runc_manifest_register_in_vm.sh` now recognizes the recorded older manifest-identity-only `standard_init_linux.go` shape and upgrades it by reconstructing `libcontainer/standard_init_linux.go` from guest `HEAD` plus the existing repo-tracked full patch, verifying the resulting layout-aware markers, and then copying that reconstructed file back before `gofmt` / `make install`. Clean-tree apply and already-applied semantic detection remain intact, and Linux/OpenSBI transport semantics were left unchanged.
- 2026-04-24 coder bounded sanity for the repair passed: `bash -n scripts/install_runc_manifest_register_in_vm.sh`; a log-derived legacy-shape matcher check against the saved failure excerpt (`LEGACY_SHAPE_MATCHED`); and a bounded temp-repo model check that the chosen `git show HEAD:file -> git apply full patch -> replace dirty worktree file` upgrade method converges (`HEAD_RECONSTRUCTION_OK`). Real guest `runc` replay plus Linux/OpenSBI evidence remains deferred to reviewer / test_runner.
- 2026-04-24 reviewer accepted the installer repair for a fresh-boot `T1` rerun. The new legacy detector matches the recorded identity-only failure shape, the fallback still uses `scripts/patches/runc_manifest_register.patch` as the single source of truth for the desired guest file, and the change does not alter the accepted `runc -> Linux -> OpenSBI` control model. Remaining risk is bounded to the installer assumption surface: the legacy branch is signature-based and relies on guest `HEAD`, so test should treat any third guest file shape as a new blocker and still require manifest-specific Linux/OpenSBI evidence after install succeeds.
- 2026-04-24 test_runner completed the requested `T1` rerun with same-turn rebuild plus fresh-boot execution evidence. `rerun4` rebuilt the dirty runtime artifacts with `make linux-update` and `make agent-update` (`logs/test_runner/TASK_20260423_231217_manifest_more_rerun4_20260424_004955.log`), but its wrapper missed the VM auto-exit despite the live pane showing authenticated SSH and `true` completing; that runner-side gate miss was not treated as the decisive packet stop. The decisive fresh-boot `rerun5` reused those rebuilt artifacts, reached `vm_ready=1 auto_exit=1`, and then stopped again at the first guest-side step: `scripts/install_runc_manifest_register_in_vm.sh` exited `rc=1` after logging `error: reconstructed guest runc file does not match expected layout-aware shape`. No guest manifest artifact or container launch was produced in `rerun5`, and no Linux `manifest layout dispatch source=register` or OpenSBI `manifest startup audit ...` evidence appeared in the saved artifacts. Primary log: `logs/test_runner/TASK_20260423_231217_manifest_more_rerun5_20260424_010151.log`; failure snapshot: `logs/test_runner/TASK_20260423_231217_manifest_more_fail_20260424_010151.log`; guest dmesg: `logs/test_runner/TASK_20260423_231217_manifest_more_guest_dmesg_20260424_010151.log`; pane logs: `logs/TASK_20260423_231217_manifest_more_rerun5_20260424_010151_qemu_20260424_010857.log` and `logs/TASK_20260423_231217_manifest_more_rerun5_20260424_010151_vm_20260424_010857.log`.
- 2026-04-24 log_analyzer reduced `rerun5` to the guest `runc` installer's HEAD-reconstruction verification gate. The primary log shows `vm_ready=1 auto_exit=1`, then the only decisive installer error `error: reconstructed guest runc file does not match expected layout-aware shape`; code inspection shows that string is emitted only inside `upgrade_guest_runc_manifest_patch_from_head()` after reconstructing `HEAD + patch` and failing the helper's layout-aware semantic check, before copy-back, `gofmt`, `make`, or `make install`. The referenced manifest-artifact path was not produced on disk, and the saved primary/dmesg/QEMU/VM artifacts show no guest manifest copy-out, container launch, Linux `manifest layout dispatch source=register`, or OpenSBI `manifest startup audit ...` evidence. The next repair should stay inside the guest install convergence path and surface the exact reconstruction mismatch rather than changing Linux/OpenSBI transport.
- 2026-04-24 coder repaired only the guest installer probe and diagnostics. `scripts/install_runc_manifest_register_in_vm.sh` no longer requires the whitespace-sensitive exact `naccManifestEnv = "NACC_MANIFEST_PATH"` line for layout-aware semantic detection; it now keys off stable structural markers from the repo-tracked layout-aware patch, emits `installer_path=...` breadcrumbs for every branch, and if `HEAD + patch` reconstruction still fails the semantic check it logs guest `HEAD` commit/blob ids, per-marker presence for `head` / `worktree` / `reconstructed`, and bounded diffs before stopping. Linux/OpenSBI manifest transport semantics remain unchanged.
- 2026-04-24 reviewer accepted the structural-probe installer repair for a fresh-boot `T1` rerun. Direct review checks confirmed the repo patch really does use aligned const-block spacing (`naccManifestEnv               = "NACC_MANIFEST_PATH"`), the new layout-aware detector keys off structural markers that exist in that patch, the saved `rerun3` artifact still matches the intended legacy identity-only markers, and the prior `rerun5` failure remained a pre-transport installer stop with zero Linux/OpenSBI manifest evidence. Remaining risk stays bounded to guest-tree-shape assumptions, so `test_runner` must capture `installer_path=...` and either reach manifest-specific Linux/OpenSBI evidence or preserve the new marker/diff diagnostics as the decisive stop.
- 2026-04-24 test_runner packet repair: later repo-owned `T1` runner artifacts existed beyond the prior packet state. `rerun7` rebuilt Linux with `make linux-update` and then stopped at `vm_ready_or_auto_exit_timeout`; `rerun8` reused that build and stopped at `debug_panes_not_ready`; neither was treated as the decisive semantic stop. The latest decisive `rerun9` reused the `rerun7` build reference `logs/test_runner/TASK_20260423_231217_manifest_more_rerun7_build_20260424_013836.log`, reached `vm_ready=1 auto_exit=1` after manual resume from the live session, completed `scripts/install_runc_manifest_register_in_vm.sh` with `installer_path=legacy_head_reconstruction`, completed `scripts/generate_manifest_in_vm.sh -o /tmp/nacc_manifest_ls.json /usr/bin/ls`, copied out `logs/test_runner/TASK_20260423_231217_manifest_more_manifest_20260424_015438.json`, and ran `docker run --security-opt seccomp=unconfined --rm -e NACC_MANIFEST_PATH=/tmp/nacc_manifest_ls.json -v /tmp/nacc_manifest_ls.json:/tmp/nacc_manifest_ls.json:ro busybox echo test` with `rc=0`. The same run captured `logs/test_runner/TASK_20260423_231217_manifest_more_guest_dmesg_20260424_015438.log`, `logs/TASK_20260423_231217_manifest_more_rerun9_20260424_015438_qemu_20260424_020658.log`, and `logs/TASK_20260423_231217_manifest_more_rerun9_20260424_015438_vm_20260424_020658.log`; runner counters ended at `linux_manifest_evidence=0` and `opensbi_manifest_evidence=4`, so the packet stays `needs_analysis` and now routes to `log_analyzer` on `logs/test_runner/TASK_20260423_231217_manifest_more_rerun9_20260424_015438.log`.
- 2026-04-24 log_analyzer reduced `rerun9` to an acceptable full-packet proof with a narrow evidence-capture false negative. The primary runner log confirms the guest installer completed through `installer_path=legacy_head_reconstruction`, manifest generation/copy-out succeeded, and the real `docker run ... busybox echo test` printed `test` and returned `rc=0`. The preserved QEMU pane log then shows the full Linux/OpenSBI evidence pair for the same CID: Linux `nacc manifest register ... layout_records=4`, four Linux `nacc manifest layout ...` records, Linux `manifest layout dispatch source=register ... records=4`, and four matching OpenSBI `manifest startup audit match ...` lines for the same `entry` / `interp` segments. The copied manifest artifact matches the logged registration payload exactly (`sha256=548bb061ed0e81669c9bd3dc97ad43fe35d7a5d04f89c08d49e60ce6cd49c0ef`, `size=2809`). The runner's `linux_manifest_evidence=0` came from an artifact boundary, not from missing Linux transport evidence: the saved guest `dmesg` snapshot begins later at timestamp `639.116640`, after the decisive Linux manifest lines at `635.003410` through `636.491483`, so those proof lines were already absent from that late-captured artifact even though they remain present in the QEMU pane log.

## Next Handoff

- Next owner: human
- Trigger: `rerun9` now has a reduced evidence record showing the full Linux/OpenSBI manifest-layout proof for the same CID despite the runner's stale `linux_manifest_evidence=0` summary.
- Exact artifact to read first: `logs/TASK_20260423_231217_manifest_more_rerun9_20260424_015438_qemu_20260424_020658.log`
- Exact task for next owner: treat this packet as proved and close it out. If workflow robustness still matters, open a separate follow-up only for runner evidence-capture hardening instead of sending this packet back through coder or test_runner.
- Expected deliverable: human closeout or archival of this packet, with any runner artifact-capture concern split into a separate workflow item.
- Stop condition: stop once the accepted proof is recorded and any optional evidence-capture follow-up is separated from this completed semantic slice.
- If blocked: cite the specific post-proof workflow concern; do not reopen Linux/OpenSBI transport work unless a new artifact contradicts the `rerun9` QEMU evidence pair.
- Do not do in this turn: do not send coder or test_runner back for another rerun solely because the late guest `dmesg` snapshot missed earlier manifest lines.

## Coder Result

- Implementation summary: Repaired only `scripts/install_runc_manifest_register_in_vm.sh`. The layout-aware semantic detector no longer relies on the whitespace-sensitive exact `naccManifestEnv = "NACC_MANIFEST_PATH"` const line that the full layout-aware Go file rewrites under const-block alignment; it now keys off stable structural markers (`NACC_MANIFEST_PATH`, the layout loader, layout-cap constant, layout pointer/count setup, and the `SYS_NACC_REGISTER` call). The helper also now emits `installer_path=...` for every branch and, if `HEAD + patch` reconstruction still fails, logs guest `HEAD` commit/blob ids, per-marker presence for `head` / `worktree` / `reconstructed`, and bounded diffs before stopping. Linux/OpenSBI transport logic was left untouched.
- Commit or patch: working-tree change in `scripts/install_runc_manifest_register_in_vm.sh`
- Route chosen and why: Kept `scripts/patches/runc_manifest_register.patch` as the single source of truth for the desired guest `runc` file shape and stayed entirely inside the installer. A bounded local marker check against the repo patch showed the old exact const-line probe could false-negative on the layout-aware file purely because Go aligned the const block differently, so switching the semantic gate to structural markers is the smallest fix that can clear the current gate without inventing a second patch or touching Linux/OpenSBI behavior.
- Escalations made: none
- Remaining risks: The legacy-upgrade branch still assumes the guest `runc` tree is a Git checkout with a usable `HEAD:libcontainer/standard_init_linux.go` baseline for `scripts/patches/runc_manifest_register.patch`. If the guest later presents some third file shape beyond clean tree or the recorded identity-only worktree state, the helper should now stop with explicit marker status and bounded diffs, but heavy guest build / VM proof that this repaired install path reaches the manifest-specific Linux/OpenSBI logs is still deferred to reviewer / test_runner.

## Review Result

- Approval status: approve-with-conditions
- Spec fidelity: acceptable. The repair is packet-faithful: it changes only the guest `runc` installer probe and bounded diagnostics, keeps `scripts/patches/runc_manifest_register.patch` as the single source of truth for the desired layout-aware file shape, and does not move manifest parsing, alter Linux/OpenSBI transport semantics, or choose a more invasive guest-side route than the packet allows.
- Fidelity findings:
- `scripts/install_runc_manifest_register_in_vm.sh` still stays entirely inside the guest install boundary: it decides among already-applied, legacy-upgrade, clean-apply, and fail-fast paths, but it does not touch Linux or OpenSBI code paths at all.
- The new layout-aware semantic gate fixes the recorded false-negative class without inventing new semantics. Direct patch inspection shows the repo-tracked full patch uses aligned const-block spacing (`naccManifestEnv               = "NACC_MANIFEST_PATH"`), so matching `NACC_MANIFEST_PATH` plus the layout loader, layout-cap, layout pointer/count, and `SYS_NACC_REGISTER` markers is the packet-minimal way to accept the intended file shape.
- The saved `rerun3` artifact still matches the bounded legacy detector (`naccLoadManifestIdentity`, `io.Copy(hasher, file)`, and `unix.Syscall6(... manifestSize, 0, 0)` without `naccLoadManifestLayout`), so the installer still targets the recorded legacy edge rather than broadening into an open-ended merge strategy.
- The added `installer_path=...`, `reconstruction_head_*`, per-marker logging, and bounded diff excerpts only expose the exact guest-tree mismatch if reconstruction fails again; they do not change the accepted `runc -> Linux -> OpenSBI` control model.
- Risk review: acceptable for a fresh-boot `T1` rerun. I found no blocking control-model or spec-fidelity issue, but the repair still carries bounded installer-side assumptions that the next test must make explicit.
- Risk findings:
- The layout-aware detector is still signature-based rather than a full semantic parser. That is acceptable for this bounded installer slice, but any future third guest file shape may still fall through to either `legacy_head_reconstruction` or `apply_failed`; `test_runner` must preserve the new branch/marker/diff logs and treat such a stop as a new guest-shape blocker instead of broadening the installer again.
- The HEAD-reconstruction branch still assumes `/root/riscv-docker/runc` is a Git checkout whose `HEAD:libcontainer/standard_init_linux.go` is compatible with `scripts/patches/runc_manifest_register.patch`. If guest `HEAD` has drifted, the helper should now stop with the new head/blob ids and marker/diff diagnostics, but test still needs to capture them.
- Installer success is still not enough. The accepted route can still degrade to identity-only / CID-only behavior on bad manifest payloads, so the rerun must require manifest-specific Linux `source=register` / dispatch evidence and OpenSBI `manifest startup audit ...` evidence before treating the packet as proved.
- The background Linux/OpenSBI transport risks from the earlier accepted review remain deferred, but they do not block this turn because this repair did not change transport semantics.
- Can proceed to test: yes
- Key files reviewed:
  - `docs/workflow/tasks/active/TASK_20260423_231217_manifest_more.md`
  - `docs/workflow/CURRENT_STATE.md`
  - `scripts/install_runc_manifest_register_in_vm.sh`
  - `scripts/patches/runc_manifest_register.patch`
  - `logs/test_runner/TASK_20260423_231217_manifest_more_rerun3_20260424_001853.log`
- `logs/test_runner/TASK_20260423_231217_manifest_more_rerun5_20260424_010151.log`
- Human-facing code explanation: `scripts/install_runc_manifest_register_in_vm.sh` now decides “is the layout-aware guest patch already here?” from a small structural marker set instead of one spacing-sensitive const line, and if `HEAD + patch` reconstruction still fails later it prints the exact branch, marker states, and short diffs needed to understand the guest-tree mismatch.
- Why this route still fits the packet: it repairs only the reproducibility and observability boundary of the already accepted `runc -> Linux -> OpenSBI` route, keeps the desired guest file definition in one repo patch artifact, and avoids widening the packet into a new transport, a new parser location, or a more invasive guest-side merge strategy.
- Requirements checked directly from code:
  - Reviewer reran `bash -n scripts/install_runc_manifest_register_in_vm.sh` and `git apply --stat --summary scripts/patches/runc_manifest_register.patch`.
  - Reviewer confirmed the new structural layout-aware markers all exist in `scripts/patches/runc_manifest_register.patch`, including the aligned-const `NACC_MANIFEST_PATH` case that the prior exact-string probe could miss.
  - Reviewer matched the saved `rerun3` failure log directly against the legacy detector markers and confirmed `naccLoadManifestLayout` is absent from that recorded failing guest shape.
  - Reviewer confirmed the saved `rerun5` stop is still pre-transport (`linux_manifest_evidence=0`, `opensbi_manifest_evidence=0`) so this turn remains an installer review, not a Linux/OpenSBI regression review.
- Human-facing summary: reviewer found no blocking spec-fidelity drift in the structural-probe installer repair. The packet can move to `test_runner`, but the rerun should stay on a fresh boot, record `installer_path=...`, and still require manifest-specific Linux/OpenSBI evidence before calling the route proved.

## Test Result

- Command run: latest decisive `T1` run is `rerun9`. It reused the earlier same-turn Linux rebuild from `logs/test_runner/TASK_20260423_231217_manifest_more_rerun7_build_20260424_013836.log`, booted a fresh debug VM with `make debug VM_AUTO_CMD='true'`, reached `vm_ready=1 auto_exit=1`, ran `scripts/install_runc_manifest_register_in_vm.sh`, ran `scripts/generate_manifest_in_vm.sh -o /tmp/nacc_manifest_ls.json /usr/bin/ls`, copied out the guest manifest, and then ran `docker run --security-opt seccomp=unconfined --rm -e NACC_MANIFEST_PATH=/tmp/nacc_manifest_ls.json -v /tmp/nacc_manifest_ls.json:/tmp/nacc_manifest_ls.json:ro busybox echo test`.
- Build actions: `make linux-update` completed in `logs/test_runner/TASK_20260423_231217_manifest_more_rerun7_build_20260424_013836.log`; `rerun9` reused that rebuilt image path and did not run another component rebuild.
- Outcome: `needs_analysis`. The decisive `rerun9` completed guest install, manifest generation/export, and the real container launch (`rc=0`), but the captured evidence still needs reduction because the runner counters ended at `linux_manifest_evidence=0` and `opensbi_manifest_evidence=4`.
- Primary log path: `logs/test_runner/TASK_20260423_231217_manifest_more_rerun9_20260424_015438.log`
- Artifact / log path:
  - failure snapshot `logs/test_runner/TASK_20260423_231217_manifest_more_fail_20260424_015438.log`
  - manifest artifact `logs/test_runner/TASK_20260423_231217_manifest_more_manifest_20260424_015438.json`
  - guest dmesg `logs/test_runner/TASK_20260423_231217_manifest_more_guest_dmesg_20260424_015438.log`
  - QEMU pane log `logs/TASK_20260423_231217_manifest_more_rerun9_20260424_015438_qemu_20260424_020658.log`
  - VM pane log `logs/TASK_20260423_231217_manifest_more_rerun9_20260424_015438_vm_20260424_020658.log`
  - rebuild reference `logs/test_runner/TASK_20260423_231217_manifest_more_rerun7_build_20260424_013836.log`

## Analysis Result

- Verdict: `acceptable`
- Human-facing summary: the decisive `rerun9` run proves the packet's first manifest-to-monitor loop on a real guest container launch. The runner's `linux_manifest_evidence=0` result was a false negative from relying on a later guest `dmesg` snapshot; the preserved QEMU pane log contains both the Linux manifest-layout transport evidence and the matching OpenSBI startup-audit evidence for the same CID and payload.
- Run classification: acceptable for this packet's proof target, with a suspicious residual evidence-capture boundary in the late guest `dmesg` artifact.
- Dominant event pattern: after the guest installer succeeds through `legacy_head_reconstruction`, the run follows a clean single-CID sequence of manifest register -> manifest layout records -> Linux startup coordinates -> Linux `source=register` layout dispatch -> four matching OpenSBI `manifest startup audit match` lines, while the real container prints `test` and exits `0`.
- Key evidence:
  - `logs/test_runner/TASK_20260423_231217_manifest_more_rerun9_20260424_015438.log` shows `vm_ready=1 auto_exit=1`, `installer_path=legacy_head_reconstruction`, successful manifest generation/copy-out, `docker run ... busybox echo test`, printed output `test`, and `guest_action_result=... rc=0`.
  - `logs/TASK_20260423_231217_manifest_more_rerun9_20260424_015438_qemu_20260424_020658.log` shows Linux registration of the exact manifest payload for CID `55f3a460174e`: `nacc manifest register ... path=/tmp/nacc_manifest_ls.json size=2809 sha256=548bb061ed0e81669c9bd3dc97ad43fe35d7a5d04f89c08d49e60ce6cd49c0ef layout_records=4`, followed immediately by four Linux `nacc manifest layout ...` records.
  - The same QEMU pane log then shows Linux runtime-coordinate join plus manifest-layout transport: `manifest startup report ... tag=nacc_invoke entry_load_bias=2ad3ce1000 interp_load_addr=3fa884c000`, `manifest layout dispatch source=register ... path=/tmp/nacc_manifest_ls.json records=4`, and one Linux dispatch record per transported segment.
  - The same QEMU pane log shows four matching OpenSBI confirmations for the same CID/root/runtime bases and segment metadata: `manifest startup audit match ...` for `entry phdr=3`, `entry phdr=4`, `interp phdr=1`, and `interp phdr=2`. No `manifest startup audit mismatch` lines appear in the preserved artifact.
  - `logs/test_runner/TASK_20260423_231217_manifest_more_manifest_20260424_015438.json` hashes to `548bb061ed0e81669c9bd3dc97ad43fe35d7a5d04f89c08d49e60ce6cd49c0ef` and is `2809` bytes, matching the logged Linux registration payload exactly.
  - `logs/test_runner/TASK_20260423_231217_manifest_more_guest_dmesg_20260424_015438.log` begins only at timestamp `639.116640`, which is later than the decisive Linux manifest lines at `635.003410` through `636.491483`, so the guest `dmesg` artifact itself proves only that the runner captured too late to retain those earlier lines.
- Likely cause:
  - The manifest-layout transport path itself succeeded end-to-end in `rerun9`; the only remaining issue exposed by this turn is that the runner's Linux-evidence check depended on a late guest `dmesg` snapshot that started after the proof lines had already scrolled out, while the QEMU pane log still retained them.
- Confidence:
  - high on the run verdict, dominant event pattern, and exact Linux/OpenSBI evidence pair
  - medium on whether runner evidence-capture hardening is worth a separate follow-up packet, because that is a workflow choice rather than a semantic blocker
- Evidence / Inference Boundary:
  - Evidence: the primary runner log shows successful guest install, manifest generation/export, real container execution, printed `test`, and container `rc=0`.
  - Evidence: the QEMU pane log contains Linux `nacc manifest register`, four Linux `nacc manifest layout` records, Linux `manifest layout dispatch source=register`, and four OpenSBI `manifest startup audit match` lines for the same CID `55f3a460174e`.
  - Evidence: the copied manifest artifact's SHA-256 and size match the Linux registration line exactly.
  - Evidence: the saved guest `dmesg` artifact starts at `639.116640`, after the decisive Linux manifest lines at `635.003410` through `636.491483`.
  - Inference: the runner's `linux_manifest_evidence=0` / `missing_manifest_or_startup_audit_evidence` stop was a false negative caused by artifact timing and retention, not by absence of Linux manifest-layout transport in the run itself.
  - Inference: any follow-up on evidence capture belongs in a separate workflow slice and is not a reason to reopen this packet's manifest-to-OpenSBI transport semantics.
- Recommended next owner: `human`
- Recommended next step: treat this packet as accepted closeout evidence. If desired, spin out a separate small workflow item for runner evidence-capture hardening so future checks consult the QEMU pane log or preserve earlier Linux lines, but do not rerun or reopen this packet's transport implementation.

## Open Questions

- No blocking semantic questions remain for this packet.
- Residual uncertainty is workflow-only: whether the runner should harden Linux-evidence capture in a separate follow-up.
