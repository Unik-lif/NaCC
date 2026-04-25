# Task Packet

- Task ID: TASK_20260423_115900_fix_manifest
- Created: 2026-04-23 11:59:00 +0800
- Priority: P0
- Lane: A
- Packet Type: execution
- Owner Role: planner
- Status: done
- Goal: Fix the manifest generation and validation flow from `docs/workflow/tasks/completed/TASK_20260421_004333_manifest_mvp.md` so the process can run inside the RISC-V VM instead of depending on host-side generation, avoiding host/VM `ld-linux` mismatch and better matching a real deployment where the platform validates a real ELF Docker image and its `manifest.json`.
- Critical Intent: Shift trust-relevant manifest work into the VM. The solution should make it practical for NaCC to consume a manifest generated in the same environment where ELF validity is judged, instead of relying on host-side assumptions that break under cross-environment loader differences.
- Preferred Shape: Reuse the prior manifest MVP only for durable semantics and existing helper logic, but move the actual manifest-generation proof into the VM. Prefer a route where the host only orchestrates over SSH while ELF parsing and interpreter resolution happen against guest-visible files inside the VM. First choice is to run `scripts/generate_manifest.py` itself, or a narrowly adapted sibling that preserves its schema and fail-closed resolution semantics, inside the guest with guest-local paths and explicit guest-visible search roots such as `/`. Do not invent a new manifest schema for the first proof.
- Disallowed Shape: Do not keep the old host-generated-manifest flow as the primary route if it still depends on host-side ELF / loader interpretation that is invalid inside the VM. Do not widen host-side closure staging again as the main answer to the `ld-linux` mismatch. Do not treat pre-boot qcow2/rootfs mutation helpers such as `scripts/install_manifest.py` or `scripts/stage_probe_root.py` as satisfying the primary proof for this round. Do not assume `riscv-docker/runc` is editable from the host worktree, and do not pull `runc` manifest-consumption work into this task's required proof.
- Allowed Freedom: It is acceptable to modify VM-side flow, repo-side helper scripts, and supporting plumbing needed to make in-VM manifest generation workable. The first proof may use SSH to copy or invoke a helper inside the guest, as long as manifest generation itself runs in the VM against guest-visible ELF/interpreter paths. If the guest lacks direct access to the repo checkout or lacks `python3`, coder may use a bounded one-shot transfer of the existing helper (or a very small derivative) into guest `/tmp`, but must preserve manifest schema semantics and stop at the first concrete prerequisite blocker instead of silently falling back to host-side generation. Updating in-VM `riscv-docker/runc` is allowed as a later extension, but not required for this task's done boundary.
- Scope: Manifest generation and validation flow related to the prior manifest MVP, with emphasis on VM-side generation, VM-side validation context, SSH-driven operator workflow, and the smallest repo-side helper/plumbing needed to run the generator in the guest. End-to-end `riscv-docker/runc` consumption remains out of scope for this packet.
- Constraints:
  - Focus this step on whether the manifest flow can run inside the VM and generally generate `manifest.json` inside the VM.
  - The result should better simulate real scenarios where a RISC-V platform uses the generated manifest to judge whether a Docker image contains a real / valid ELF.
  - Treat guest-executed reuse of `scripts/generate_manifest.py` as the default first route because the current helper is pure Python stdlib and already fail-closes unless an explicit `--search-root` is supplied for absolute `PT_INTERP`.
  - For `T1`, prefer an existing guest-resident dynamic ELF as the first validation anchor. Fall back to a copied-in sample ELF only if no stable guest-resident target is quickly available, and record why.
  - A sufficient `T1` proof is: `manifest.json` generated inside the guest for a real guest-visible ELF, plus one guest-side coherence check showing the resolved entry/interpreter path facts match guest-visible files. Full `runc` or NaCC manifest-consumption wiring is not required here.
  - Do not use host sysroot or host filesystem paths as manifest resolution roots for the proof run; the proof must resolve against guest-visible files only.
  - Use VM access through SSH after the VM is launched, but do not treat `localhost:2222` listening or raw `make vm-debug` as sufficient readiness proof by itself.
  - For runner-owned automation, prefer the repo-owned wait path `VM_SSH_READY_TIMEOUT_SECONDS=<bounded timeout> make vm VM_AUTO_CMD='true'` or the equivalent `config/vm_link.sh "true"` probe before any host-side helper that depends on guest SSH.
  - Only proceed to `scripts/generate_manifest_in_vm.sh` after the repo wait path reaches authenticated SSH success; if the guest still is not reachable, record that first blocker instead of inventing a substitute route.
  - `riscv-docker/runc` should be treated as an in-VM path inside `NaCC.qcow2`, not as a normal repo-side path in the host workspace.
  - If reading `manifest.json` into the NaCC system requires it in a later step, modifying the in-VM `riscv-docker/runc` is permitted. The current custom syscall before `linux.exec` only registers the CID; it may be extended later so `runc` analyzes `manifest.json` and provides detailed information through the same ecall path.
- Open Semantic Questions:
  - None at planning time if coder stays within the `T1` boundary above. Guest readiness and guest prerequisite discovery are execution facts to record, not remaining task-meaning gaps.
- Human Concern:
  - The previous host-generated route was semantically misleading because host-side loader / closure facts diverged from the guest runtime, especially around `ld-linux`, so the next step must anchor validation inside the VM instead of widening host-side staging again.
- Key Assumptions: guest-side reuse of the existing generator is the default route, and missing guest prerequisites should be reported as blockers instead of causing a host-side fallback
  - The current archived manifest MVP packet remains useful only as durable history and prior code/evidence boundaries; it is not the active source of truth.
  - VM SSH access is the normal execution path for role work in this round once the VM is launched.
  - `scripts/generate_manifest.py` can be reused inside the guest without host-only library dependencies because the current implementation is Python-stdlib-only.
  - The first credible proof can use any real guest-visible ELF and does not require immediate Docker payload extraction if a stable guest-resident target is available faster.
  - If the guest lacks a prerequisite such as `python3` or a suitable reachable ELF, the correct first outcome is a concrete blocker report rather than a broadened host-side route.
  - End-to-end NaCC consumption through `riscv-docker/runc` is a possible next step, but not required for this task's Definition Of Done.
- Evidence / Inference Boundary:
  - Directly observed in this planning turn: the host workspace still contains the prior manifest tooling (`scripts/generate_manifest.py`, `scripts/install_manifest.py`, `scripts/stage_probe_root.py`) and the Makefile exposes `make vm-debug` as the repo-side SSH entrypoint.
  - Directly observed in this planning turn: `scripts/generate_manifest.py` is a standalone Python-stdlib ELF parser/generator that fail-closes on absolute `PT_INTERP` unless at least one explicit `--search-root` is provided.
  - Directly observed in this planning turn: `scripts/install_manifest.py` and `scripts/stage_probe_root.py` are pre-boot qcow2/rootfs mutation helpers, so they remain useful prior art but do not satisfy the VM-first primary proof by themselves.
  - Direct human-provided evidence for this packet: the prior host-side manifest route is blocked by host/VM `ld-linux` mismatch, `riscv-docker/runc` lives inside the VM image rather than the host workspace, and role agents may need to enter the VM through SSH before inspecting or changing that path.
  - Conflict note: `docs/workflow/CURRENT_STATE.md` still says there is intentionally no live Phase 2 active packet; that background statement is stale relative to this newly seeded packet and is treated as superseded workflow context rather than a semantic override.
- Planning inference: the smallest route aligned with the human seed is a guest-executed reuse of the current manifest-generator semantics, and repo-local `runc` edits must not be assumed possible before reaching the guest filesystem or VM shell.
- Directly observed in this coder turn: `make launch` booted the guest far enough to expose forwarded SSH on `localhost:2222`, and authenticated SSH succeeded after the guest's normal network/sshd bring-up delay.
- Directly observed in this coder turn: the guest has `python3` (`/usr/bin/python3.10`) and a stable guest-visible dynamic ELF at `/usr/bin/ls`, so the first `T1` proof did not need a copied-in sample ELF.
- Directly observed in this coder turn: `scripts/generate_manifest_in_vm.sh` staged the unchanged `scripts/generate_manifest.py` into guest `/tmp/nacc_generate_manifest.py`, ran `python3 /tmp/nacc_generate_manifest.py --search-root / -o /tmp/nacc_manifest_ls.json /usr/bin/ls` inside the guest, and the saved guest-side coherence check confirmed `entry=/usr/bin/ls` and `interp=/usr/lib/ld-linux-riscv64-lp64d.so.1`; preserved artifacts are `logs/coder/TASK_20260423_115900_fix_manifest_vm_proof_20260423_124137.log` and `logs/coder/TASK_20260423_115900_fix_manifest_vm_manifest_20260423_124209.json`.
- Directly observed in this test_runner turn: a fresh detached `make launch` boot reached authenticated SSH after the expected network/sshd delay, `scripts/generate_manifest_in_vm.sh -o /tmp/nacc_manifest_ls.json /usr/bin/ls` succeeded against guest-visible paths only, the runner-owned wrapper log preserved the guest-side coherence lines for `entry=/usr/bin/ls` and `interp=/usr/lib/ld-linux-riscv64-lp64d.so.1`, and the host-copied manifest artifact hash matched the guest file; preserved artifacts are `logs/test_runner/TASK_20260423_115900_fix_manifest_t1_20260423_125539.log`, `logs/test_runner/TASK_20260423_115900_fix_manifest_qemu_20260423_125539.log`, and `logs/test_runner/TASK_20260423_115900_fix_manifest_vm_manifest_20260423_125539.json`.
- Directly observed in this follow-up test_runner turn: when the packet-owned readiness gate was made explicit as `VM_SSH_READY_TIMEOUT_SECONDS=180 make vm VM_AUTO_CMD='true'`, the repo wait path reported `[NaCC][ssh-ready] authenticated after 2 attempt(s)` and only then ran the guest command; the follow-on `scripts/generate_manifest_in_vm.sh -o /tmp/nacc_manifest_ls.json /usr/bin/ls` proof again succeeded, preserved the same guest-side coherence facts, and produced a matching host/guest manifest hash pair `a765474e05b86f7ecd81c15e938b53e72b4c46a3a19f2763370081b535072345`; preserved artifacts are `logs/test_runner/TASK_20260423_115900_fix_manifest_vm_ready_20260423_130735.log`, `logs/test_runner/TASK_20260423_115900_fix_manifest_t1_20260423_130735.log`, `logs/test_runner/TASK_20260423_115900_fix_manifest_qemu_20260423_130735.log`, and `logs/test_runner/TASK_20260423_115900_fix_manifest_vm_manifest_20260423_130735.json`.
- Directly observed in this log_analyzer turn: the authoritative readiness log shows the repo-owned wait path reaching authenticated SSH before any helper invocation, the authoritative T1 log shows the guest-side generator and coherence check executing against `/usr/bin/ls`, the copied manifest JSON preserves guest-side resolution roots and guest-resolved interpreter path `/usr/lib/ld-linux-riscv64-lp64d.so.1`, and the supporting QEMU log for the same timestamp shows `make launch` hit a qcow2 write lock rather than proving a brand-new guest boot.
- Log-analyzer inference: this artifact set is still sufficient for the packet's bounded `T1` proof because it proves the trust-relevant ELF/interpreter resolution and manifest generation happened inside a live authenticated guest with matching host/guest manifest bytes; the only caveat is operational wording, namely that the follow-up rerun is stronger as "live guest proof with explicit readiness gate" than as evidence of a fresh QEMU instance being created in that exact step.
- Reconciliation Required: no
- Post-Run Analysis Required: no
- Human Checkpoint Required: no
- Definition Of Done: This task establishes and validates an in-VM `manifest.json` generation path that avoids the known host-side `ld-linux` mismatch. The result should make VM-side manifest generation the primary route for this flow, with SSH-accessible execution inside the VM. End-to-end NaCC consumption of manifest details through `riscv-docker/runc` is explicitly out of scope for this task and may be handled in a later step.
- Related State:
  - `docs/workflow/CURRENT_STATE.md`
  - `docs/workflow/NEXT_STEPS.md`
- Related Ticket / Plan:
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

- Patch or commit: bounded patch/commit that enables or documents the VM-first generator route, or a tightly scoped no-code prototype if repo changes are unnecessary for the first proof
- Minimal compile result: if repo-side Python helpers change, run `python3 -m py_compile` on the changed script set; otherwise write `not needed for VM-first proof`
- Test command or batch plan: launch or reuse the guest, then gate readiness through the repo-owned wait path `VM_SSH_READY_TIMEOUT_SECONDS=180 make vm VM_AUTO_CMD='true'` (or equivalent `config/vm_link.sh "true"`), then run `scripts/generate_manifest_in_vm.sh -o /tmp/nacc_manifest_ls.json /usr/bin/ls`, copy the generated guest artifact back to the host, and preserve both the generated artifact path and one guest-side coherence check command/output
- Primary log path: `logs/test_runner/TASK_20260423_115900_fix_manifest_t1_20260423_130735.log`
- Log path if validation fails: `not applicable; runner-owned T1 proof passed`

## Latest Summary

- Fresh packet seeded from human intent for a VM-first manifest round.
- Archived `TASK_20260421_004333_manifest_mvp` is auxiliary history only; its host-side validation anchor is treated as semantically misaligned for this follow-on step.
- Planner confirmed the repo still contains manifest tooling and `make vm-debug`, but `riscv-docker/runc` is an in-VM path inside `NaCC.qcow2`, so any route touching it must begin from SSH-accessible guest work rather than host-worktree assumptions.
- Planner chose the default first proof: run the existing manifest-generator semantics inside the guest, preferably by invoking `scripts/generate_manifest.py` or a narrow derivative against guest-local paths and guest-visible search roots only.
- Pre-boot qcow2/rootfs mutation helpers remain auxiliary history for this packet and do not satisfy the primary VM-first proof by themselves.
- Current host observation: forwarded SSH port `localhost:2222` is not listening right now, so the next role must treat guest launch/readiness as an explicit precondition rather than assuming a live VM.
- Coder landed a bounded orchestration helper at `scripts/generate_manifest_in_vm.sh` that copies the existing generator into guest `/tmp`, runs it inside the VM with `--search-root /`, and performs one guest-side coherence check without changing manifest schema semantics.
- Coder completed the packet's first `T1` proof against guest ELF `/usr/bin/ls`: guest artifact `/tmp/nacc_manifest_ls.json` was generated in-VM, the coherence check resolved the interpreter to guest path `/usr/lib/ld-linux-riscv64-lp64d.so.1`, and the saved host-side evidence is `logs/coder/TASK_20260423_115900_fix_manifest_vm_proof_20260423_124137.log` plus `logs/coder/TASK_20260423_115900_fix_manifest_vm_manifest_20260423_124209.json`.
- Test runner reproduced the packet-owned `T1` proof on a fresh VM launch: `scripts/generate_manifest_in_vm.sh -o /tmp/nacc_manifest_ls.json /usr/bin/ls` completed over SSH, the guest-side coherence output again reported `entry=/usr/bin/ls` plus guest-visible interpreter `/usr/lib/ld-linux-riscv64-lp64d.so.1`, and the host-copied manifest artifact matched the guest file by SHA-256.
- Follow-up runner rerun encoded the repo-owned readiness gate directly: `VM_SSH_READY_TIMEOUT_SECONDS=180 make vm VM_AUTO_CMD='true'` reached authenticated SSH before the host-side helper was invoked, then the same VM-first proof completed successfully with the expected guest-side coherence output and a matching host/guest manifest hash.
- Authoritative runner-owned evidence for closeout is `logs/test_runner/TASK_20260423_115900_fix_manifest_vm_ready_20260423_130735.log` plus `logs/test_runner/TASK_20260423_115900_fix_manifest_t1_20260423_130735.log`, with supporting `logs/test_runner/TASK_20260423_115900_fix_manifest_qemu_20260423_130735.log` and `logs/test_runner/TASK_20260423_115900_fix_manifest_vm_manifest_20260423_130735.json`.
- Log analysis classifies the latest rerun as acceptable for this packet's bounded goal: the readiness gate prevented premature SSH use, manifest generation and ELF/interpreter resolution happened inside the guest, and the copied manifest matched the guest artifact byte-for-byte.
- Residual caveat for closeout wording: the supporting QEMU log at the same timestamp shows a qcow2 write-lock collision, so this evidence proves successful reuse of a live guest under the repo-owned readiness gate, not an independently proven brand-new `make launch` boot in that exact rerun.
- Human follow-on framing for the next step: this round should be treated as a repair and workflow alignment step, not as a semantically new manifest stage; the host-copied `manifest.json` is evidence export of the same guest-generated artifact, not a different manifest source.
- Human workflow note for future machine turns: when an agent needs to enter the VM and run commands over SSH, prefer the repo-owned wait path `make vm VM_AUTO_CMD='...'` rather than ad hoc direct SSH entry, because the repo path waits for authenticated SSH and avoids the brittle "port is open but session is not ready" interruption pattern.
- Human workflow note for future manifest-consumption work: if a later round needs `runc` to read `manifest.json` and pass details into the system, a candidate in-guest hook point is `/root/riscv-docker/runc/libcontainer/standard_init_linux.go` near the final registration syscall path; after editing that in-guest `runc` tree, the expected activation step is in-guest `make && make install`, which is slow enough that planner/test flow should budget explicit wait time.
- Planner follow-on decision: do not resume archived host-closure PR4 validation as the default continuation from this packet. Seed a fresh bounded runtime-aligned packet at `docs/workflow/tasks/active/TASK_20260423_170823_manifest_register.md` and treat this packet only as accepted closeout evidence plus workflow guidance.
- Planner route for the next slice: make the real guest container/CID registration path carry bounded manifest identity from inside the VM before reopening broader audit or enforcement work.

## Follow-on Workflow Notes

- Treat the host-side copied `manifest.json` as exported evidence of the same guest-generated artifact. Do not frame SCP copy-out as a separate semantic validation stage by itself.
- For agent-driven guest command execution, prefer `make vm VM_AUTO_CMD='...'` over raw direct SSH because the repo-owned path waits for authenticated SSH readiness and is less likely to fail at the readiness boundary.
- If follow-on work needs in-VM `runc` changes for manifest ingestion, inspect `/root/riscv-docker/runc/libcontainer/standard_init_linux.go` near the terminal registration syscall path first.
- After in-VM `runc` edits, expect to run `make && make install` inside that guest tree before validation. This rebuild/install step is materially slower than the helper-only proof path and should be treated as a long-running action in future packet planning.

## Next Handoff

- Next owner: coder
- Trigger: the VM-first generation proof is accepted, and the fresh follow-on packet `docs/workflow/tasks/active/TASK_20260423_170823_manifest_register.md` now defines the next bounded runtime-aligned slice.
- Exact artifact to read first: `docs/workflow/tasks/active/TASK_20260423_170823_manifest_register.md`, then this packet's `## Analysis Result` and `## Follow-on Workflow Notes`, then `docs/workflow/tasks/reports/active/TASK_20260423_115900_fix_manifest_human_report.md` if extra context is needed.
- Exact task for next owner: execute the new packet's bounded in-guest manifest-registration route and use this packet only as accepted proof plus workflow guidance.
- Expected deliverable: repo-tracked helper/patch artifacts and a first proof or first concrete blocker showing whether bounded manifest identity can be attached to the guest CID registration path from inside the VM.
- Stop condition: stop after the first decisive proof or first concrete blocker from the new packet; do not add more runtime-proof work to this packet unless its closeout wording itself becomes disputed.
- If blocked: update the new packet with the first decisive blocker rather than reopening host-side manifest generation or re-litigating SCP copy-out semantics here.
- Do not do in this turn: do not reopen this packet's T1 proof, do not resume archived PR4C4 host-closure staging as the default continuation, and do not assume the host worktree directly contains the guest `runc` tree.

## Coder Result

- Implementation summary: Added `scripts/generate_manifest_in_vm.sh`, a small host-side SSH/SCP orchestration helper that copies the existing `scripts/generate_manifest.py` into guest `/tmp`, runs it inside the VM with guest-visible paths only, and performs one guest-side coherence check on the generated manifest. Left `scripts/generate_manifest.py`, `scripts/install_manifest.py`, `scripts/stage_probe_root.py`, Makefile VM targets, and any `runc`/Linux/OpenSBI consumer paths unchanged.
- Commit or patch: working-tree patch adding `scripts/generate_manifest_in_vm.sh`
- Route chosen and why: used the packet's preferred default route verbatim: preserve the existing manifest schema and fail-closed ELF/interpreter logic by reusing `scripts/generate_manifest.py` itself inside the guest, with the host limited to SSH/SCP orchestration. This was the least invasive way to move trust-relevant ELF/interpreter resolution into the VM without reopening host-side staging or consumer design.
- Escalations made: none. Execution noted the expected guest bring-up delay boundary (`localhost:2222` listener appeared before authenticated SSH stabilized), but it resolved inside the existing bounded SSH retry model and did not require a semantic escalation.
- Remaining risks: the helper depends on guest SSH reachability and guest `python3`; the saved `T1` proof uses guest ELF `/usr/bin/ls` rather than a Docker payload ELF; end-to-end NaCC or `riscv-docker/runc` manifest consumption remains intentionally out of scope; no heavy rebuild or repeated-run proof was attempted in this coder turn.

## Review Result

- Approval status: approve-with-conditions
- Spec fidelity: pass
- Fidelity findings:
  - No spec-fidelity failure found. `scripts/generate_manifest_in_vm.sh` is a thin SSH/SCP orchestration wrapper that stages the unchanged `scripts/generate_manifest.py` into guest `/tmp` and runs it there under guest `python3` with guest-visible `--search-root /`.
  - The patch stays on the packet's least-invasive route: one new top-level helper, no manifest schema change, no host-side ELF/interpreter resolution path, and no widening into `scripts/install_manifest.py`, `scripts/stage_probe_root.py`, `riscv-docker/runc`, Linux, OpenSBI, or agent changes.
  - The saved `T1` proof artifacts remain within the approved validation anchor: a real guest-visible dynamic ELF at `/usr/bin/ls`, in-guest manifest generation, and one guest-side coherence check confirming guest-visible entry/interpreter facts.
- Risk review: pass with operational conditions
- Risk findings:
  - The helper assumes a reachable SSH-ready guest and guest `python3`; it has no built-in readiness retry. Test should therefore treat VM readiness and guest prerequisites as explicit preconditions and stop at the first concrete blocker instead of falling back to host generation.
  - The coder-owned `/usr/bin/ls` proof is a valid `T1` anchor, but runner still needs runner-owned evidence for the same VM-first route before this packet can move past test.
- Can proceed to test: yes
- Key files reviewed:
  - `docs/workflow/tasks/active/TASK_20260423_115900_fix_manifest.md`
  - `docs/workflow/CURRENT_STATE.md`
  - `scripts/generate_manifest.py`
  - `scripts/generate_manifest_in_vm.sh`
  - `logs/coder/TASK_20260423_115900_fix_manifest_vm_proof_20260423_124137.log`
  - `logs/coder/TASK_20260423_115900_fix_manifest_vm_manifest_20260423_124209.json`
- Human-facing code explanation:
  - The new helper copies the existing Python manifest generator into guest `/tmp`, runs it there on a guest ELF with `--search-root /`, and then checks that the generated manifest resolves back to real guest-visible entry/interpreter files.
- Why this route still fits the packet:
  - It keeps trust-relevant ELF parsing and `PT_INTERP` resolution inside the VM, preserves the existing generator's schema and fail-closed behavior by reusing that exact helper, and limits the host to SSH/SCP orchestration instead of reopening host-side closure staging or consumer design.
- Requirements checked directly from code:
  - the helper stages the exact `scripts/generate_manifest.py` into the guest rather than reimplementing manifest logic
  - manifest generation runs inside the guest against guest-visible paths only, with explicit `--search-root`
  - the guest-side flow fails closed if the local generator is missing, guest `python3` is absent, or the guest entry path is not a regular file
  - the guest-side coherence check validates manifest-resolved entry/interpreter paths against guest-visible files
  - no manifest schema change and no widening into qcow2 mutation helpers, `riscv-docker/runc`, Linux, OpenSBI, or agent code
- Human-facing summary:
  - Reviewer accepts the VM-first helper for bounded `T1` test handoff. The next run should reproduce the same guest-side flow and preserve the first readiness/prerequisite blocker if the VM is not ready, rather than broadening the route or regenerating the manifest on the host.

## Test Result

- Command run:
  - fresh VM launch via `make launch`
  - `VM_SSH_READY_TIMEOUT_SECONDS=180 make vm VM_AUTO_CMD='true'`
  - `scripts/generate_manifest_in_vm.sh -o /tmp/nacc_manifest_ls.json /usr/bin/ls`
  - host-side copy of guest artifact `/tmp/nacc_manifest_ls.json` to `logs/test_runner/TASK_20260423_115900_fix_manifest_vm_manifest_20260423_130735.json`
- Build actions:
  - no packet-owned component rebuild was run
  - observed local dirtiness in the workspace did not require `linux-update`, `opensbi`, `agent-update`, or `qemu` rebuilds for this bounded VM-first proof
- Outcome:
  - passed; needs_analysis
  - runner-owned `T1` proof completed on guest ELF `/usr/bin/ls`
  - repo-owned readiness gate completed first and reported `[NaCC][ssh-ready] authenticated after 2 attempt(s)`
  - guest-side coherence output confirmed `entry=/usr/bin/ls` and `interp=/usr/lib/ld-linux-riscv64-lp64d.so.1`
  - host-copied manifest artifact SHA-256 matched the guest file: `a765474e05b86f7ecd81c15e938b53e72b4c46a3a19f2763370081b535072345`
  - primary log path: `logs/test_runner/TASK_20260423_115900_fix_manifest_t1_20260423_130735.log`
- Artifact / log path:
  - `logs/test_runner/TASK_20260423_115900_fix_manifest_vm_ready_20260423_130735.log`
  - `logs/test_runner/TASK_20260423_115900_fix_manifest_t1_20260423_130735.log`
  - `logs/test_runner/TASK_20260423_115900_fix_manifest_qemu_20260423_130735.log`
  - `logs/test_runner/TASK_20260423_115900_fix_manifest_vm_manifest_20260423_130735.json`

## Analysis Result

- Observed symptom:
  - Dominant event pattern is: the repo-owned readiness gate waited until authenticated SSH succeeded, then the host helper staged and ran the unchanged manifest generator inside the guest, the guest-side coherence check resolved both `entry` and `interp` to guest-visible files, and the copied manifest matched the guest artifact byte-for-byte.
- Verdict: acceptable
- Key evidence:
  - `logs/test_runner/TASK_20260423_115900_fix_manifest_vm_ready_20260423_130735.log` shows the packet-owned readiness path reaching `[NaCC][ssh-ready] authenticated after 2 attempt(s)` before the no-op guest command was auto-run.
  - `logs/test_runner/TASK_20260423_115900_fix_manifest_t1_20260423_130735.log` shows `scripts/generate_manifest_in_vm.sh` invoking `python3 /tmp/nacc_generate_manifest.py --search-root / -o /tmp/nacc_manifest_ls.json /usr/bin/ls` inside the guest and preserving the guest-side coherence facts `entry=/usr/bin/ls`, `interp=/usr/lib/ld-linux-riscv64-lp64d.so.1`, and `roles=entry,interp`.
  - `logs/test_runner/TASK_20260423_115900_fix_manifest_vm_manifest_20260423_130735.json` records `schema: nacc-manifest-v1alpha1`, `resolution_roots: ["/"]`, `entry.input_path: /usr/bin/ls`, and `entry.interp_resolved_path: /usr/lib/ld-linux-riscv64-lp64d.so.1`, which preserves guest-local resolution rather than host-side loader assumptions.
  - The same T1 log records matching guest and host SHA-256 values `a765474e05b86f7ecd81c15e938b53e72b4c46a3a19f2763370081b535072345`, confirming the copied artifact is the same manifest generated inside the guest.
  - `logs/test_runner/TASK_20260423_115900_fix_manifest_qemu_20260423_130735.log` shows an attempted `make launch` hit `Failed to get "write" lock`, so this rerun should be interpreted as successful proof against a live guest reached through the readiness gate, not as independent proof that a brand-new QEMU instance was created in that exact step.
- Likely cause:
  - The helper and runner flow now satisfy the intended VM-first semantics: trust-relevant ELF parsing and `PT_INTERP` resolution ran in the guest filesystem context after authenticated SSH readiness. The write-lock side signal most likely reflects reuse of an already-running VM rather than a semantic problem in manifest generation itself.
- Confidence:
  - high that the bounded packet goal was met and that the manifest evidence is guest-generated rather than host-generated
  - medium on any claim that this exact rerun also demonstrated a fresh QEMU launch, because the supporting QEMU log points the other way
- Evidence / Inference Boundary:
  - Evidence: readiness succeeded after two authenticated SSH attempts; the guest command path executed `python3 /tmp/nacc_generate_manifest.py --search-root / ... /usr/bin/ls`; the coherence check and JSON both resolve the interpreter to guest path `/usr/lib/ld-linux-riscv64-lp64d.so.1`; and host/guest manifest hashes match exactly.
  - Inference: this is sufficient to say the packet's bounded VM-first proof is complete and human-closeout-ready.
  - Not claimed as fact: that the follow-up rerun created a brand-new VM instance. The QEMU write-lock artifact makes that freshness claim weaker than the core in-guest manifest proof.
- Human-facing summary:
  - This packet now has acceptable closeout evidence for the intended `T1` scope. The important thing proved is not "host copied a manifest around" but that the existing manifest generator semantics ran inside the guest, resolved the guest's own interpreter path, and produced a host-copied artifact identical to the guest file after the repo-owned readiness gate confirmed authenticated SSH. The copied file should be read as exported evidence of the same guest-generated manifest, not as a separate semantic stage.
- Recommended next owner:
  - `planner`
- Recommended next step:
  - preserve this packet as the accepted VM-first proof and have planner define the next bounded step, likely around in-VM manifest consumption or a stronger integration target, using the recorded workflow notes about `make vm VM_AUTO_CMD='...'` and the in-guest `runc` hook/build path

## Open Questions

- No blocking semantic questions remain for this packet.
- Residual uncertainty is operational only: whether a future packet wants an explicitly fresh-boot rerun or broader workload coverage beyond `/usr/bin/ls`.
