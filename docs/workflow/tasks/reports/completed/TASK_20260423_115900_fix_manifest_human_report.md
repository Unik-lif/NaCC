# Human Progress Report

- Task ID: TASK_20260423_115900_fix_manifest
- Task Packet: `docs/workflow/tasks/active/TASK_20260423_115900_fix_manifest.md`
- Created: 2026-04-23 11:59:00 +0800
- Purpose: cumulative human-readable updates appended by coder, reviewer, and log_analyzer
- Append Rule: add a new timestamped section for each new turn; do not rewrite older entries
- Reading Hint: newest updates are appended at the end of this file

## 2026-04-23 Planner Bootstrap Update

- Seeded the fresh packet from human intent instead of inferring from the task name.
- Locked the task boundary to `Goal / Constraints / Definition Of Done`: this round is only about establishing and validating an in-VM `manifest.json` generation path that avoids the known host/guest `ld-linux` mismatch.
- Carried forward only durable history from the archived manifest MVP packet: the old host-side validation anchor is treated as semantically misaligned for this follow-on step, and widening host-side closure staging again is not the default answer.
- Recorded the key environment correction from the human: `riscv-docker/runc` is an in-VM path inside `NaCC.qcow2`, not a repo-side path in the host workspace.
- Shaped the next coder handoff around a VM-first route:
  - launch or reuse the VM
  - enter via SSH / `make vm-debug`
  - inspect the guest environment
  - implement the smallest workable in-VM manifest-generation proof
  - stop at the first credible proof or first concrete blocker
- Current host observation added to the packet: `localhost:2222` is not listening right now, so guest launch/readiness must be treated as an explicit precondition for the next turn.

## 2026-04-23 12:44:01 +0800 Coder Update

- Changed file: `scripts/generate_manifest_in_vm.sh`.
- Why this was needed: the packet's primary proof route requires manifest generation itself to run inside the RISC-V guest, with the host limited to SSH orchestration. The new helper stages the existing `scripts/generate_manifest.py` into guest `/tmp`, runs it there with guest-visible search root `/`, and then performs one guest-side coherence check on the generated manifest.
- What changed in code:
  - added a small Bash helper that uses `sshpass`/`scp` when available, otherwise plain `ssh`/`scp`
  - keeps `scripts/generate_manifest.py` unchanged and reuses it verbatim inside the guest
  - prints the exact guest generation command and guest coherence-check boundary into the saved proof log
  - fails closed if the local generator is missing, guest `python3` is unavailable, or the guest entry path is not a regular file
- What I intentionally left unchanged:
  - no manifest schema changes
  - no edits to `scripts/generate_manifest.py`
  - no reuse of `scripts/install_manifest.py` or `scripts/stage_probe_root.py` as the primary route
  - no Makefile target changes
  - no Linux / OpenSBI / agent / `riscv-docker/runc` consumer work
- Cheap bounded sanity checks run:
  - `bash -n scripts/generate_manifest_in_vm.sh`
  - `python3 -m py_compile scripts/generate_manifest.py`
- Bounded VM-first proof run:
  - booted the guest with `make launch`
  - verified guest prerequisite `python3` over SSH and chose guest-resident ELF `/usr/bin/ls`
  - ran `scripts/generate_manifest_in_vm.sh -o /tmp/nacc_manifest_ls.json /usr/bin/ls`
  - the helper's in-guest command was `python3 /tmp/nacc_generate_manifest.py --search-root / -o /tmp/nacc_manifest_ls.json /usr/bin/ls`
  - the guest-side coherence check confirmed `entry=/usr/bin/ls`, `interp=/usr/lib/ld-linux-riscv64-lp64d.so.1`, and `roles=entry,interp`
- Preserved artifacts:
  - proof log: `logs/coder/TASK_20260423_115900_fix_manifest_vm_proof_20260423_124137.log`
  - copied manifest artifact: `logs/coder/TASK_20260423_115900_fix_manifest_vm_manifest_20260423_124209.json`
- What is intentionally deferred to reviewer / test_runner:
  - spec-fidelity review that this helper is still the least invasive VM-first route
  - any repeated-run or heavier proof beyond this first `T1` in-guest generation check
  - any later manifest consumer work in `riscv-docker/runc` or Linux/OpenSBI

## 2026-04-23 12:46:13 +0800 Reviewer Update

- Verdict: approve-with-conditions for bounded `T1` test handoff.
- What I checked directly:
  - `docs/workflow/tasks/active/TASK_20260423_115900_fix_manifest.md`
  - `docs/workflow/CURRENT_STATE.md`
  - `scripts/generate_manifest_in_vm.sh`
  - `scripts/generate_manifest.py`
  - `logs/coder/TASK_20260423_115900_fix_manifest_vm_proof_20260423_124137.log`
  - `logs/coder/TASK_20260423_115900_fix_manifest_vm_manifest_20260423_124209.json`
  - `bash -n scripts/generate_manifest_in_vm.sh`
  - `python3 -m py_compile scripts/generate_manifest.py`
  - `git diff --check -- scripts/generate_manifest_in_vm.sh`
- Most important findings:
  - No spec-fidelity failure found. The helper keeps the host as an SSH/SCP orchestrator only and runs the unchanged `scripts/generate_manifest.py` inside the guest with guest-visible `--search-root /`.
  - The route stays least-invasive: one new top-level helper, no schema change, no host-side ELF/interpreter authority, no fallback to `scripts/install_manifest.py` or `scripts/stage_probe_root.py`, and no widening into `riscv-docker/runc`, Linux, OpenSBI, or agent work.
  - Remaining risk is operational rather than semantic: the helper assumes an SSH-ready guest and guest `python3`, so runner must preserve the first prerequisite blocker instead of silently falling back to host generation.
- Plain-English code explanation:
  - `scripts/generate_manifest_in_vm.sh` copies the existing Python manifest generator into guest `/tmp`, runs it there against a guest ELF, and then checks that the generated manifest points back to real guest-visible files for the entry and interpreter.
- What the human should watch next:
  - runner-owned proof should reproduce the same in-guest `/usr/bin/ls` flow or stop immediately on the first concrete readiness/prerequisite blocker
  - this round should not widen into `riscv-docker/runc` consumption, qcow2/rootfs mutation helpers, or host-side manifest regeneration

## 2026-04-23 13:12:18 +0800 Log Analyzer Update

- Verdict: acceptable for the packet's bounded `T1` goal and ready for human closeout.
- Dominant runtime pattern: the repo-owned readiness gate waited for authenticated SSH first, then the helper staged and ran the unchanged `scripts/generate_manifest.py` inside the guest, and the guest-side coherence check plus copied artifact matched the expected guest-visible `entry` and `interp` facts.
- Key evidence:
  - `logs/test_runner/TASK_20260423_115900_fix_manifest_vm_ready_20260423_130735.log` reports `[NaCC][ssh-ready] authenticated after 2 attempt(s)` before any manifest helper work.
  - `logs/test_runner/TASK_20260423_115900_fix_manifest_t1_20260423_130735.log` records in-guest execution of `python3 /tmp/nacc_generate_manifest.py --search-root / -o /tmp/nacc_manifest_ls.json /usr/bin/ls` and preserves `coherence_entry_realpath=/usr/bin/ls` plus `coherence_interp_realpath=/usr/lib/ld-linux-riscv64-lp64d.so.1`.
  - `logs/test_runner/TASK_20260423_115900_fix_manifest_vm_manifest_20260423_130735.json` preserves guest-local resolution facts, including `entry.interp_resolved_path=/usr/lib/ld-linux-riscv64-lp64d.so.1` and `resolution_roots: ["/"]`.
  - The same T1 log records matching guest/host SHA-256 `a765474e05b86f7ecd81c15e938b53e72b4c46a3a19f2763370081b535072345`, so the host artifact is the exact manifest produced in the guest.
- What this means for the next decision:
  - The packet's actual proof target is satisfied: manifest generation and ELF/interpreter resolution moved into the VM and no longer depend on host-side `ld-linux` interpretation for this bounded flow.
  - This packet does not need another machine turn unless the human wants to widen scope beyond the approved `T1` boundary.
- Remaining uncertainty:
  - `logs/test_runner/TASK_20260423_115900_fix_manifest_qemu_20260423_130735.log` shows `make launch` hit a qcow2 write lock, so this rerun is best described as successful proof against a live guest reached through the readiness gate, not as independent evidence of a brand-new boot in that exact step.
  - Broader follow-on work such as Docker payload coverage or `riscv-docker/runc` manifest consumption still belongs in a fresh packet, not as an extension of this one.

## 2026-04-23 17:04:36 +0800 Log Analyzer Update

- Human-directed handoff adjustment recorded into the packet: this round should be treated as a repair / workflow-alignment proof, not as a semantically separate stage created by SCP copy-out. The host-side copied `manifest.json` is evidence export of the same guest-generated artifact.
- Added follow-on workflow notes for planner:
  - for agent-driven guest command execution, prefer the repo-owned readiness path `make vm VM_AUTO_CMD='...'` instead of ad hoc direct SSH entry
  - if a later round needs `runc` to ingest `manifest.json`, inspect `/root/riscv-docker/runc/libcontainer/standard_init_linux.go` near the terminal registration syscall path first
  - after in-guest `runc` edits, expect to run in-guest `make && make install` and budget for a long-running build/install step before validation
- Packet handoff target changed from `human` to `planner` so the next machine turn can define the next bounded scope without reopening the completed VM-first proof in this packet.
