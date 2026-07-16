# XS-GEM5 Migration Milestones

Date: 2026-06-29

Context:
- Goal: move the NaCC runtime environment from the current QEMU-based flow to XS-GEM5.
- Existing local setup note: `record/20260624_xsgem5_setup.md`.
- Preferred strategy: bring up a standard XS-GEM5 flow first, then migrate NaCC features incrementally.
- Non-goal for the first pass: fully understand or rewrite GEM5 before there is a runnable baseline.

## Guiding Principle

Use runnable milestones to drive learning.

XS-GEM5/GEM5 has a large code surface. Learn the simulator architecture in the order forced by concrete blockers:
1. boot/config/checkpoint path;
2. RISC-V platform and device model;
3. privilege/CSR/trap behavior;
4. MMU/TLB/page-table walker;
5. PMP or memory protection checks;
6. timing/performance details.

Do not start by broadly reading GEM5 internals. Start by making the standard flow reproducible, then use NaCC bring-up failures to identify the exact simulator component to study or modify.

## Milestone 0: XS-GEM5 Baseline Is Reproducible

Purpose:
- Confirm the host build and launch environment is stable.

Inputs:
- `GEM5/build/RISCV/gem5.opt`
- `scripts/xsgem5-env.sh`
- `scripts/xsgem5-build.sh`
- `make gem5`

Exit criteria:
- `make gem5` completes or confirms the existing binary is valid.
- `GEM5/build/RISCV/gem5.opt -h` works.
- `GEM5/build/RISCV/gem5.opt GEM5/configs/example/kmhv3.py --help` works.
- A short command log is saved under `logs/` or summarized in `record/`.

Known note:
- The setup note from 2026-06-24 records the Anaconda/protobuf trap. Keep using the strict system `PATH` wrappers.

## Milestone 1: Run a Standard XS-GEM5 RISC-V Flow

Purpose:
- Establish a known-good simulator baseline before introducing NaCC.

Target:
- Run the upstream-supported XS-GEM5 RISC-V flow, either:
  - raw bare-metal image via `--raw-cpt --generic-rv-cpt=<bin>`; or
  - XiangShan/NEMU-style GCPT checkpoint via `--generic-rv-cpt=<checkpoint.gz>`.

Exit criteria:
- The simulator starts from a documented command.
- Console or simulator output shows expected progress.
- The required Difftest/reference/restorer inputs are identified:
  - `GCBV_REF_SO`
  - `GCB_REF_SO`, if needed
  - `GCB_RESTORER`
  - `GCBV_RESTORER`, if needed
  - `GCB_MULTI_CORE_RESTORER`, if needed
- Log and exact command are saved.

Questions to answer:
- Is the practical baseline a raw bare-metal binary or a GCPT checkpoint?
- Is Difftest required for all useful runs, or can it be disabled locally for early bring-up?
- What is the minimal input format XS-GEM5 accepts for a Linux/full-system run?

## Milestone 2: Inventory the Current QEMU Boot Contract

Purpose:
- Make the QEMU-to-XS-GEM5 delta explicit before porting.

Inventory items:
- Firmware/OpenSBI image path and load address.
- Linux image format, load address, and boot arguments.
- DTB source and generated DTB actually used by QEMU.
- Rootfs/initrd/disk image format.
- Console device and earlycon settings.
- Machine memory map.
- CPU count and ISA extensions.
- CLINT/PLIC/UART/virtio devices.
- Any QEMU-specific changes in CPU, CSR, MMU, PMP, trap, or device behavior.
- Host scripts that currently encode the launch contract.

Exit criteria:
- A short `record/` note or table maps each QEMU dependency to one of:
  - already supported by XS-GEM5;
  - needs configuration/DTB work;
  - needs image/checkpoint conversion;
  - needs GEM5 model changes;
  - unknown.

## Milestone 3: Boot Non-NaCC Linux on XS-GEM5

Purpose:
- Separate "can XS-GEM5 boot Linux here?" from "can NaCC security semantics work?"

Target:
- Boot a plain RISC-V Linux/rootfs path accepted by XS-GEM5.

Exit criteria:
- Kernel reaches early console at minimum.
- Preferably reaches userspace shell or a deterministic init command.
- Exact image inputs, DTB, command line, simulator command, and log are saved.

Likely learning areas:
- XS-GEM5 config scripts.
- Platform memory map and DTB generation.
- UART/console path.
- Checkpoint/restorer expectations.

## Milestone 4: Boot NaCC Linux with NaCC Disabled or Minimal

Purpose:
- Prove the NaCC kernel tree can boot in XS-GEM5 without requiring complete NaCC security behavior.

Target:
- Use the NaCC Linux build, but keep NaCC hooks disabled, bypassed, or in a minimum logging-only mode where possible.

Exit criteria:
- NaCC Linux reaches the same stage as Milestone 3.
- Any boot breakage is classified as:
  - image/load/DTB mismatch;
  - missing device/platform feature;
  - RISC-V privilege/CSR mismatch;
  - MMU/TLB behavior mismatch;
  - NaCC-specific monitor/agent dependency.

Likely learning areas:
- Kernel boot protocol expected by XS-GEM5.
- DTB compatibility.
- RISC-V CSR and exception behavior in GEM5.

## Milestone 5: Boot NaCC OpenSBI + NaCC Linux

Purpose:
- Bring the M-mode NaCC Monitor path into the simulator.

Target:
- XS-GEM5 loads the NaCC OpenSBI image and then boots NaCC Linux.

Exit criteria:
- OpenSBI banner and NaCC-specific Monitor init logs appear.
- Linux receives a sane hart state and DTB.
- SBI calls used by NaCC can be observed.
- The first failure after enabling the Monitor has a bounded log and classified root cause.

Likely learning areas:
- XS-GEM5 reset vector and firmware load path.
- M-mode trap delegation and SBI ecall handling.
- RISC-V privilege CSRs in GEM5.

## Milestone 6: Bring Up the Minimal NaCC Agent/Monitor Interaction

Purpose:
- Validate the smallest end-to-end NaCC control path before testing isolation.

Target:
- One minimal NaCC operation crosses Linux -> SBI/Monitor -> Agent/metadata path, with logging enough to prove control flow.

Exit criteria:
- A deterministic smoke case triggers the NaCC path.
- Monitor/Agent/kernel logs agree on the request type and target address/page.
- Failure modes are localizable without scanning huge logs.

Likely learning areas:
- Trap/exception path.
- Bare-metal Agent memory placement.
- Shared memory or metadata layout.
- Simulator support for the exact access pattern.

## Milestone 7: Validate Page-Table Isolation Semantics

Purpose:
- Check whether XS-GEM5 models the hardware semantics NaCC relies on.

Target checks:
- `satp` writes and address-space changes.
- `sfence.vma` behavior.
- TLB invalidation and stale translation behavior.
- Page-table walker permission checks.
- Supervisor/User access checks, including `SUM`-related paths if relevant.
- PMP or other M-mode protection behavior if NaCC depends on it.
- Fault cause and trap value correctness.

Exit criteria:
- A small test matrix proves expected allow/deny behavior.
- Any simulator gaps are mapped to concrete GEM5 files/components before editing.
- Security invariant failures are separated from performance/timing issues.

Likely learning areas:
- RISC-V TLB implementation.
- Page-table walker.
- Physical memory request path.
- PMP/protection checker.
- CSR side effects.

## Milestone 8: Port or Patch XS-GEM5 Hardware Semantics

Purpose:
- Modify XS-GEM5 only for hardware behavior that NaCC requires and the baseline does not provide.

Patch candidates:
- RISC-V CSR implementation.
- Trap/delegation behavior.
- TLB/page-table walker behavior.
- PMP or memory-protection checks.
- Memory map/platform model.
- Device model only if it blocks boot or workload execution.

Exit criteria:
- Each simulator patch has:
  - a minimal reproducer;
  - a before/after log;
  - a comment explaining the NaCC hardware assumption;
  - a regression command.

Rule:
- Do not mix many semantic changes in one patch. Keep each GEM5 modification tied to one observed failure.

## Milestone 9: Workload and Performance Rebaseline

Purpose:
- Re-establish NaCC functional and performance expectations under XS-GEM5.

Target:
- Start with tiny deterministic smoke tests, then selected workloads.
- Only after correctness is stable, compare performance trends.

Exit criteria:
- A small workload set runs repeatedly.
- Logs are bounded and named.
- Differences from QEMU are classified as:
  - expected simulator/platform difference;
  - XS-GEM5 model limitation;
  - NaCC portability bug;
  - measurement artifact.

## Suggested Immediate Next Step

Start with Milestone 1, not broad GEM5 architecture reading.

Concrete next work item:
- Build or obtain the smallest standard XS-GEM5 RISC-V input that is known to work with `configs/example/kmhv3.py`.
- Save the exact run command and result log.
- If it fails, classify whether the blocker is Difftest/reference/restorer setup, checkpoint format, or simulator config.

After Milestone 1 is stable, do Milestone 2 in parallel with light GEM5 reading. The first code areas to learn should be whichever files directly explain the launch/config path and boot failure, not the whole simulator.

