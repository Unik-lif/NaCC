# PRIVATE_DATA T1 181934 Run-Family Readout

Date: 2026-04-20
Scope: `private-baseline-t1-20260419_181934`
Artifacts:
- `logs/private-baseline-t1-20260419_181934.launcher.log`
- `logs/private_baseline_t1_01_20260419_181934_qemu_20260419_182419.log`
- `logs/private_baseline_t1_02_20260419_182419_qemu_20260419_182922.log`
- `logs/private_baseline_t1_03_20260419_182923_qemu_20260419_183426.log`
- `logs/private_baseline_t1_04_20260419_183426_qemu_20260419_183913.log`
- `logs/private_baseline_t1_05_20260419_183914_qemu_20260419_184357.log`
- `logs/private_baseline_t1_06_20260419_184357_qemu_20260419_184844.log`
- `logs/private_baseline_t1_07_20260419_184844_qemu_20260419_185343.log`
- `logs/private_baseline_t1_08_20260419_185343_qemu_20260419_185832.log`

## How To Read The Final Block

These fields are not all answering the same question.

| Field | What it means | Exact or bounded |
| --- | --- | --- |
| `region: root_pfn ... leaf_private=...` | How many user leaf pages ended up tagged private under this root | Exact snapshot |
| `region: decisions ... set=... leave_off=...` | How many tag decisions happened at `reconcile` / `install` touchpoints | Exact decision counters, not unique pages |
| `PRIVATE_DATA trap stats` | Total mediated traps | Exact |
| `PRIVATE_DATA width` | Access widths for trapped loads/stores | Exact |
| `PRIVATE_DATA category` | Path classification: what kind of runtime path the trap happened on | Exact |
| `PRIVATE_DATA provenance[]` | Hot source buckets: which private user ranges were hit most often | Bounded heavy-hitter summary |
| `PRIVATE_DATA mepc[]` | Hot PCs: which PCs were hottest at trap time | Bounded heavy-hitter summary |

The practical reading rule for this family is:

- `category` answers: "Which path is paying the trap cost?"
- `provenance` answers: "Which user-side source/range is being touched?"
- `mepc` answers: "Which PC was executing when the trap was recorded?"

For this packet, many final `mepc[]` entries are kernel helper PCs, so `mepc` is often a poor source identifier. `provenance[]` is the better source signal.

## Why Only 8 `mepc[]` And 8 `provenance[]`

The limit is hardcoded in OpenSBI:

- `NACC_PRIVATE_DATA_PC_SLOTS = 8` in [opensbi/lib/sbi/sbi_trap_ldst.c](/home/link/NaCC/opensbi/lib/sbi/sbi_trap_ldst.c:28)
- `NACC_PRIVATE_DATA_PROVENANCE_SLOTS = 8` in [opensbi/lib/sbi/sbi_trap_ldst.c](/home/link/NaCC/opensbi/lib/sbi/sbi_trap_ldst.c:29)

The recording logic is bounded on purpose:

- If a new trap matches an existing `mepc` bucket or provenance bucket, that bucket is incremented.
- If no match exists and there is an empty slot, the new item gets the empty slot.
- If all slots are full, the new item replaces the current smallest bucket.

Relevant code:

- provenance heavy-hitter replacement: [opensbi/lib/sbi/sbi_trap_ldst.c](/home/link/NaCC/opensbi/lib/sbi/sbi_trap_ldst.c:333)
- `mepc` heavy-hitter replacement: [opensbi/lib/sbi/sbi_trap_ldst.c](/home/link/NaCC/opensbi/lib/sbi/sbi_trap_ldst.c:398)
- final descending sort before print: [opensbi/lib/sbi/sbi_trap_ldst.c](/home/link/NaCC/opensbi/lib/sbi/sbi_trap_ldst.c:502)

So the printed `mepc[]` and `provenance[]` are not full histograms. They are bounded "keep the hottest few" summaries. That is why they are useful for hot-path triage, but not for complete attribution accounting.

## Run-By-Run Summary

### Compact Table

| Run | Workload | `leaf_private` | Trap total | Category split | Top provenance signal | `mepc` shape | Plain-language read |
| --- | --- | ---: | ---: | --- | --- | --- | --- |
| 01 | `printf alpha >/dev/null` | 470 | 39082 | syscall-buffer 29495 (75.5%), mapping-update 9587 (24.5%) | anon 681, anon 663, COW 157 | 8 adjacent kernel helper PCs, each about 4885 hits | Minimal syscall path baseline. Cost is dominated by S-mode copy/helper traffic, not by a single user PC. |
| 02 | `read /etc/hostname` | 454 | 38339 | syscall-buffer 28566 (74.5%), mapping-update 9773 (25.5%) | anon 784, anon 765, COW 157 | same 8-PC helper cluster, each about 4792-4793 hits | Same shape as run 01. Simple read path still spends most trap cost in helper-side buffering. |
| 03 | fork-private repro | 495 | 115230 | syscall-buffer 100799 (87.5%), mapping-update 14431 (12.5%) | anon 971, anon 747, fork-anon 298, COW 157 | same helper cluster, each about 14404 hits | Fork/COW pressure explodes total traps. Still helper-heavy, but anonymous forked ranges become clearly visible. |
| 04 | `cat /etc/hostname` | 461 | 112238 | syscall-buffer 86321 (76.9%), mapping-update 25917 (23.1%) | anon 948, anon 783, anon 585, COW 213 | same helper cluster, each about 14030 hits | File read is still helper-dominated on top, but provenance shows loader and `cat`-side file-backed ranges underneath. |
| 05 | `echo alpha | cat` | 463 | 112560 | syscall-buffer 78842 (70.0%), mapping-update 33718 (30.0%) | anon 1227, anon 867, anon 641, COW 226 | same helper cluster, each about 14070 hits | Pipe + `cat` increases mapping churn. Still helper-dominated, with file-backed loader/cat ranges visible under the surface. |
| 06 | `wc -c /etc/hostname` | 452 | 121143 | syscall-buffer 93720 (77.4%), mapping-update 27423 (22.6%) | anon 949, anon 789, anon 632, COW 213 | one extra store-heavy helper PC plus the usual helper cluster | `wc` on a file keeps the same overall shape, but one kernel helper PC stands out as an extra hot store loop. |
| 07 | `echo alpha | wc -c` | 481 | 129714 | syscall-buffer 98106 (75.6%), mapping-update 31608 (24.4%) | anon 1227, anon 885, anon 662, COW 230 | same helper cluster, each about 16214-16215 hits | This is the trap-heaviest helper-driven run. Pipeline cost is very concentrated in a tiny S-mode helper loop. |
| 08 | `/nacc_shm_repro` | 129 | 12817 | syscall-buffer 3601 (28.1%), mapping-update 9216 (71.9%) | file-COW 247, anon 213, anon 188, shared file-fault 4 | mixed: syscall-buffer PC plus teardown PCs | Shared-memory repro is qualitatively different: teardown / `munmap` dominates, and the shared-file bucket finally surfaces directly. |

### Per-Run Readout

#### Run 01

- Workload: `printf alpha >/dev/null; echo kernel_read_done`
- Private coverage: `leaf_private=470`, and no `leave_off` counters were nonzero anywhere in the family.
- Readout:
  - This is the cleanest "minimal syscall path" baseline.
  - Even here, about three quarters of traps are already in `syscall_buffer_path`.
  - The hottest provenance buckets are two anonymous ranges; the file-backed activity is present but much smaller.
  - The top 8 `mepc` entries are basically one small helper loop in the kernel.

#### Run 02

- Workload: `IFS= read -r line </etc/hostname; echo kernel_write_done`
- Private coverage: `leaf_private=454`
- Readout:
  - Very similar to run 01.
  - Reading a single line from a file does not make final attribution file-dominant; the helper/copy path still dominates the top-level cost.
  - The file-backed side is visible only as a smaller COW bucket under the helper-heavy top-line categories.

#### Run 03

- Workload: large shell-local string mutation plus `fork_private_done`
- Private coverage: `leaf_private=495`
- Readout:
  - This is the first run where total traps jump sharply.
  - The dominant cost is still helper-side, but the provenance table now clearly shows fork-related anonymous ranges in both parent and child roots.
  - A small `file_fault` bucket does survive in the final provenance output, so this run still preserves some file-backed attribution even though the top-line story is "helper-heavy fork/COW".

#### Run 04

- Workload: `cat /etc/hostname; echo done`
- Private coverage: `leaf_private=461`
- Key source joins:
  - loader range joins to `/lib/ld-linux-riscv64-lp64d.so.1` at [15767](/home/link/NaCC/logs/private_baseline_t1_04_20260419_183426_qemu_20260419_183913.log:15767) through [15770](/home/link/NaCC/logs/private_baseline_t1_04_20260419_183426_qemu_20260419_183913.log:15770)
  - `cat` text/data ranges are visible at [15754](/home/link/NaCC/logs/private_baseline_t1_04_20260419_183426_qemu_20260419_183913.log:15754) through [15756](/home/link/NaCC/logs/private_baseline_t1_04_20260419_183426_qemu_20260419_183913.log:15756)
- Readout:
  - Top-line numbers still say "kernel helper + mapping churn".
  - But unlike runs 01-02, the file probe now leaves direct file-backed breadcrumbs that can be joined back to real paths.
  - In other words: the path is still helper-heavy, but the source is no longer opaque.

#### Run 05

- Workload: `echo alpha | cat; echo done`
- Private coverage: `leaf_private=463`
- Key source joins:
  - loader range joins to `/lib/ld-linux-riscv64-lp64d.so.1` at [21378](/home/link/NaCC/logs/private_baseline_t1_05_20260419_183914_qemu_20260419_184357.log:21378) through [21381](/home/link/NaCC/logs/private_baseline_t1_05_20260419_183914_qemu_20260419_184357.log:21381)
  - `cat` ranges are visible at [21365](/home/link/NaCC/logs/private_baseline_t1_05_20260419_183914_qemu_20260419_184357.log:21365) through [21367](/home/link/NaCC/logs/private_baseline_t1_05_20260419_183914_qemu_20260419_184357.log:21367)
- Readout:
  - Piping through `cat` increases mapping-update cost relative to run 04.
  - Final provenance is still anonymous-heavy in the top slots, but the underlying file-backed path is clearly joinable.
  - This run is a good example of why `category` and `provenance` must be read separately.

#### Run 06

- Workload: `wc -c /etc/hostname; echo done`
- Private coverage: `leaf_private=452`
- Key source joins:
  - `wc` ranges at [15388](/home/link/NaCC/logs/private_baseline_t1_06_20260419_184357_qemu_20260419_184844.log:15388) through [15390](/home/link/NaCC/logs/private_baseline_t1_06_20260419_184357_qemu_20260419_184844.log:15390)
  - `libc` ranges at [15391](/home/link/NaCC/logs/private_baseline_t1_06_20260419_184357_qemu_20260419_184844.log:15391) through [15393](/home/link/NaCC/logs/private_baseline_t1_06_20260419_184357_qemu_20260419_184844.log:15393)
  - loader ranges at [15401](/home/link/NaCC/logs/private_baseline_t1_06_20260419_184357_qemu_20260419_184844.log:15401) through [15403](/home/link/NaCC/logs/private_baseline_t1_06_20260419_184357_qemu_20260419_184844.log:15403)
- Readout:
  - Same overall helper-heavy shape, but `mepc[0]` is no longer part of the usual tiny `800b03de`-style cluster.
  - One additional store-heavy helper PC stands out, which suggests `wc` is exercising a different helper micro-path on top of the common copy loop.
  - Final provenance remains anon-dominant, with file-backed loader/libc evidence visible via Linux-side range provenance.

#### Run 07

- Workload: `echo alpha | wc -c; echo done`
- Private coverage: `leaf_private=481`
- Key source joins:
  - loader range joins at [21592](/home/link/NaCC/logs/private_baseline_t1_07_20260419_184844_qemu_20260419_185343.log:21592) through [21595](/home/link/NaCC/logs/private_baseline_t1_07_20260419_184844_qemu_20260419_185343.log:21595)
  - `wc` ranges are visible at [21579](/home/link/NaCC/logs/private_baseline_t1_07_20260419_184844_qemu_20260419_185343.log:21579) through [21581](/home/link/NaCC/logs/private_baseline_t1_07_20260419_184844_qemu_20260419_185343.log:21581)
- Readout:
  - This is the most trap-heavy helper-dominated pipeline run in the family.
  - The top-line category counts are still dominated by `syscall_buffer_path`, and the hottest `mepc[]` entries are an almost perfectly flat helper loop.
  - Provenance keeps the user-side anonymous and file-COW hotspots visible, but `mepc` by itself would look misleadingly "all kernel".

#### Run 08

- Workload: `busybox /nacc_shm_repro`
- Private coverage: `leaf_private=129`
- Key source joins:
  - `/nacc_shm_repro` private-file ranges at [3165](/home/link/NaCC/logs/private_baseline_t1_08_20260419_185343_qemu_20260419_185832.log:3165) through [3167](/home/link/NaCC/logs/private_baseline_t1_08_20260419_185343_qemu_20260419_185832.log:3167)
  - shared file bucket `/dev/shm/nacc-mini-shm-1` at [3168](/home/link/NaCC/logs/private_baseline_t1_08_20260419_185343_qemu_20260419_185832.log:3168)
- Readout:
  - This run is the outlier in the family.
  - Only about 28% of final traps are in `syscall_buffer_path`; almost 72% are `teardown_mapping_update`.
  - This is the clearest proof that the counters are not "always helper-only": once the workload shifts to shared-memory teardown, the top-line category distribution changes qualitatively and the shared-file provenance bucket becomes visible in the final block.

## Cross-Run Conclusions

### 1. The family is successful, not failing

- All 8 runs completed successfully in the launcher summary.
- This family is measuring the fail-closed upper bound, not isolating a crash point.

### 2. For 7 out of 8 runs, the dominant path cost is helper-side

- Runs 01-07 all end with `syscall_buffer_path` as the top category.
- The practical meaning is: once all ordinary user leaf pages are forced private, a large fraction of the cost is paid when the kernel touches those user buffers on behalf of the task.

### 3. `provenance[]` is the right place to look for source identity

- `mepc[]` often points to kernel helper PCs and may carry `range=[0,0)` / `class=INVALID`.
- `provenance[]` is where the user-side hot anonymous ranges and file-backed/COW ranges survive.
- Linux-side `region provenance` logs are what let those file-backed ranges be joined back to real paths.

### 4. `mepc[]` still matters

- It tells you whether the cost is concentrated or diffuse.
- In runs 01-05 and 07, the top 8 PCs form an extremely flat, tiny helper loop.
- In run 06, one extra helper PC becomes visibly dominant.
- In run 08, `mepc[]` splits between helper-side PCs and teardown-side PCs, which matches the top-line category flip.

### 5. Why the current summary still feels "hard to read"

- The exact totals are in `trap stats`, `width`, and `category`.
- But the source attribution is only available through bounded heavy-hitter summaries plus Linux range-to-path logs.
- So the system is already decision-useful, but not yet a one-line "full histogram of all sources" report.

## Practical Reading Order For A New Log

When reading a future final block, use this order:

1. `trap stats`: How large is the total burden?
2. `category`: Is this helper-heavy or mapping-update-heavy?
3. `provenance[]`: Which user-side ranges are actually hot?
4. `mepc[]`: Is the burden concentrated in a tiny helper loop, or spread across different PCs?
5. Linux `region provenance`: If file-backed ranges matter, join them back to real file paths.

## Bottom Line

The most important takeaway from the `181934` family is:

- The fail-closed baseline works.
- The dominant trap cost for ordinary file/pipe/fork probes is usually not "a mysterious user PC"; it is S-mode helper traffic touching now-private user pages.
- Even so, the final output is already good enough to recover the hot user-side sources through `provenance[]` and Linux `region provenance`.
