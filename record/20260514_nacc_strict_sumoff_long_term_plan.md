# 2026-05-14 NaCC strict SUM-off private data long-term plan

## Context

The earlier refcount/lifecycle work reduced one broad class of Linux ordinary-page
lifecycle interference with NaCC private user leaf data pages. In the T1 run
summarized by `record/20260514_nacc_refcount_t1_sum_trap_readout.md`,
workloads 1 and 2 reached `SUM-off = 0`, but workloads 3 through 8 still showed
SUM-off private-data traps.

The remaining events were concentrated:

- all observed SUM-off private-data events were loads, not stores;
- the access class was `kernel_high`;
- the top PC cluster resolved to `__pi___memcpy` in
  `linux/arch/riscv/lib/memcpy.S`.

## Long-Term Direction

SUM-on accesses are comparatively easier to constrain because Linux user-memory
accesses tend to cluster around explicit SUM enable/disable sites. SUM-off
accesses may be more scattered, especially around COW, page copy, pipe/iov_iter,
or shmem paths. The long-term goal is to reduce or eliminate direct Linux
touches of private-data bitmap pages while SUM is off.

The desired end-state is an explicit mediation model:

- Linux must not directly read or modify NaCC private user leaf pages through
  SUM-off direct-map/kernel-high paths.
- If Linux needs data from, or needs to apply changes to, a private user leaf
  page, Linux should describe the operation in a shared region.
- A trusted component such as SBI/OpenSBI monitor or the NaCC agent should
  perform the actual private-page read/write on Linux's behalf.
- The interface should cover both directions when needed:
  - private source page to shared/public destination;
  - shared/public source to private destination.

## Why This Is Deferred

This is too large for a single blind implementation step. The first useful move
is to identify the concrete Linux call stack for workload 3's first SUM-off
private-data `memcpy` trap. That smaller task can determine whether the first
offending path is COW/page-copy, fork copy, pipe/iov_iter, shmem, or something
else.

## Immediate Follow-Up

Use task packet `TASK_20260514_165833_nacc_strict_sum_off` for the first
small-step diagnostic:

- enable strict deny for `SUM-off + kernel_high/direct-map + private data PFN`;
- print minimal first-deny evidence;
- resolve `pc` and `ra`;
- add temporary Linux-side stack dumps only if `ra` is insufficient;
- run workload 3 only.
