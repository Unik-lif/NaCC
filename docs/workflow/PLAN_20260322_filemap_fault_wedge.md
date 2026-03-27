# Filemap / Page-Fault Wedge Plan

## Problem

- `docker run --security-opt seccomp=unconfined --rm busybox sh -c "echo alpha | wc -c; echo done"` is not a valid pass.
- The strongest current signal is not "`wc` itself is broken". The stronger signal is that `wc` exposes a file-backed mapping / `filemap_map_pages()` / page-fault semantic wedge.

## Why This Matters

- This is not a harmless compatibility corner case.
- Commands like `wc` exercise:
  - `exec`
  - file-backed mapping
  - page fault
  - `filemap_map_pages()`
- Those paths are tightly related to:
  - shared memory / `mmap`
  - small real applications
  - Ubuntu-scale workloads
- This wedge should therefore be treated as a real validation blocker, not as something to defer indefinitely.

## Current Evidence

- VM-side business output is missing and the prompt does not return as expected.
- QEMU-side traces show that the pipeline at least reaches:
  - `pipe2`
  - two `clone`s
  - `wait4`
- The first suspicious point to focus on is:
  - page fault after `sys_pipe2`
  - `Kernel filemap_map_pages`
  - `SEGV_ACCERR`

## Working Hypothesis

- High-probability interpretation:
  - this is not a `wc` special case
  - this is a file-backed page-fault / PTE-install path that is still incomplete in NaCC
- Most suspicious pieces:
  - `filemap_map_pages()` batch fault-around
  - `set_pte_range()` / `set_ptes()`
  - secure PTE writes followed by permission, user-bit, or TLB-visibility issues
- Lower-priority suspicions:
  - logger simply dropped output
  - shell builtin behavior by itself

## Immediate Strategy

### Step 1: Split the problem before changing code

Do not keep pipe / `wc` / `mmap` / shell mixed into one command.

Run these in order:

```bash
docker run --security-opt seccomp=unconfined --rm busybox sh -c "echo alpha | cat; echo done"
```

```bash
docker run --security-opt seccomp=unconfined --rm busybox sh -c "wc -c /etc/hostname; echo done"
```

```bash
docker run --security-opt seccomp=unconfined --rm busybox wc -c /etc/hostname
```

```bash
docker run --security-opt seccomp=unconfined --rm busybox cat /etc/hostname
```

Goal:

- determine whether the first broken layer is:
  - pipe
  - shell
  - `wc`
  - file-backed page fault

### Step 2: If it still points at `filemap_map_pages()`, use a diagnostic fallback

- In NaCC-related cases, temporarily disable the `filemap_map_pages()` fault-around / batch-map path and fall back to the more conservative single-page fault path.
- This is a diagnostic fallback, not necessarily the final fix.
- The question it should answer quickly is:
  - is the problem specifically inside batch `set_ptes()` / secure batch PTE writes?

### Step 3: If the fallback restores behavior, narrow the secure batch-write issue

Focus on:

- `filemap_map_pages()`
- `set_pte_range()`
- `set_ptes()`
- `nacc_set_ptes_sbi()`

Then choose between:

- fixing batch secure writes
- or temporarily disabling that optimization in NaCC mode

## Suggested Code Focus

- `linux/mm/filemap.c`
- `linux/mm/memory.c`
- `linux/arch/riscv/include/asm/pgtable.h`
- `linux/arch/riscv/mm/fault.c`

## Non-Goals

- do not generalize this immediately into "all `mmap` is broken"
- do not blame `wc` by default
- do not widen this directly to Ubuntu-scale workloads
- do not mix `bitmap` protection into this round

## Exit Criteria

- identify which layer breaks first:
  - pipe
  - shell
  - `wc` file access
  - file-backed page fault
  - batch PTE install
- if the diagnostic fallback restores behavior, narrow the problem to `filemap_map_pages()` / secure batch PTE writes
- sync the conclusion back into `CURRENT_STATE.md` / `HYPOTHESES.md` / `NEXT_STEPS.md`
